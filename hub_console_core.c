/* SSH admin console — the core's side (main thread only).  docs/console.md.
 *
 * The console thread (hub_console.c) terminates SSH and authenticates admins
 * against the credential snapshot published from here.  Each logged-in
 * console becomes an internal admin connection: a hub_client_t whose fd is
 * the core's end of a socketpair, already authenticated, speaking plaintext
 * frames len(4) || op(1) || payload.  Its requests go through the same
 * handle_admin_command as every admin command ever did (hub_logic.c); what
 * this file adds is the handoff of "SSH-" sockets, the control channel, the
 * pushed events (status, tree, upgrade, log lines) and the log ring. */
/* MAP_ANONYMOUS and MADV_DONTDUMP are not POSIX: older glibc (Rocky 8)
 * hides them under the build's -D_POSIX_C_SOURCE. */
#define _DEFAULT_SOURCE
#include "hub.h"
#include "hub_console.h"
#include "hub_reply.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

/* Snapshots the core takes of itself (hub_logic.c). */
int  hub_console_tree_rows(hub_state_t *state, char *buf, int max_len);
void hub_console_status_line(hub_state_t *state, const char *tree,
                             char *out, size_t out_size);
void hub_console_upg_line(hub_state_t *state, char *out, size_t out_size);
void hub_console_record_failed_auth(hub_state_t *state, const char *ip);
void hub_console_note_login(hub_state_t *state, const char *name);

struct hub_console_link {
  char          admin[CONSOLE_NAME_MAX];
  unsigned char ed_pub[32];      /* the key this console logged in with   */
  unsigned char *outq;           /* frames waiting for the socketpair      */
  size_t        outq_len, outq_off, outq_cap;
  bool          sub_status, sub_tree, sub_upg;
  int           log_level;       /* -1 = no log lines                      */
  uint64_t      log_next;        /* next ring sequence to send             */
  unsigned long drops;           /* events / log lines not queued          */
  char          status_last[256];
  char          upg_last[256];
  unsigned char tree_hash[32];
  bool          tree_sent;
};

/* ---- Log ring ----------------------------------------------------------- */
typedef struct {
  uint64_t seq;
  int      level;
  time_t   ts;
  char     text[CONSOLE_LOG_LINE_MAX];
} console_log_entry_t;

/* Not encrypted: the ring is a mapping of its own, page-aligned so that
 * mlock (no swap, no hibernation image) and MADV_DONTDUMP (no core dump)
 * cover exactly it.  NULL until hub_console_log_ring_init(); a hub whose
 * mmap failed runs without a log view rather than with an unprotected one. */
static console_log_entry_t *g_log_ring;
static uint64_t g_log_next = 1;   /* sequence the next line gets */

bool hub_console_log_ring_init(void) {
  if (g_log_ring) return true;
  size_t len = sizeof(console_log_entry_t) * CONSOLE_LOG_RING;
  void *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                 -1, 0);
  if (p == MAP_FAILED) {
    fprintf(stderr, "Warning: console log ring: mmap failed (%s) - the "
                    "consoles' log view is off.\n", strerror(errno));
    return false;
  }
  if (madvise(p, len, MADV_DONTDUMP) != 0)
    fprintf(stderr, "Warning: console log ring: madvise(MADV_DONTDUMP) "
                    "failed (%s).\n", strerror(errno));
  if (mlock(p, len) != 0)
    fprintf(stderr, "Warning: mlock(console log ring) failed (%s) - log "
                    "lines may reach swap.\n", strerror(errno));
  g_log_ring = p;   /* MAP_ANONYMOUS: already zero */
  return true;
}

void hub_console_log_append(int level, const char *line, size_t len) {
  if (!g_log_ring) return;
  console_log_entry_t *e = &g_log_ring[g_log_next % CONSOLE_LOG_RING];
  e->seq = g_log_next++;
  /* The message is sanitized again where it is shown; here it only has to
   * be one line: a newline inside becomes a space, the last one goes. */
  size_t o = 0;
  for (size_t i = 0; i < len && o + 1 < sizeof(e->text); i++) {
    char ch = line[i];
    if (ch == '\n' || ch == '\r') {
      if (i + 1 == len) break;
      ch = ' ';
    }
    e->text[o++] = ch;
  }
  /* The rest of the slot still holds an older line: clear it. */
  memset(e->text + o, 0, sizeof(e->text) - o);
  e->level = level < LOG_ERROR ? LOG_ERROR : level > LOG_DEBUG ? LOG_DEBUG : level;
  e->ts = time(NULL);
}

static const char *log_level_word(int level) {
  switch (level) {
  case LOG_ERROR:   return "error";
  case LOG_WARNING: return "warning";
  case LOG_DEBUG:   return "debug";
  default:          return "info";
  }
}

/* ---- Control channel ---------------------------------------------------- */
static unsigned char g_ctl_buf[8192];
static size_t g_ctl_len;
static unsigned char g_cred_hash[32];
static bool g_cred_published;
static unsigned char g_hostkey_pub[32];
static bool g_hostkey_published;
static time_t g_last_cred_check;
/* A console (re)subscribed: take the next snapshot now, not next second. */
static bool g_snap_now;

static void set_nonblock(int fd) {
  int fl = fcntl(fd, F_GETFL, 0);
  if (fl >= 0) (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
  (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
}

static void console_publish_hostkey_from(hub_state_t *state) {
  if (!state->hub_keys_loaded) return;
  bool changed = g_hostkey_published &&
                 memcmp(g_hostkey_pub, state->hub_ed25519_pub, 32) != 0;
  char old_fp[80] = "";
  if (changed) console_ssh_fingerprint(g_hostkey_pub, old_fp, sizeof(old_fp));
  console_publish_hostkey(state->hub_ed25519_priv, state->hub_ed25519_pub);
  memcpy(g_hostkey_pub, state->hub_ed25519_pub, 32);
  g_hostkey_published = true;
  char fp[80];
  console_ssh_fingerprint(state->hub_ed25519_pub, fp, sizeof(fp));
  /* Key material changed hands: an audit line, not just a notice. */
  if (changed)
    hub_log_warning("[AUDIT] SSH host key republished: ssh-ed25519 %s "
                    "(was %s); admins must accept the new host key\n",
                    fp, old_fp);
  else
    hub_log_info("[CONSOLE] SSH host key ssh-ed25519 %s\n", fp);
}

/* The admins that may log in: active admin records with a key, each key on
 * exactly one of them (a key on two records is refused, as it always was). */
static int build_creds(hub_state_t *state, console_cred_t *out, int max) {
  int n = 0;
  for (int i = 0; i < state->user_record_count && n < max; i++) {
    const hub_user_record_t *u = &state->user_records[i];
    if (u->type != 'a' || !u->is_active || !u->has_pubkey || !u->name[0]) continue;
    unsigned char pub[COMBINED_KEY_LEN];
    if (!hub_crypto_pubkey_b64_decode(u->pubkey_b64, pub)) continue;
    int same = 0;
    for (int j = 0; j < state->user_record_count; j++) {
      const hub_user_record_t *v = &state->user_records[j];
      if (v->type == 'a' && v->is_active && v->has_pubkey &&
          strcmp(v->pubkey_b64, u->pubkey_b64) == 0)
        same++;
    }
    if (same != 1) continue;
    snprintf(out[n].name, sizeof(out[n].name), "%s", u->name);
    memcpy(out[n].ed_pub, pub, 32);
    n++;
  }
  return n;
}

static bool creds_hold(const console_cred_t *creds, int n, const char *name,
                       const unsigned char ed_pub[32]) {
  for (int i = 0; i < n; i++)
    if (strcmp(creds[i].name, name) == 0 &&
        CRYPTO_memcmp(creds[i].ed_pub, ed_pub, 32) == 0)
      return true;
  return false;
}

static void console_refresh_creds(hub_state_t *state, bool force) {
  console_cred_t creds[MAX_HUB_USER_RECORDS];
  int n = build_creds(state, creds, MAX_HUB_USER_RECORDS);
  unsigned char h[32];
  EVP_Digest(creds, sizeof(creds[0]) * (size_t)n, h, NULL, EVP_sha256(), NULL);
  if (!force && g_cred_published && memcmp(h, g_cred_hash, 32) == 0) return;
  memcpy(g_cred_hash, h, 32);
  g_cred_published = true;
  console_publish_creds(creds, n);
  console_publish_hubname(state->hub_friendly_name[0] ? state->hub_friendly_name
                                                      : "hub");
  /* A console whose admin was removed, or whose key changed, ends now. */
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (!c->internal || !c->console) continue;
    if (!creds_hold(creds, n, c->console->admin, c->console->ed_pub)) {
      hub_log_warning("[CONSOLE] Closing %s's console: the admin record or its "
                      "key changed\n", c->console->admin);
      hub_disconnect_client(state, c);
      i--;
    }
  }
  secure_wipe(creds, sizeof(creds));
}

bool hub_console_start(hub_state_t *state) {
  int sv[2];
  state->console_ctl_fd = -1;
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
    hub_log_error("[CONSOLE] socketpair failed: %s\n", strerror(errno));
    return false;
  }
  set_nonblock(sv[0]);
  (void)fcntl(sv[1], F_SETFD, FD_CLOEXEC);
  console_publish_hostkey_from(state);
  console_refresh_creds(state, true);
  if (!console_thread_start(sv[1])) {
    hub_log_error("[CONSOLE] Could not start the console thread\n");
    close(sv[0]);
    close(sv[1]);
    return false;
  }
  state->console_ctl_fd = sv[0];
  g_ctl_len = 0;
  return true;
}

void hub_console_stop(hub_state_t *state) {
  if (state->console_ctl_fd < 0) return;
  console_thread_stop();
  close(state->console_ctl_fd);
  state->console_ctl_fd = -1;
}

void hub_console_hostkey_changed(hub_state_t *state) {
  console_publish_hostkey_from(state);
}

void hub_console_handoff(hub_state_t *state, hub_client_t *c) {
  int fd = c->fd;
  bool sent = false;
  if (state->console_ctl_fd >= 0) {
    char msg[128];
    snprintf(msg, sizeof(msg), "NEW|%d|%s", fd, c->ip);
    sent = console_ctl_write(state->console_ctl_fd, msg);
  }
  if (sent) {
    /* The socket is the console thread's now: detach it from the client
     * before the client is dropped, so hub_disconnect_client leaves it open. */
    c->fd = -1;
    hub_log_debug("[CONSOLE] SSH connection from %s handed to the console\n", c->ip);
  } else {
    hub_log_warning("[CONSOLE] SSH connection from %s refused: console not "
                    "running\n", c->ip);
  }
  hub_disconnect_client(state, c);
}

static const hub_user_record_t *admin_by_name(hub_state_t *state,
                                              const char *name) {
  for (int i = 0; i < state->user_record_count; i++) {
    const hub_user_record_t *u = &state->user_records[i];
    if (u->type == 'a' && u->is_active && strcmp(u->name, name) == 0) return u;
  }
  return NULL;
}

/* "OPEN|<fd>|<name>|<ip>": a console logged in; its session fd is ours now. */
static void ctl_open(hub_state_t *state, char *args) {
  char *save = NULL;
  char *sfd = strtok_r(args, "|", &save);
  char *name = strtok_r(NULL, "|", &save);
  char *ip = strtok_r(NULL, "|", &save);
  unsigned long fdv = 0;
  if (!sfd || !name || !ip || !hub_parse_uint(sfd, 65535, &fdv) || fdv < 3) {
    hub_log_error("[CONSOLE] Malformed OPEN from the console thread\n");
    return;
  }
  int fd = (int)fdv;
  const hub_user_record_t *u = admin_by_name(state, name);
  unsigned char pub[COMBINED_KEY_LEN];
  if (!u || !u->has_pubkey || !hub_crypto_pubkey_b64_decode(u->pubkey_b64, pub) ||
      strlen(name) + sizeof("ADMIN:") > sizeof(((hub_client_t *)0)->id)) {
    hub_log_warning("[CONSOLE] Login for '%s' from %s no longer matches a "
                    "record — closing\n", name, ip);
    close(fd);
    return;
  }
  if (state->client_count >= MAX_CLIENTS) {
    hub_log_warning("[CONSOLE] Console for %s from %s refused: client table "
                    "full\n", name, ip);
    close(fd);
    return;
  }
  hub_client_t *c = calloc(1, sizeof(*c));
  struct hub_console_link *l = calloc(1, sizeof(*l));
  if (!c || !l || !hub_client_alloc_buffers(c, MAX_BUFFER)) {
    if (c) { free(c->recv_buf); free(c->writing_buf); }
    free(c);
    free(l);
    close(fd);
    hub_log_error("[CONSOLE] OOM opening a console for %s\n", name);
    return;
  }
  set_nonblock(fd);
  snprintf(l->admin, sizeof(l->admin), "%s", name);
  memcpy(l->ed_pub, pub, 32);
  l->log_level = -1;
  l->log_next = g_log_next;
  c->fd = fd;
  c->conn_serial = hub_next_conn_serial();
  snprintf(c->ip, sizeof(c->ip), "%s", ip);
  snprintf(c->id, sizeof(c->id), "ADMIN:%s", name);
  c->type = CLIENT_ADMIN;
  c->authenticated = true;
  c->internal = true;
  c->inbound = true;   /* the SSH side came in on the listener */
  c->console = l;
  c->last_seen = c->connected_at = time(NULL);
  state->clients[state->client_count++] = c;
  increment_active_connections(state, c->ip);

  char fp[KEY_FP_LEN + 1];
  hub_crypto_key_fingerprint(pub, fp);
  hub_log_info("[HUB] Admin Login (SSH console, key %s): %s as '%s'\n", fp, ip,
               name);
  hub_console_note_login(state, name);
}

static void ctl_frame(hub_state_t *state, char *text) {
  if (strncmp(text, "OPEN|", 5) == 0) {
    ctl_open(state, text + 5);
  } else if (strncmp(text, "FAIL|", 5) == 0) {
    /* FAIL|<ip>|<name>|<reason> */
    char *save = NULL;
    char *ip = strtok_r(text + 5, "|", &save);
    char *name = strtok_r(NULL, "|", &save);
    char *why = strtok_r(NULL, "", &save);
    if (!ip) return;
    hub_log_warning("[CONSOLE] Refused SSH login '%s' from %s: %s\n",
                    name ? name : "?", ip, why ? why : "refused");
    hub_console_record_failed_auth(state, ip);
  } else if (strncmp(text, "LOG|", 4) == 0) {
    /* LOG|<level>|<text> — audit lines; the console thread never logs itself. */
    char *msg = strchr(text + 4, '|');
    if (!msg) return;
    int lvl = atoi(text + 4);
    msg++;
    if (lvl <= LOG_ERROR) hub_log_error("%s\n", msg);
    else if (lvl == LOG_WARNING) hub_log_warning("%s\n", msg);
    else if (lvl >= LOG_DEBUG) hub_log_debug("%s\n", msg);
    else hub_log_info("%s\n", msg);
  }
}

void hub_console_ctl_read(hub_state_t *state) {
  for (;;) {
    if (g_ctl_len == sizeof(g_ctl_buf)) {
      hub_log_error("[CONSOLE] Control channel overflow — stopping the console\n");
      hub_console_stop(state);
      return;
    }
    ssize_t n = read(state->console_ctl_fd, g_ctl_buf + g_ctl_len,
                     sizeof(g_ctl_buf) - g_ctl_len);
    if (n == 0) {
      hub_log_error("[CONSOLE] Console thread went away\n");
      close(state->console_ctl_fd);
      state->console_ctl_fd = -1;
      return;
    }
    if (n < 0) break;   /* EAGAIN: all read */
    g_ctl_len += (size_t)n;
  }
  size_t off = 0;
  while (g_ctl_len - off >= 4) {
    uint32_t nl;
    memcpy(&nl, g_ctl_buf + off, 4);
    uint32_t len = ntohl(nl);
    if (len == 0 || len > sizeof(g_ctl_buf) - 5) {
      hub_log_error("[CONSOLE] Bad control frame — stopping the console\n");
      hub_console_stop(state);
      return;
    }
    if (g_ctl_len - off - 4 < len) break;
    char text[sizeof(g_ctl_buf)];
    memcpy(text, g_ctl_buf + off + 4, len);
    text[len] = '\0';
    off += 4 + len;
    ctl_frame(state, text);
    if (state->console_ctl_fd < 0) return;
  }
  memmove(g_ctl_buf, g_ctl_buf + off, g_ctl_len - off);
  g_ctl_len -= off;
}

/* ---- Session frames ----------------------------------------------------- */
bool hub_console_send(hub_client_t *c, uint8_t op, const void *data, size_t len) {
  struct hub_console_link *l = c->console;
  if (!l || c->fd < 0) return false;
  size_t need = 5 + len;
  if (l->outq_len - l->outq_off + need > CONSOLE_CORE_OUTQ_MAX) {
    if (op == CONSOLE_REPLY) return false;
    l->drops++;
    return true;
  }
  if (l->outq_off > 0 && l->outq_len + need > l->outq_cap) {
    memmove(l->outq, l->outq + l->outq_off, l->outq_len - l->outq_off);
    l->outq_len -= l->outq_off;
    l->outq_off = 0;
  }
  if (l->outq_len + need > l->outq_cap) {
    size_t cap = l->outq_cap ? l->outq_cap : 16384;
    while (cap < l->outq_len + need) cap *= 2;
    unsigned char *nb = realloc(l->outq, cap);
    if (!nb) {
      if (op == CONSOLE_REPLY) return false;
      l->drops++;
      return true;
    }
    l->outq = nb;
    l->outq_cap = cap;
  }
  uint32_t nl = htonl((uint32_t)(1 + len));
  memcpy(l->outq + l->outq_len, &nl, 4);
  l->outq[l->outq_len + 4] = op;
  if (len) memcpy(l->outq + l->outq_len + 5, data, len);
  l->outq_len += need;
  return true;
}

static bool send_event(hub_client_t *c, const char *topic, const char *data) {
  size_t tl = strlen(topic), dl = strlen(data);
  char *buf = malloc(tl + 1 + dl);
  if (!buf) {
    c->console->drops++;
    return false;
  }
  memcpy(buf, topic, tl);
  buf[tl] = '|';
  memcpy(buf + tl + 1, data, dl);
  bool ok = hub_console_send(c, CMD_CONSOLE, buf, tl + 1 + dl);
  free(buf);
  return ok;
}

bool hub_console_has_pending(const hub_client_t *c) {
  return c->console && c->console->outq_len > c->console->outq_off;
}

void hub_console_drain(hub_state_t *state, hub_client_t *c) {
  struct hub_console_link *l = c->console;
  if (!l) return;
  while (l->outq_len > l->outq_off) {
    ssize_t s = send(c->fd, l->outq + l->outq_off, l->outq_len - l->outq_off,
                     MSG_DONTWAIT | MSG_NOSIGNAL);
    if (s > 0) {
      l->outq_off += (size_t)s;
      continue;
    }
    if (s < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
      return;
    hub_disconnect_client(state, c);
    return;
  }
  l->outq_len = l->outq_off = 0;
}

void hub_console_link_free(hub_client_t *c) {
  if (!c->console) return;
  free(c->console->outq);
  secure_wipe(c->console, sizeof(*c->console));
  free(c->console);
  c->console = NULL;
}

/* "sub|status,tree,upg,log=3[,logreplay]" — replaces the console's
 * subscriptions.  logreplay also sends what the log ring still holds (the
 * full-screen log view); without it only new lines come. */
static void console_subscribe(struct hub_console_link *l, const char *topics) {
  l->sub_status = l->sub_tree = l->sub_upg = false;
  int want_log = -1;
  bool replay = false;
  char buf[256];
  snprintf(buf, sizeof(buf), "%s", topics);
  char *save = NULL;
  for (char *t = strtok_r(buf, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
    if (strcmp(t, "status") == 0) l->sub_status = true;
    else if (strcmp(t, "tree") == 0) l->sub_tree = true;
    else if (strcmp(t, "upg") == 0) l->sub_upg = true;
    else if (strcmp(t, "logreplay") == 0) replay = true;
    else if (strncmp(t, "log=", 4) == 0) {
      unsigned long v = 0;
      if (hub_parse_uint(t + 4, LOG_DEBUG, &v)) want_log = (int)v;
    }
  }
  /* A (re)subscription resends the current state of everything asked for. */
  l->status_last[0] = '\0';
  l->upg_last[0] = '\0';
  l->tree_sent = false;
  g_snap_now = true;
  if (want_log >= 0 && l->log_level < 0) {
    l->log_next = !replay ? g_log_next
                  : g_log_next > CONSOLE_LOG_RING ? g_log_next - CONSOLE_LOG_RING + 1
                                                  : 1;
  }
  l->log_level = want_log;
}

bool hub_console_frame(hub_state_t *state, hub_client_t *c, uint8_t op,
                       const char *payload, int payload_len) {
  (void)payload_len;
  struct hub_console_link *l = c->console;
  if (op != CMD_CONSOLE || !l) return false;
  if (strncmp(payload, "sub|", 4) == 0) {
    console_subscribe(l, payload + 4);
    return true;   /* no reply: a subscription is not a command */
  }
  /* get|tree and get|status: the result line, then the rows / key=value
   * lines exactly as the events carry them (docs/console.md §3.4). */
  if (strcmp(payload, "get|tree") == 0 || strcmp(payload, "get|status") == 0) {
    char *rows = malloc(MAX_TREE_PAYLOAD);
    if (!rows) {
      static const char OOM[] = "err|internal.oom|msg=out of memory";
      return hub_console_send(c, CONSOLE_REPLY, OOM, sizeof(OOM) - 1);
    }
    hub_console_tree_rows(state, rows, MAX_TREE_PAYLOAD);
    bool ok;
    if (payload[4] == 't') {
      size_t rl = strlen(rows);
      while (rl > 0 && rows[rl - 1] == '\n') rows[--rl] = '\0';
      char *out = malloc(rl + 32);
      if (!out) {
        free(rows);
        static const char OOM[] = "err|internal.oom|msg=out of memory";
        return hub_console_send(c, CONSOLE_REPLY, OOM, sizeof(OOM) - 1);
      }
      int n = snprintf(out, rl + 32, "ok|network.tree%s%s", rl ? "\n" : "", rows);
      ok = hub_console_send(c, CONSOLE_REPLY, out, (size_t)n);
      free(out);
    } else {
      char line[256], out[512];
      hub_console_status_line(state, rows, line, sizeof(line));
      /* one key=value per line */
      size_t o = (size_t)snprintf(out, sizeof(out), "ok|network.status\n");
      for (const char *p = line; *p && o + 2 < sizeof(out); p++)
        out[o++] = (*p == '|') ? '\n' : *p;
      out[o] = '\0';
      ok = hub_console_send(c, CONSOLE_REPLY, out, o);
    }
    free(rows);
    return ok;
  }
  /* get|log: the log settings and how full the file and the ring are */
  if (strcmp(payload, "get|log") == 0) {
    reply_t r;
    reply_init(&r);
    reply_ok(&r, "log.show");
    reply_kvi(&r, "file_level", state->log_level);
    reply_kvi(&r, "console_level", state->console_log_level);
    reply_kv(&r, "file", HUB_LOG_FILE);
    struct stat st;
    reply_kvi(&r, "file_bytes", stat(HUB_LOG_FILE, &st) == 0 ? (long long)st.st_size : 0);
    reply_kvi(&r, "limit",
              state->log_max_size > 0 ? state->log_max_size : HUB_LOG_FILE_SIZE);
    uint64_t lines = g_log_next > 1 ? g_log_next - 1 : 0;
    if (lines > CONSOLE_LOG_RING) lines = CONSOLE_LOG_RING;
    reply_kvu(&r, "ring_lines", (unsigned long long)lines);
    reply_kvi(&r, "ring_cap", CONSOLE_LOG_RING);
    if (lines && g_log_ring) {
      const console_log_entry_t *e = &g_log_ring[(g_log_next - lines) % CONSOLE_LOG_RING];
      if (e->ts > 0) reply_kvi(&r, "ring_oldest", (long long)e->ts);
    }
    reply_kvi(&r, "session_level", l->log_level);
    bool ok = hub_console_send(c, CONSOLE_REPLY, reply_text(&r), strlen(reply_text(&r)));
    reply_free(&r);
    return ok;
  }
  static const char UNK[] = "err|console.unknown|msg=unknown console request";
  return hub_console_send(c, CONSOLE_REPLY, UNK, sizeof(UNK) - 1);
}

/* ---- Per-pass work ------------------------------------------------------ */
static void push_log(hub_client_t *c) {
  struct hub_console_link *l = c->console;
  if (l->log_level < 0) {
    l->log_next = g_log_next;
    return;
  }
  uint64_t oldest = g_log_next > CONSOLE_LOG_RING ? g_log_next - CONSOLE_LOG_RING + 1 : 1;
  if (l->log_next < oldest) {
    l->drops += (unsigned long)(oldest - l->log_next);
    l->log_next = oldest;
  }
  for (; l->log_next < g_log_next; l->log_next++) {
    const console_log_entry_t *e = &g_log_ring[l->log_next % CONSOLE_LOG_RING];
    if (e->seq != l->log_next || e->level > l->log_level) continue;
    char data[CONSOLE_LOG_LINE_MAX + 16];
    snprintf(data, sizeof(data), "%s|%s", log_level_word(e->level), e->text);
    send_event(c, "log", data);
    secure_wipe(data, sizeof(data));
  }
}

void hub_console_tick(hub_state_t *state) {
  if (state->console_ctl_fd < 0) return;
  time_t now = time(NULL);
  if (now != g_last_cred_check) {
    g_last_cred_check = now;
    console_refresh_creds(state, false);
    if (state->hub_keys_loaded &&
        (!g_hostkey_published || memcmp(g_hostkey_pub, state->hub_ed25519_pub, 32)))
      console_publish_hostkey_from(state);
  }

  bool any = false, want_tree = false;
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (!c->internal || !c->console) continue;
    any = true;
    if (c->console->sub_tree || c->console->sub_status) want_tree = true;
  }
  if (!any) return;

  /* Status and tree at most once a second; the log on every pass. */
  static time_t last_snap;
  if (g_snap_now) {
    last_snap = 0;
    g_snap_now = false;
  }
  char *rows = NULL;
  char status[256] = "", upg[256] = "";
  unsigned char tree_hash[32];
  if (want_tree && now != last_snap) {
    rows = malloc(MAX_TREE_PAYLOAD);
    if (rows) {
      hub_console_tree_rows(state, rows, MAX_TREE_PAYLOAD);
      EVP_Digest(rows, strlen(rows), tree_hash, NULL, EVP_sha256(), NULL);
      hub_console_status_line(state, rows, status, sizeof(status));
    }
  }
  if (now != last_snap) hub_console_upg_line(state, upg, sizeof(upg));

  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (!c->internal || !c->console) continue;
    struct hub_console_link *l = c->console;
    if (now != last_snap) {
      if (l->sub_status && status[0] && strcmp(status, l->status_last) != 0) {
        snprintf(l->status_last, sizeof(l->status_last), "%s", status);
        send_event(c, "status", status);
      }
      if (l->sub_tree && rows &&
          (!l->tree_sent || memcmp(tree_hash, l->tree_hash, 32) != 0)) {
        memcpy(l->tree_hash, tree_hash, 32);
        l->tree_sent = true;
        send_event(c, "tree", rows);
      }
      if (l->sub_upg && upg[0] && strcmp(upg, l->upg_last) != 0) {
        snprintf(l->upg_last, sizeof(l->upg_last), "%s", upg);
        send_event(c, "upg", upg);
      }
    }
    push_log(c);
    if (l->drops && l->outq_len - l->outq_off + 64 < CONSOLE_CORE_OUTQ_MAX) {
      char n[32];
      snprintf(n, sizeof(n), "%lu", l->drops);
      l->drops = 0;
      send_event(c, "drop", n);
    }
  }
  if (now != last_snap && (rows || !want_tree)) last_snap = now;
  free(rows);
}
