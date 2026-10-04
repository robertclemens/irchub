/* SSH admin console — the console thread.  docs/console.md.
 *
 * One thread, one libssh event loop, every SSH session of the hub.  The core
 * hands over accepted sockets whose first bytes were "SSH-" (control frame
 * NEW); this thread runs the key exchange, authenticates the admin against the
 * credential snapshot the core published, enforces the channel policy, and
 * then connects the session's UI (hub_console_ui.c) to the core through a
 * fresh socketpair (control frame OPEN).  It never touches hub_state_t and
 * never calls hub_log: refusals and audit lines go to the core as FAIL / LOG
 * frames and are logged there. */
#include "hub_console_ui.h"
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/* ==========================================================================
 * Published snapshot (the only data shared with the core)
 * ========================================================================== */
static pthread_mutex_t g_pub_mu = PTHREAD_MUTEX_INITIALIZER;
static console_cred_t g_creds[MAX_HUB_USER_RECORDS];
static int g_ncreds;
static unsigned char g_host_seed[32], g_host_pub[32];
static unsigned g_host_gen;   /* bumped on every host key change */
static char g_hubname[64];

void console_publish_creds(const console_cred_t *creds, int n) {
  pthread_mutex_lock(&g_pub_mu);
  if (n > MAX_HUB_USER_RECORDS) n = MAX_HUB_USER_RECORDS;
  secure_wipe(g_creds, sizeof(g_creds));
  memcpy(g_creds, creds, sizeof(console_cred_t) * (size_t)n);
  g_ncreds = n;
  pthread_mutex_unlock(&g_pub_mu);
}

void console_publish_hostkey(const unsigned char seed[32], const unsigned char pub[32]) {
  pthread_mutex_lock(&g_pub_mu);
  memcpy(g_host_seed, seed, 32);
  memcpy(g_host_pub, pub, 32);
  g_host_gen++;
  pthread_mutex_unlock(&g_pub_mu);
}

void console_publish_hubname(const char *name) {
  pthread_mutex_lock(&g_pub_mu);
  snprintf(g_hubname, sizeof(g_hubname), "%s", name);
  pthread_mutex_unlock(&g_pub_mu);
}

/* ==========================================================================
 * Helpers shared with the core
 * ========================================================================== */
bool console_ctl_write(int fd, const char *text) {
  size_t len = strlen(text);
  unsigned char buf[4 + 1024];
  if (len == 0 || len > sizeof(buf) - 4) return false;
  uint32_t nl = htonl((uint32_t)len);
  memcpy(buf, &nl, 4);
  memcpy(buf + 4, text, len);
  size_t off = 0, total = 4 + len;
  while (off < total) {
    ssize_t n = send(fd, buf + off, total - off, MSG_NOSIGNAL);
    if (n > 0) {
      off += (size_t)n;
      continue;
    }
    if (n < 0 && errno == EINTR) continue;
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      struct pollfd p = {fd, POLLOUT, 0};
      if (poll(&p, 1, 1000) > 0) continue;
    }
    return false;
  }
  return true;
}

/* The ssh-ed25519 public key blob: string "ssh-ed25519" || string pub. */
static size_t ed25519_blob(const unsigned char pub[32], unsigned char out[51]) {
  static const unsigned char head[] = {0, 0, 0, 11, 's', 's', 'h', '-', 'e', 'd',
                                       '2', '5', '5', '1', '9', 0, 0, 0, 32};
  memcpy(out, head, sizeof(head));
  memcpy(out + sizeof(head), pub, 32);
  return sizeof(head) + 32;
}

void console_ssh_fingerprint(const unsigned char pub[32], char *out, size_t out_size) {
  unsigned char blob[51], h[32];
  size_t bl = ed25519_blob(pub, blob);
  EVP_Digest(blob, bl, h, NULL, EVP_sha256(), NULL);
  char *b64 = base64_encode(h, 32);
  if (!b64) {
    snprintf(out, out_size, "SHA256:?");
    return;
  }
  size_t l = strlen(b64);
  while (l > 0 && b64[l - 1] == '=') b64[--l] = '\0';
  snprintf(out, out_size, "SHA256:%s", b64);
  free(b64);
}

/* An unencrypted "openssh-key-v1" private key file for an Ed25519 key, the
 * form libssh imports (keygen writes the same format, optionally encrypted,
 * as an admin's <ts>_<name>_ed25519).  The caller wipes and frees the
 * result. */
static char *openssh_private_pem(const unsigned char seed[32], const unsigned char pub[32]) {
  unsigned char raw[512];
  size_t o = 0;
#define PUT32(v) do { uint32_t _v = htonl((uint32_t)(v)); memcpy(raw + o, &_v, 4); o += 4; } while (0)
#define PUTS(p, n) do { PUT32(n); memcpy(raw + o, (p), (n)); o += (n); } while (0)
  memcpy(raw, "openssh-key-v1", 15);   /* incl. NUL */
  o = 15;
  PUTS("none", 4);
  PUTS("none", 4);
  PUTS("", 0);
  PUT32(1);
  unsigned char blob[51];
  size_t bl = ed25519_blob(pub, blob);
  PUTS(blob, bl);
  /* private section, padded to 8 */
  unsigned char sec[256];
  size_t so = 0;
  uint32_t check;
  if (RAND_bytes((unsigned char *)&check, sizeof(check)) != 1) check = 0x1e5b2c7d;
  memcpy(sec + so, &check, 4); so += 4;
  memcpy(sec + so, &check, 4); so += 4;
  {
    uint32_t v = htonl(11);
    memcpy(sec + so, &v, 4); so += 4;
    memcpy(sec + so, "ssh-ed25519", 11); so += 11;
    v = htonl(32);
    memcpy(sec + so, &v, 4); so += 4;
    memcpy(sec + so, pub, 32); so += 32;
    v = htonl(64);
    memcpy(sec + so, &v, 4); so += 4;
    memcpy(sec + so, seed, 32); so += 32;
    memcpy(sec + so, pub, 32); so += 32;
    v = htonl(6);
    memcpy(sec + so, &v, 4); so += 4;
    memcpy(sec + so, "irchub", 6); so += 6;
  }
  for (unsigned char pad = 1; so % 8 != 0; pad++) sec[so++] = pad;
  PUTS(sec, so);
  secure_wipe(sec, sizeof(sec));
#undef PUTS
#undef PUT32
  char *b64 = base64_encode(raw, (int)o);
  secure_wipe(raw, sizeof(raw));
  if (!b64) return NULL;
  size_t bl64 = strlen(b64);
  size_t cap = bl64 + bl64 / 70 + 128;
  char *pem = malloc(cap);
  if (!pem) {
    secure_wipe(b64, bl64);
    free(b64);
    return NULL;
  }
  size_t p = (size_t)snprintf(pem, cap, "-----BEGIN OPENSSH PRIVATE KEY-----\n");
  for (size_t i = 0; i < bl64; i += 70) {
    size_t n = bl64 - i < 70 ? bl64 - i : 70;
    memcpy(pem + p, b64 + i, n);
    p += n;
    pem[p++] = '\n';
  }
  p += (size_t)snprintf(pem + p, cap - p, "-----END OPENSSH PRIVATE KEY-----\n");
  secure_wipe(b64, bl64);
  free(b64);
  return pem;
}

/* ==========================================================================
 * Sessions
 * ========================================================================== */
typedef struct csess {
  struct csess *next;
  ssh_session   s;
  ssh_channel   ch;
  struct ssh_server_callbacks_struct scb;
  struct ssh_channel_callbacks_struct ccb;
  bool          in_event;
  char          ip[64];
  char          user[CONSOLE_NAME_MAX];
  bool          authed;
  int           refused;          /* keys refused so far */
  bool          fail_sent;
  bool          have_pty, shell;
  char          term[32];
  int           cols, rows;
  long long     start_ms;
  bool          drop;             /* policy violation or protocol error */
  bool          eof;              /* the client sent EOF: finish, then close */
  char          why[80];
  int           core_fd;          /* our end of the session socketpair */
  bool          core_in_event;
  unsigned char *core_in;
  size_t        core_in_len, core_in_cap;
  console_ui_t *ui;
} csess_t;

static pthread_t g_thread;
static bool g_running;
static volatile sig_atomic_t g_stop;
static int g_ctl = -1;          /* this thread's end of the control pair */
static int g_wake[2] = {-1, -1};
static ssh_event g_ev;
static ssh_bind g_bind;
static unsigned g_bind_gen;
static csess_t *g_sessions;
static unsigned char g_ctl_in[8192];
static size_t g_ctl_len;

static long long now_ms(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static void ctl_log(int level, const char *fmt, ...) {
  char msg[600];
  int o = snprintf(msg, sizeof(msg), "LOG|%d|", level);
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg + o, sizeof(msg) - (size_t)o, fmt, ap);
  va_end(ap);
  if (g_ctl >= 0) (void)console_ctl_write(g_ctl, msg);
}

/* A client-supplied user name, safe for a '|'-separated control frame. */
static void clean_name(const char *in, char *out, size_t cap) {
  size_t o = 0;
  for (size_t i = 0; in && in[i] && o + 1 < cap && o < 64; i++) {
    unsigned char c = (unsigned char)in[i];
    out[o++] = (c < 0x20 || c == 0x7f || c == '|' || c >= 0x80) ? '?' : (char)c;
  }
  out[o] = '\0';
}

static void sess_drop(csess_t *x, const char *why) {
  if (!x->drop) {
    x->drop = true;
    snprintf(x->why, sizeof(x->why), "%s", why);
  }
}

static bool rebuild_bind(void) {
  unsigned char seed[32], pub[32];
  unsigned gen;
  pthread_mutex_lock(&g_pub_mu);
  memcpy(seed, g_host_seed, 32);
  memcpy(pub, g_host_pub, 32);
  gen = g_host_gen;
  pthread_mutex_unlock(&g_pub_mu);
  if (gen == 0) return false;   /* no host key published yet */

  ssh_bind b = ssh_bind_new();
  if (!b) {
    secure_wipe(seed, sizeof(seed));
    return false;
  }
  bool no = false;
  int verb = SSH_LOG_NOLOG;
  ssh_bind_options_set(b, SSH_BIND_OPTIONS_PROCESS_CONFIG, &no);
  ssh_bind_options_set(b, SSH_BIND_OPTIONS_LOG_VERBOSITY, &verb);
  ssh_bind_options_set(b, SSH_BIND_OPTIONS_BANNER, "irchub");
  bool ok = true;
  if (ssh_bind_options_set(b, SSH_BIND_OPTIONS_KEY_EXCHANGE,
                           "mlkem768x25519-sha256,sntrup761x25519-sha512,"
                           "sntrup761x25519-sha512@openssh.com,curve25519-sha256,"
                           "curve25519-sha256@libssh.org") != SSH_OK)
    ok = ssh_bind_options_set(b, SSH_BIND_OPTIONS_KEY_EXCHANGE,
                              "curve25519-sha256,curve25519-sha256@libssh.org") == SSH_OK;
  const char *ciphers = "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com";
  const char *macs = "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com";
  ok = ok && ssh_bind_options_set(b, SSH_BIND_OPTIONS_CIPHERS_C_S, ciphers) == SSH_OK;
  ok = ok && ssh_bind_options_set(b, SSH_BIND_OPTIONS_CIPHERS_S_C, ciphers) == SSH_OK;
  ok = ok && ssh_bind_options_set(b, SSH_BIND_OPTIONS_HMAC_C_S, macs) == SSH_OK;
  ok = ok && ssh_bind_options_set(b, SSH_BIND_OPTIONS_HMAC_S_C, macs) == SSH_OK;
  ok = ok && ssh_bind_options_set(b, SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS, "ssh-ed25519") == SSH_OK;
  ok = ok && ssh_bind_options_set(b, SSH_BIND_OPTIONS_PUBKEY_ACCEPTED_KEY_TYPES,
                                  "ssh-ed25519") == SSH_OK;
  char *pem = ok ? openssh_private_pem(seed, pub) : NULL;
  secure_wipe(seed, sizeof(seed));
  ok = ok && pem && ssh_bind_options_set(b, SSH_BIND_OPTIONS_IMPORT_KEY_STR, pem) == SSH_OK;
  if (pem) {
    secure_wipe(pem, strlen(pem));
    free(pem);
  }
  if (!ok) {
    ctl_log(LOG_ERROR, "[CONSOLE] Could not configure the SSH server: %s",
            ssh_get_error(b));
    ssh_bind_free(b);
    return false;
  }
  if (g_bind) ssh_bind_free(g_bind);
  g_bind = b;
  g_bind_gen = gen;
  return true;
}

/* ---- authentication ---- */
static bool key_matches(const char *user, ssh_key key) {
  unsigned char offered[32] = {0};
  bool is_ed = ssh_key_type(key) == SSH_KEYTYPE_ED25519;
  if (is_ed) {
    /* the key blob: string "ssh-ed25519" || string pub(32) */
    char *b64 = NULL;
    int bl = 0;
    unsigned char *blob = NULL;
    if (ssh_pki_export_pubkey_base64(key, &b64) == SSH_OK && b64)
      blob = base64_decode(b64, &bl);
    if (blob && bl == 51 && memcmp(blob + 4, "ssh-ed25519", 11) == 0)
      memcpy(offered, blob + 19, 32);
    else
      is_ed = false;
    free(blob);
    ssh_string_free_char(b64);
  }
  /* Same work for every name: an unknown one is compared against a dummy. */
  unsigned char want[32] = {0};
  bool known = false;
  pthread_mutex_lock(&g_pub_mu);
  for (int i = 0; i < g_ncreds; i++) {
    if (!known && user && strcmp(g_creds[i].name, user) == 0) {
      memcpy(want, g_creds[i].ed_pub, 32);
      known = true;
    }
  }
  pthread_mutex_unlock(&g_pub_mu);
  bool eq = CRYPTO_memcmp(want, offered, 32) == 0;
  secure_wipe(want, sizeof(want));
  return is_ed && known && eq;
}

static void report_fail(csess_t *x, const char *why) {
  if (x->fail_sent || g_ctl < 0) return;
  x->fail_sent = true;
  char name[72], msg[256];
  clean_name(x->user, name, sizeof(name));
  snprintf(msg, sizeof(msg), "FAIL|%s|%s|%s", x->ip, name[0] ? name : "?", why);
  (void)console_ctl_write(g_ctl, msg);
}

static int cb_auth_pubkey(ssh_session s, const char *user, struct ssh_key_struct *pubkey,
                          char signature_state, void *ud) {
  (void)s;
  csess_t *x = ud;
  if (x->authed || x->drop) return SSH_AUTH_DENIED;
  snprintf(x->user, sizeof(x->user), "%s", user ? user : "");
  bool ok = key_matches(user, pubkey);
  if (ok && signature_state == SSH_PUBLICKEY_STATE_NONE) return SSH_AUTH_SUCCESS;
  if (ok && signature_state == SSH_PUBLICKEY_STATE_VALID) {
    x->authed = true;
    return SSH_AUTH_SUCCESS;
  }
  if (++x->refused >= CONSOLE_MAX_AUTH_TRIES) {
    report_fail(x, "too many refused keys");
    sess_drop(x, "authentication failed");
  }
  return SSH_AUTH_DENIED;
}

/* ---- channel policy ---- */
static int cb_pty(ssh_session s, ssh_channel c, const char *term, int cols, int rows,
                  int px, int py, void *ud) {
  (void)s; (void)c; (void)px; (void)py;
  csess_t *x = ud;
  if (x->have_pty || x->shell) return -1;
  x->have_pty = true;
  clean_name(term ? term : "", x->term, sizeof(x->term));
  x->cols = cols;
  x->rows = rows;
  return 0;
}

static int cb_winch(ssh_session s, ssh_channel c, int cols, int rows, int px, int py,
                    void *ud) {
  (void)s; (void)c; (void)px; (void)py;
  csess_t *x = ud;
  x->cols = cols;
  x->rows = rows;
  if (x->ui) ui_resize(x->ui, cols, rows, now_ms());
  return 0;
}

static int cb_shell(ssh_session s, ssh_channel c, void *ud);

static int cb_exec(ssh_session s, ssh_channel c, const char *cmd, void *ud) {
  (void)s; (void)c; (void)cmd;
  sess_drop(ud, "exec refused");
  return -1;
}

static int cb_subsys(ssh_session s, ssh_channel c, const char *sub, void *ud) {
  (void)s; (void)c; (void)sub;
  sess_drop(ud, "subsystem refused");
  return -1;
}

static int cb_env(ssh_session s, ssh_channel c, const char *n, const char *v, void *ud) {
  /* Refused, but clients send LANG/LC_* by default: not a violation. */
  (void)s; (void)c; (void)n; (void)v; (void)ud;
  return -1;
}

static void cb_x11(ssh_session s, ssh_channel c, int single, const char *proto,
                   const char *cookie, uint32_t screen, void *ud) {
  (void)s; (void)c; (void)single; (void)proto; (void)cookie; (void)screen;
  sess_drop(ud, "x11 forwarding refused");
}

static void cb_agent(ssh_session s, ssh_channel c, void *ud) {
  (void)s; (void)c;
  sess_drop(ud, "agent forwarding refused");
}

static int cb_data(ssh_session s, ssh_channel c, void *data, uint32_t len, int is_stderr,
                   void *ud) {
  (void)s; (void)c;
  csess_t *x = ud;
  if (is_stderr) return (int)len;
  if (x->ui && !x->drop) ui_input(x->ui, data, len, now_ms());
  return (int)len;
}

static void cb_eof(ssh_session s, ssh_channel c, void *ud) {
  (void)s; (void)c;
  csess_t *x = ud;
  /* No more input, but what was typed still gets its answer (a script
   * piping commands in and closing stdin). */
  x->eof = true;
}

static void cb_close(ssh_session s, ssh_channel c, void *ud) {
  (void)s; (void)c;
  sess_drop(ud, "client closed");
}

static ssh_channel cb_chan_open(ssh_session s, void *ud) {
  csess_t *x = ud;
  if (!x->authed || x->ch) {
    sess_drop(x, "extra channel refused");
    return NULL;
  }
  x->ch = ssh_channel_new(s);
  if (!x->ch) return NULL;
  memset(&x->ccb, 0, sizeof(x->ccb));
  x->ccb.userdata = x;
  x->ccb.channel_data_function = cb_data;
  x->ccb.channel_eof_function = cb_eof;
  x->ccb.channel_close_function = cb_close;
  x->ccb.channel_pty_request_function = cb_pty;
  x->ccb.channel_shell_request_function = cb_shell;
  x->ccb.channel_pty_window_change_function = cb_winch;
  x->ccb.channel_exec_request_function = cb_exec;
  x->ccb.channel_subsystem_request_function = cb_subsys;
  x->ccb.channel_env_request_function = cb_env;
  x->ccb.channel_x11_req_function = cb_x11;
  x->ccb.channel_auth_agent_req_function = cb_agent;
  ssh_callbacks_init(&x->ccb);
  ssh_set_channel_callbacks(x->ch, &x->ccb);
  return x->ch;
}

/* Everything the callbacks above do not cover.  Auth methods other than
 * publickey and the service request get libssh's default answer; any
 * forwarding or other channel type ends the connection. */
static int cb_message(ssh_session s, ssh_message m, void *ud) {
  (void)s;
  csess_t *x = ud;
  int type = ssh_message_type(m);
  int sub = ssh_message_subtype(m);
  if (type == SSH_REQUEST_AUTH || type == SSH_REQUEST_SERVICE) return 1;
  if (type == SSH_REQUEST_GLOBAL) {
    if (sub == SSH_GLOBAL_REQUEST_TCPIP_FORWARD ||
        sub == SSH_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD)
      sess_drop(x, "port forwarding refused");
    return 1;   /* keepalive@openssh.com and friends: default "failure" */
  }
  if (type == SSH_REQUEST_CHANNEL_OPEN) {
    sess_drop(x, "channel type refused");
    return 1;
  }
  return 1;
}

static int cb_shell(ssh_session s, ssh_channel c, void *ud) {
  (void)s; (void)c;
  csess_t *x = ud;
  if (x->shell || !x->authed) return -1;
  int sv[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
    sess_drop(x, "no socketpair");
    return -1;
  }
  (void)fcntl(sv[0], F_SETFD, FD_CLOEXEC);
  (void)fcntl(sv[1], F_SETFD, FD_CLOEXEC);
  (void)fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL, 0) | O_NONBLOCK);
  char msg[160];
  snprintf(msg, sizeof(msg), "OPEN|%d|%s|%s", sv[1], x->user, x->ip);
  if (!console_ctl_write(g_ctl, msg)) {
    close(sv[0]);
    close(sv[1]);
    sess_drop(x, "hub not answering");
    return -1;
  }
  /* sv[1] is the core's now. */
  x->core_fd = sv[0];
  x->shell = true;
  char hub[64];
  pthread_mutex_lock(&g_pub_mu);
  snprintf(hub, sizeof(hub), "%s", g_hubname);
  pthread_mutex_unlock(&g_pub_mu);
  /* TERM=dumb, or no pty at all, is line mode (docs/console.md §3). */
  bool line_mode = !x->have_pty || strcmp(x->term, "dumb") == 0;
  x->ui = ui_new(line_mode, x->cols, x->rows, x->user, x->ip, hub);
  if (!x->ui) {
    sess_drop(x, "out of memory");
    return -1;
  }
  ui_start(x->ui, now_ms());
  return 0;
}

/* ---- per-session plumbing ---- */
static int cb_core_fd(socket_t fd, int revents, void *ud) {
  csess_t *x = ud;
  (void)fd;
  if (!(revents & (POLLIN | POLLHUP | POLLERR))) return 0;
  for (;;) {
    if (x->core_in_len == x->core_in_cap) {
      size_t cap = x->core_in_cap ? x->core_in_cap * 2 : 65536;
      if (cap > CONSOLE_FRAME_MAX + 5) {
        sess_drop(x, "frame from the hub too large");
        return 0;
      }
      unsigned char *nb = realloc(x->core_in, cap);
      if (!nb) {
        sess_drop(x, "out of memory");
        return 0;
      }
      x->core_in = nb;
      x->core_in_cap = cap;
    }
    ssize_t n = read(x->core_fd, x->core_in + x->core_in_len, x->core_in_cap - x->core_in_len);
    if (n > 0) {
      x->core_in_len += (size_t)n;
      continue;
    }
    if (n == 0) {
      sess_drop(x, "closed by the hub");
      break;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) break;
    sess_drop(x, "hub link error");
    break;
  }
  size_t off = 0;
  long long t = now_ms();
  while (x->core_in_len - off >= 4) {
    uint32_t nl;
    memcpy(&nl, x->core_in + off, 4);
    uint32_t len = ntohl(nl);
    if (len < 1 || len > CONSOLE_FRAME_MAX) {
      sess_drop(x, "bad frame from the hub");
      break;
    }
    if (x->core_in_len - off - 4 < len) break;
    const unsigned char *f = x->core_in + off + 4;
    if (x->ui) ui_core_frame(x->ui, f[0], (const char *)f + 1, len - 1, t);
    off += 4 + len;
  }
  if (off) {
    memmove(x->core_in, x->core_in + off, x->core_in_len - off);
    x->core_in_len -= off;
  }
  return 0;
}

static void sess_flush(csess_t *x) {
  if (!x->ui) return;
  /* frames for the core */
  cbuf_t *co = ui_core_out(x->ui);
  while (co->len > 0 && x->core_fd >= 0) {
    ssize_t n = send(x->core_fd, co->p, co->len, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (n > 0) {
      cbuf_consume(co, (size_t)n);
      continue;
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) break;
    sess_drop(x, "hub link error");
    break;
  }
  /* bytes for the terminal, as far as the channel window allows */
  cbuf_t *to = ui_term_out(x->ui);
  while (to->len > 0 && x->ch && ssh_channel_is_open(x->ch)) {
    uint32_t win = ssh_channel_window_size(x->ch);
    if (win == 0) break;
    size_t n = to->len < win ? to->len : win;
    if (n > 32768) n = 32768;
    int w = ssh_channel_write(x->ch, to->p, (uint32_t)n);
    if (w <= 0) break;
    cbuf_consume(to, (size_t)w);
  }
  /* audit lines */
  int lvl;
  char line[400];
  while (ui_take_audit(x->ui, &lvl, line, sizeof(line))) ctl_log(lvl, "%s", line);
}

static int count_preauth(const char *ip, int *per_ip) {
  int n = 0;
  *per_ip = 0;
  for (csess_t *x = g_sessions; x; x = x->next) {
    if (x->shell) continue;
    n++;
    if (!strcmp(x->ip, ip)) (*per_ip)++;
  }
  return n;
}

static int count_consoles(void) {
  int n = 0;
  for (csess_t *x = g_sessions; x; x = x->next)
    if (x->shell) n++;
  return n;
}

static void sess_new(int fd, const char *ip) {
  int per_ip = 0;
  int pre = count_preauth(ip, &per_ip);
  if (pre >= CONSOLE_MAX_PREAUTH || per_ip >= CONSOLE_MAX_PREAUTH_PER_IP) {
    ctl_log(LOG_WARNING, "[CONSOLE] Too many SSH logins in progress; dropped %s", ip);
    close(fd);
    return;
  }
  pthread_mutex_lock(&g_pub_mu);
  unsigned gen = g_host_gen;
  pthread_mutex_unlock(&g_pub_mu);
  if (!g_bind || g_bind_gen != gen) rebuild_bind();
  if (!g_bind) {
    close(fd);
    return;
  }
  csess_t *x = calloc(1, sizeof(*x));
  if (!x) {
    close(fd);
    return;
  }
  x->core_fd = -1;
  snprintf(x->ip, sizeof(x->ip), "%s", ip);
  x->start_ms = now_ms();
  x->s = ssh_new();
  if (!x->s || ssh_bind_accept_fd(g_bind, x->s, fd) != SSH_OK) {
    ctl_log(LOG_WARNING, "[CONSOLE] SSH accept failed for %s", ip);
    if (x->s) ssh_free(x->s);   /* owns fd once accepted */
    else close(fd);
    free(x);
    return;
  }
  memset(&x->scb, 0, sizeof(x->scb));
  x->scb.userdata = x;
  x->scb.auth_pubkey_function = cb_auth_pubkey;
  x->scb.channel_open_request_session_function = cb_chan_open;
  ssh_callbacks_init(&x->scb);
  ssh_set_server_callbacks(x->s, &x->scb);
  ssh_set_auth_methods(x->s, SSH_AUTH_METHOD_PUBLICKEY);
  ssh_set_message_callback(x->s, cb_message, x);
  ssh_set_blocking(x->s, 0);
  if (ssh_handle_key_exchange(x->s) == SSH_ERROR) {
    ssh_free(x->s);
    free(x);
    return;
  }
  if (ssh_event_add_session(g_ev, x->s) == SSH_OK) x->in_event = true;
  x->next = g_sessions;
  g_sessions = x;
}

static void sess_free(csess_t *x) {
  const char *uwhy = NULL;
  bool ui_closed = x->ui && ui_closing(x->ui, &uwhy);
  const char *why = x->drop ? x->why : ui_closed ? uwhy : "closed";
  if (x->ui) {
    ui_goodbye(x->ui, why);
    sess_flush(x);
  }
  if (!x->authed && x->refused > 0) report_fail(x, "key refused");
  if (x->shell)
    ctl_log(LOG_INFO, "[CONSOLE] %s@%s console closed: %s", x->user, x->ip, why);
  else if (x->authed)
    ctl_log(LOG_WARNING, "[CONSOLE] %s@%s dropped before the console opened: %s",
            x->user, x->ip, why);
  if (x->core_fd >= 0) {
    if (x->core_in_event) ssh_event_remove_fd(g_ev, x->core_fd);
    close(x->core_fd);
  }
  if (x->in_event) ssh_event_remove_session(g_ev, x->s);
  if (x->ch) {
    ssh_channel_send_eof(x->ch);
    ssh_channel_close(x->ch);
  }
  ssh_disconnect(x->s);
  ssh_free(x->s);
  ui_free(x->ui);
  free(x->core_in);
  secure_wipe(x, sizeof(*x));
  free(x);
}

static void sess_service(csess_t *x, long long t) {
  if (!x->shell && t - x->start_ms > (long long)CONSOLE_LOGIN_GRACE * 1000) {
    if (!x->authed && x->refused > 0) report_fail(x, "login grace expired");
    sess_drop(x, "login grace expired");
  }
  int st = ssh_get_status(x->s);
  if (st & (SSH_CLOSED | SSH_CLOSED_ERROR)) sess_drop(x, "connection closed");
  if (x->shell && x->core_fd >= 0 && !x->core_in_event) {
    if (count_consoles() > CONSOLE_MAX_SESSIONS) {
      sess_drop(x, "too many consoles");
    } else if (ssh_event_add_fd(g_ev, x->core_fd, POLLIN, cb_core_fd, x) == SSH_OK) {
      x->core_in_event = true;
    }
  }
  if (x->ui) {
    ui_tick(x->ui, t);
    const char *why;
    if (ui_closing(x->ui, &why)) sess_drop(x, why);
    sess_flush(x);
  }
  if (x->eof && (!x->ui || !ui_busy(x->ui))) sess_drop(x, "client closed");
}

/* ---- control channel ---- */
static int cb_ctl(socket_t fd, int revents, void *ud) {
  (void)ud;
  if (!(revents & (POLLIN | POLLHUP | POLLERR))) return 0;
  ssize_t n = read(fd, g_ctl_in + g_ctl_len, sizeof(g_ctl_in) - g_ctl_len);
  if (n <= 0) {
    if (n == 0 || (errno != EAGAIN && errno != EINTR)) g_stop = 1;
    return 0;
  }
  g_ctl_len += (size_t)n;
  size_t off = 0;
  while (g_ctl_len - off >= 4) {
    uint32_t nl;
    memcpy(&nl, g_ctl_in + off, 4);
    uint32_t len = ntohl(nl);
    if (len == 0 || len > sizeof(g_ctl_in) - 5) {
      g_stop = 1;
      return 0;
    }
    if (g_ctl_len - off - 4 < len) break;
    char text[256];
    size_t tl = len < sizeof(text) - 1 ? len : sizeof(text) - 1;
    memcpy(text, g_ctl_in + off + 4, tl);
    text[tl] = '\0';
    off += 4 + len;
    if (strncmp(text, "NEW|", 4) == 0) {
      char *save = NULL;
      char *sfd = strtok_r(text + 4, "|", &save);
      char *ip = strtok_r(NULL, "|", &save);
      int nfd = sfd ? atoi(sfd) : -1;
      if (nfd > 2 && ip) sess_new(nfd, ip);
      else if (nfd > 2) close(nfd);
    }
  }
  memmove(g_ctl_in, g_ctl_in + off, g_ctl_len - off);
  g_ctl_len -= off;
  return 0;
}

static int cb_wake(socket_t fd, int revents, void *ud) {
  (void)ud;
  (void)revents;
  char b[16];
  (void)!read(fd, b, sizeof(b));
  return 0;
}

static void *console_main(void *arg) {
  (void)arg;
  ssh_init();
  ssh_set_log_level(SSH_LOG_NOLOG);
  g_ev = ssh_event_new();
  if (!g_ev) {
    g_stop = 1;
    return NULL;
  }
  ssh_event_add_fd(g_ev, g_ctl, POLLIN, cb_ctl, NULL);
  ssh_event_add_fd(g_ev, g_wake[0], POLLIN, cb_wake, NULL);
  rebuild_bind();
  while (!g_stop) {
    ssh_event_dopoll(g_ev, 25);
    long long t = now_ms();
    for (csess_t *x = g_sessions; x; x = x->next) sess_service(x, t);
    for (csess_t **pp = &g_sessions; *pp;) {
      csess_t *x = *pp;
      if (x->drop) {
        *pp = x->next;
        sess_free(x);
      } else {
        pp = &x->next;
      }
    }
  }
  while (g_sessions) {
    csess_t *x = g_sessions;
    g_sessions = x->next;
    sess_drop(x, "hub shutting down");
    sess_free(x);
  }
  ssh_event_remove_fd(g_ev, g_ctl);
  ssh_event_remove_fd(g_ev, g_wake[0]);
  ssh_event_free(g_ev);
  g_ev = NULL;
  if (g_bind) ssh_bind_free(g_bind);
  g_bind = NULL;
  ssh_finalize();
  return NULL;
}

bool console_thread_start(int ctl_fd) {
  if (g_running) return false;
  if (pipe(g_wake) != 0) return false;
  (void)fcntl(g_wake[0], F_SETFD, FD_CLOEXEC);
  (void)fcntl(g_wake[1], F_SETFD, FD_CLOEXEC);
  g_ctl = ctl_fd;
  g_stop = 0;
  /* The host key seed is the hub's own Ed25519 private key: kept out of
   * swap like the core's copy (hub_main.c).  Best effort, as there. */
  (void)mlock(g_host_seed, sizeof(g_host_seed));
  if (pthread_create(&g_thread, NULL, console_main, NULL) != 0) {
    close(g_wake[0]);
    close(g_wake[1]);
    g_wake[0] = g_wake[1] = -1;
    g_ctl = -1;
    return false;
  }
  g_running = true;
  return true;
}

void console_thread_stop(void) {
  if (!g_running) return;
  g_stop = 1;
  (void)!write(g_wake[1], "x", 1);
  pthread_join(g_thread, NULL);
  g_running = false;
  close(g_wake[0]);
  close(g_wake[1]);
  g_wake[0] = g_wake[1] = -1;
  if (g_ctl >= 0) close(g_ctl);
  g_ctl = -1;
  pthread_mutex_lock(&g_pub_mu);
  secure_wipe(g_host_seed, sizeof(g_host_seed));
  secure_wipe(g_creds, sizeof(g_creds));
  pthread_mutex_unlock(&g_pub_mu);
  (void)munlock(g_host_seed, sizeof(g_host_seed));
}
