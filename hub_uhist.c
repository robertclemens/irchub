/* hub_uhist.c - upgrade history (docs/plans/2026-10-31_upgrade_history_plan.md)
 *
 * The last X upgrade runs, one line each, kept in .irchub.cnf (uhist|) and
 * replicated hub to hub over CMD_UPGRADE_HISTORY.  A record belongs to the hub
 * that drove the run: only it bumps rev.  Every other hub stores the body as
 * it came and forwards it unchanged.
 *
 * The set converges without tombstones: same id = higher rev wins (a tie goes
 * to the greater string), and eviction is a pure function of the set: sort by
 * (started, id) descending and keep the top `keep`.
 *
 * Hub-local input is not the only source of a body, so nothing here trusts one:
 * uhist_parse() validates every field and bound, whether the body came from a
 * peer, the config file or this hub. */
#include "hub_uhist.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Codec --------------------------------------------------------------- */

static bool uh_must_escape(unsigned char c) {
  return c == '%' || c == '|' || c == ',' || c == ';' || c < 0x20 || c >= 0x7f;
}

/* Append s, escaped, at out+*off.  False when it does not fit. */
static bool uh_put_esc(char *out, size_t cap, size_t *off, const char *s) {
  static const char hex[] = "0123456789ABCDEF";
  size_t o = *off;
  for (const unsigned char *p = (const unsigned char *)(s ? s : ""); *p; p++) {
    if (uh_must_escape(*p)) {
      if (o + 3 >= cap) return false;
      out[o++] = '%';
      out[o++] = hex[*p >> 4];
      out[o++] = hex[*p & 15];
    } else {
      if (o + 1 >= cap) return false;
      out[o++] = (char)*p;
    }
  }
  out[o] = '\0';
  *off = o;
  return true;
}

static bool uh_put_raw(char *out, size_t cap, size_t *off, const char *s) {
  size_t n = strlen(s);
  if (*off + n >= cap) return false;
  memcpy(out + *off, s, n + 1);
  *off += n;
  return true;
}

static bool uh_put_ll(char *out, size_t cap, size_t *off, long long v) {
  char b[24];
  snprintf(b, sizeof(b), "%lld", v);
  return uh_put_raw(out, cap, off, b);
}

static int uh_hex(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

/* Decode [s, s+n) into dst.  False on a bad escape or one that does not fit.
 * A decoded control character becomes a space: this text reaches a terminal. */
static bool uh_unesc(const char *s, size_t n, char *dst, size_t cap) {
  size_t o = 0;
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c == '%') {
      if (i + 2 >= n) return false;
      int h = uh_hex(s[i + 1]), l = uh_hex(s[i + 2]);
      if (h < 0 || l < 0) return false;
      c = (unsigned char)(h << 4 | l);
      i += 2;
    }
    if (c < 0x20 || c == 0x7f) c = ' ';
    if (o + 1 >= cap) return false;
    dst[o++] = (char)c;
  }
  dst[o] = '\0';
  return true;
}

/* A whole non-negative decimal in [s, s+n); empty reads as 0. */
static bool uh_num(const char *s, size_t n, long long *out) {
  long long v = 0;
  if (n > 18) return false;
  for (size_t i = 0; i < n; i++) {
    if (!isdigit((unsigned char)s[i])) return false;
    v = v * 10 + (s[i] - '0');
  }
  *out = v;
  return true;
}

/* An id travels in the digest between ':' and ',': letters, digits, - and _. */
static bool uh_id_ok(const char *s) {
  if (!s[0] || strlen(s) >= 64) return false;
  for (; *s; s++)
    if (!isalnum((unsigned char)*s) && *s != '-' && *s != '_') return false;
  return true;
}

void hub_uhist_view_free(uhist_view_t *v) {
  free(v->nodes);
  v->nodes = NULL;
  v->node_count = 0;
}

/* Split one node.  Extra trailing fields are a later version's. */
static bool uh_parse_node(const char *s, size_t n, uhist_node_t *o) {
  const char *f[UHIST_NODE_FIELDS + 3];
  size_t fl[UHIST_NODE_FIELDS + 3];
  int c = 0;
  const char *p = s, *end = s + n;
  while (c < UHIST_NODE_FIELDS + 3) {
    const char *q = memchr(p, ',', (size_t)(end - p));
    f[c] = p;
    fl[c] = q ? (size_t)(q - p) : (size_t)(end - p);
    c++;
    if (!q) break;
    p = q + 1;
  }
  if (c < UHIST_NODE_FIELDS) return false;
  return uh_unesc(f[0], fl[0], o->kind, sizeof(o->kind)) && o->kind[0] &&
         uh_unesc(f[1], fl[1], o->state, sizeof(o->state)) && o->state[0] &&
         uh_unesc(f[2], fl[2], o->uuid, sizeof(o->uuid)) &&
         uh_unesc(f[3], fl[3], o->name, sizeof(o->name)) &&
         uh_unesc(f[4], fl[4], o->from, sizeof(o->from)) &&
         uh_unesc(f[5], fl[5], o->to, sizeof(o->to)) &&
         uh_unesc(f[6], fl[6], o->base, sizeof(o->base)) &&
         uh_unesc(f[7], fl[7], o->want, sizeof(o->want)) &&
         uh_unesc(f[8], fl[8], o->arch, sizeof(o->arch)) &&
         uh_unesc(f[9], fl[9], o->libc, sizeof(o->libc)) &&
         uh_num(f[10], fl[10], &o->committed) && uh_num(f[11], fl[11], &o->back) &&
         uh_num(f[12], fl[12], &o->done) &&
         uh_unesc(f[13], fl[13], o->reason, sizeof(o->reason)) &&
         (c < UHIST_NODE_FIELDS + 3 ||
          (uh_unesc(f[14], fl[14], o->code, sizeof(o->code)) &&
           uh_unesc(f[15], fl[15], o->build, sizeof(o->build)) &&
           uh_num(f[16], fl[16], &o->stage_s)));
}

bool hub_uhist_parse(const char *body, uhist_view_t *v) {
  memset(v, 0, sizeof(*v));
  size_t blen = strlen(body);
  if (blen == 0 || blen >= UHIST_LINE_MAX) return false;
  for (size_t i = 0; i < blen; i++) {
    unsigned char c = (unsigned char)body[i];
    if (c < 0x20 || c >= 0x7f) return false;
  }
  const char *f[UHIST_HEADER_FIELDS];
  size_t fl[UHIST_HEADER_FIELDS];
  int c = 0;
  const char *p = body, *end = body + blen;
  while (c < UHIST_HEADER_FIELDS) {
    const char *q = memchr(p, '|', (size_t)(end - p));
    f[c] = p;
    fl[c] = q ? (size_t)(q - p) : (size_t)(end - p);
    c++;
    if (!q) break;
    p = q + 1;
  }
  if (c < UHIST_HEADER_FIELDS) return false;

  long long step = 0, steps = 0;
  if (!uh_unesc(f[0], fl[0], v->id, sizeof(v->id)) || !uh_id_ok(v->id) ||
      !uh_num(f[1], fl[1], &v->rev) || v->rev <= 0 ||
      !uh_unesc(f[2], fl[2], v->driver_uuid, sizeof(v->driver_uuid)) || !v->driver_uuid[0] ||
      !uh_unesc(f[3], fl[3], v->driver_name, sizeof(v->driver_name)) ||
      !uh_unesc(f[4], fl[4], v->by, sizeof(v->by)) ||
      /* Not hub_ts_ahead: it lets anything through during a config load, and
       * a future `started` would hold the top of the list against real runs. */
      !uh_num(f[5], fl[5], &v->started) || v->started <= 0 ||
      v->started > (long long)time(NULL) + LWW_MAX_FUTURE ||
      !uh_num(f[6], fl[6], &v->rolling_at) || !uh_num(f[7], fl[7], &v->ended) ||
      !uh_unesc(f[8], fl[8], v->result, sizeof(v->result)) || !v->result[0] ||
      !uh_unesc(f[9], fl[9], v->bot_ver, sizeof(v->bot_ver)) ||
      !uh_unesc(f[10], fl[10], v->hub_ver, sizeof(v->hub_ver)) ||
      !uh_unesc(f[11], fl[11], v->variant, sizeof(v->variant)) ||
      !uh_unesc(f[12], fl[12], v->kind, sizeof(v->kind)) ||
      !uh_unesc(f[13], fl[13], v->min_from, sizeof(v->min_from)) ||
      !uh_num(f[14], fl[14], &v->plan_id) || !uh_num(f[15], fl[15], &step) ||
      !uh_num(f[16], fl[16], &steps) || step > MAX_UPGRADE_STEPS || steps > MAX_UPGRADE_STEPS ||
      !uh_unesc(f[17], fl[17], v->sel, sizeof(v->sel)) ||
      !uh_unesc(f[18], fl[18], v->summary, sizeof(v->summary)))
    return false;
  v->step = (int)step;
  v->steps = (int)steps;

  const char *ns = f[19];
  size_t nl = fl[19];
  if (nl == 0) return true;
  int count = 1;
  for (size_t i = 0; i < nl; i++)
    if (ns[i] == ';') count++;
  if (count > MAX_UPGRADE_NODES) return false;
  v->nodes = calloc((size_t)count, sizeof(*v->nodes));
  if (!v->nodes) return false;
  const char *np = ns, *nend = ns + nl;
  for (int i = 0; i < count; i++) {
    const char *q = memchr(np, ';', (size_t)(nend - np));
    size_t len = q ? (size_t)(q - np) : (size_t)(nend - np);
    if (!uh_parse_node(np, len, &v->nodes[i])) {
      hub_uhist_view_free(v);
      return false;
    }
    v->node_count = i + 1;
    np = q ? q + 1 : nend;
  }
  return true;
}

bool hub_uhist_format(const uhist_view_t *v, char *out, size_t cap) {
  size_t o = 0;
  out[0] = '\0';
#define PS(x) (uh_put_esc(out, cap, &o, (x)) && uh_put_raw(out, cap, &o, "|"))
#define PN(x) (uh_put_ll(out, cap, &o, (x)) && uh_put_raw(out, cap, &o, "|"))
  if (!PS(v->id) || !PN(v->rev) || !PS(v->driver_uuid) || !PS(v->driver_name) || !PS(v->by) ||
      !PN(v->started) || !PN(v->rolling_at) || !PN(v->ended) || !PS(v->result) ||
      !PS(v->bot_ver) || !PS(v->hub_ver) || !PS(v->variant) || !PS(v->kind) ||
      !PS(v->min_from) || !PN(v->plan_id) || !PN(v->step) || !PN(v->steps) || !PS(v->sel) ||
      !PS(v->summary))
    return false;
#undef PS
#undef PN
#define NS(x) (uh_put_esc(out, cap, &o, (x)) && uh_put_raw(out, cap, &o, ","))
#define NN(x) (uh_put_ll(out, cap, &o, (x)) && uh_put_raw(out, cap, &o, ","))
  for (int i = 0; i < v->node_count; i++) {
    const uhist_node_t *n = &v->nodes[i];
    if (i && !uh_put_raw(out, cap, &o, ";")) return false;
    if (!NS(n->kind) || !NS(n->state) || !NS(n->uuid) || !NS(n->name) || !NS(n->from) ||
        !NS(n->to) || !NS(n->base) || !NS(n->want) || !NS(n->arch) || !NS(n->libc) ||
        !NN(n->committed) || !NN(n->back) || !NN(n->done) || !NS(n->reason) ||
        !NS(n->code) || !NS(n->build) || !uh_put_ll(out, cap, &o, n->stage_s))
      return false;
  }
#undef NS
#undef NN
  return true;
}

/* ---- Store ---------------------------------------------------------------- */

int hub_uhist_keep(const hub_state_t *state) {
  int k = state->uhist_keep_setting;
  return k >= 1 && k <= MAX_UPGRADE_HISTORY ? k : UHIST_DEFAULT_KEEP;
}

/* Negative when a sorts before b: newest first. */
static int uh_order(time_t a_started, const char *a_id, time_t b_started, const char *b_id) {
  if (a_started != b_started) return a_started > b_started ? -1 : 1;
  return -strcmp(a_id, b_id);
}

static void uh_rec_free(uhist_rec_t *r) {
  free(r->body);
  memset(r, 0, sizeof(*r));
}

static void uh_remove_at(hub_state_t *state, int i) {
  uh_rec_free(&state->uhist[i]);
  for (int j = i + 1; j < state->uhist_count; j++) state->uhist[j - 1] = state->uhist[j];
  state->uhist_count--;
  memset(&state->uhist[state->uhist_count], 0, sizeof(state->uhist[0]));
}

void hub_uhist_trim(hub_state_t *state) {
  int keep = hub_uhist_keep(state);
  while (state->uhist_count > keep) {
    uh_remove_at(state, state->uhist_count - 1);
    state->config_dirty = true;
  }
}

int hub_uhist_find(const hub_state_t *state, const char *id) {
  for (int i = 0; i < state->uhist_count; i++)
    if (strcmp(state->uhist[i].id, id) == 0) return i;
  return -1;
}

/* Merge a parsed body.  True when the store changed. */
static bool uh_merge(hub_state_t *state, const uhist_view_t *v, const char *body) {
  int at = hub_uhist_find(state, v->id);
  if (at >= 0) {
    const uhist_rec_t *r = &state->uhist[at];
    if (v->rev < r->rev || (v->rev == r->rev && strcmp(body, r->body) <= 0)) return false;
  }
  char *copy = strdup(body);
  if (!copy) {
    hub_log_error("[UPGRADE] OOM storing upgrade history\n");
    return false;
  }
  if (at >= 0) uh_remove_at(state, at);

  int keep = hub_uhist_keep(state);
  int pos = 0;
  while (pos < state->uhist_count &&
         uh_order(state->uhist[pos].started, state->uhist[pos].id, (time_t)v->started, v->id) < 0)
    pos++;
  /* It would fall straight off the end: nothing new is stored, but an older
   * revision removed above is a change the caller must save and flood. */
  if (pos >= keep) {
    free(copy);
    return at >= 0;
  }
  if (state->uhist_count >= MAX_UPGRADE_HISTORY) {
    uh_remove_at(state, state->uhist_count - 1);
  }
  for (int j = state->uhist_count; j > pos; j--) state->uhist[j] = state->uhist[j - 1];
  uhist_rec_t *n = &state->uhist[pos];
  memset(n, 0, sizeof(*n));
  n->body = copy;
  n->rev = v->rev;
  n->started = (time_t)v->started;
  snprintf(n->id, sizeof(n->id), "%s", v->id);
  state->uhist_count++;
  hub_uhist_trim(state);
  return true;
}

bool hub_uhist_load_line(hub_state_t *state, const char *body) {
  uhist_view_t v;
  if (!hub_uhist_parse(body, &v)) return false;
  uh_merge(state, &v, body);
  hub_uhist_view_free(&v);
  return true;
}

/* ---- Wire ----------------------------------------------------------------- */

static void uh_send_record(hub_state_t *state, hub_client_t *c, const char *body) {
  size_t n = strlen(body);
  char *frame = malloc(n + 3);
  if (!frame) {
    hub_log_error("[UPGRADE] OOM sending upgrade history\n");
    return;
  }
  frame[0] = 'R';
  frame[1] = '|';
  memcpy(frame + 2, body, n + 1);
  hub_peer_enqueue_sync(state, c, CMD_UPGRADE_HISTORY, LANE_BULK, frame, NULL, 0);
  free(frame);
}

static void uh_flood(hub_state_t *state, const char *body, const hub_client_t *except) {
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type == CLIENT_HUB && c->authenticated && c != except)
      uh_send_record(state, c, body);
  }
}

void hub_uhist_send_digest(hub_state_t *state, hub_client_t *c) {
  char d[UHIST_DIGEST_MAX];
  int o = snprintf(d, sizeof(d), "D|%d|", hub_uhist_keep(state));
  for (int i = 0; i < state->uhist_count; i++) {
    const uhist_rec_t *r = &state->uhist[i];
    o += snprintf(d + o, sizeof(d) - (size_t)o, "%s%s:%lld:%lld", i ? "," : "", r->id, r->rev,
                  (long long)r->started);
  }
  hub_peer_enqueue_sync(state, c, CMD_UPGRADE_HISTORY, LANE_BULK, d, NULL, 0);
}

/* Push what the sender of this digest lacks.  A digest is never answered with
 * a digest, so this cannot loop. */
static void uh_on_digest(hub_state_t *state, hub_client_t *from, const char *rest) {
  char *end;
  errno = 0;
  long keep = strtol(rest, &end, 10);
  if (errno || end == rest || *end != '|' || keep < 1 || keep > MAX_UPGRADE_HISTORY) {
    hub_log_warning("[UPGRADE] Malformed history digest from %s\n", hub_who_client(state, from));
    return;
  }
  struct {
    char id[64];
    long long rev, started;
  } peer[MAX_UPGRADE_HISTORY];
  int pn = 0;
  const char *p = end + 1;
  while (*p && pn < MAX_UPGRADE_HISTORY) {
    const char *c1 = strchr(p, ':');
    if (!c1 || (size_t)(c1 - p) >= sizeof(peer[0].id)) goto bad;
    memcpy(peer[pn].id, p, (size_t)(c1 - p));
    peer[pn].id[c1 - p] = '\0';
    const char *c2 = strchr(c1 + 1, ':');
    if (!c2 || !uh_num(c1 + 1, (size_t)(c2 - c1 - 1), &peer[pn].rev)) goto bad;
    const char *q = strchr(c2 + 1, ',');
    size_t sl = q ? (size_t)(q - c2 - 1) : strlen(c2 + 1);
    if (!uh_num(c2 + 1, sl, &peer[pn].started)) goto bad;
    if (!uh_id_ok(peer[pn].id)) goto bad;
    pn++;
    if (!q) break;
    p = q + 1;
  }

  int oldest = -1;
  for (int i = 0; i < pn; i++)
    if (oldest < 0 || uh_order((time_t)peer[i].started, peer[i].id, (time_t)peer[oldest].started,
                               peer[oldest].id) > 0)
      oldest = i;
  for (int i = 0; i < state->uhist_count; i++) {
    const uhist_rec_t *r = &state->uhist[i];
    int at = -1;
    for (int j = 0; j < pn; j++)
      if (strcmp(peer[j].id, r->id) == 0) at = j;
    if (at >= 0) {
      if (peer[at].rev < r->rev) uh_send_record(state, from, r->body);
      continue;
    }
    /* Outside its window: it would evict this straight away. */
    if (pn >= keep && oldest >= 0 &&
        uh_order(r->started, r->id, (time_t)peer[oldest].started, peer[oldest].id) > 0)
      continue;
    uh_send_record(state, from, r->body);
  }
  return;
bad:
  hub_log_warning("[UPGRADE] Malformed history digest from %s\n", hub_who_client(state, from));
}

void hub_uhist_process(hub_state_t *state, hub_client_t *from, const char *payload) {
  if (payload[0] == 'D' && payload[1] == '|') {
    uh_on_digest(state, from, payload + 2);
    return;
  }
  if (payload[0] != 'R' || payload[1] != '|') {
    hub_log_warning("[UPGRADE] Unknown history frame from %s\n", hub_who_client(state, from));
    return;
  }
  const char *body = payload + 2;
  uhist_view_t v;
  if (!hub_uhist_parse(body, &v)) {
    hub_log_warning("[UPGRADE] Dropped a malformed history record from %s\n",
                    hub_who_client(state, from));
    return;
  }
  if (uh_merge(state, &v, body)) {
    state->config_dirty = true;
    uh_flood(state, body, from);
  }
  hub_uhist_view_free(&v);
}

/* The driver stores a new rev of its own record, floods it and writes the file
 * now: it may be about to replace this process. */
void hub_uhist_put_own(hub_state_t *state, uhist_view_t *v) {
  int at = hub_uhist_find(state, v->id);
  v->rev = at >= 0 ? state->uhist[at].rev + 1 : 1;
  char *body = malloc(UHIST_LINE_MAX);
  if (!body) {
    hub_log_error("[UPGRADE] OOM recording upgrade %s\n", v->id);
    return;
  }
  if (!hub_uhist_format(v, body, UHIST_LINE_MAX)) {
    hub_log_warning("[UPGRADE] History record for %s does not fit; not kept\n", v->id);
    free(body);
    return;
  }
  if (uh_merge(state, v, body)) uh_flood(state, body, NULL);
  free(body);
  hub_config_write(state);
}

/* What the plan's earlier steps recorded as the admin who typed it. */
void hub_uhist_plan_by(const hub_state_t *state, long long plan_id, char *out, size_t cap) {
  out[0] = '\0';
  for (int i = 0; i < state->uhist_count; i++) {
    uhist_view_t v;
    if (!hub_uhist_parse(state->uhist[i].body, &v)) continue;
    bool hit = v.plan_id == plan_id && strcmp(v.driver_uuid, state->hub_uuid) == 0 && v.by[0];
    if (hit) snprintf(out, cap, "%s", v.by);
    hub_uhist_view_free(&v);
    if (hit) return;
  }
}

/* A boot closes what the last process could not: a run it never finished, and
 * the driver's own node, which only the new build can report on. */
void hub_uhist_boot(hub_state_t *state) {
  bool changed = false;
  char ids[MAX_UPGRADE_HISTORY][64];
  int n = state->uhist_count;
  for (int i = 0; i < n; i++) snprintf(ids[i], sizeof(ids[i]), "%s", state->uhist[i].id);
  for (int i = 0; i < n; i++) {
    int at = hub_uhist_find(state, ids[i]);
    if (at < 0) continue;
    uhist_view_t v;
    if (!hub_uhist_parse(state->uhist[at].body, &v)) continue;
    if (strcmp(v.driver_uuid, state->hub_uuid) != 0) {
      hub_uhist_view_free(&v);
      continue;
    }
    bool amend = false;
    time_t now = time(NULL);
    if (strcmp(v.result, "running") == 0) {
      snprintf(v.result, sizeof(v.result), "interrupted");
      snprintf(v.summary, sizeof(v.summary), "this hub restarted before the run finished");
      v.ended = (long long)now;
      amend = true;
    } else if (strcmp(v.result, "aborted") != 0) {
      for (int k = 0; k < v.node_count; k++) {
        uhist_node_t *nd = &v.nodes[k];
        if (nd->kind[0] != 's' || strcmp(nd->state, "committing") != 0) continue;
        const char *want = nd->want[0] ? nd->want : nd->base;
        bool ok = hub_update_version_cmp(HUB_VERSION, nd->to) == 0 &&
                  (!want[0] || strcmp(want, hub_update_host_variant()) == 0);
        int done = 0, unable = 0;
        nd->done = (long long)now;
        snprintf(nd->state, sizeof(nd->state), "%s", ok ? "done" : "failed");
        if (!ok)
          snprintf(nd->reason, sizeof(nd->reason), "came back on %s/%s", HUB_VERSION,
                   hub_update_host_variant());
        for (int m = 0; m < v.node_count; m++) {
          if (strcmp(v.nodes[m].state, "done") == 0) done++;
          else if (strcmp(v.nodes[m].state, "unable") == 0) unable++;
        }
        if (ok) {
          snprintf(v.summary, sizeof(v.summary), "%d node(s) now on the target, %d could not take it",
                   done, unable);
        } else {
          snprintf(v.result, sizeof(v.result), "partial");
          snprintf(v.summary, sizeof(v.summary), "%d node(s) upgraded, but this hub stayed on %s",
                   done, HUB_VERSION);
        }
        v.ended = (long long)now;
        amend = true;
      }
    }
    if (amend) {
      hub_uhist_put_own(state, &v);
      changed = true;
    }
    hub_uhist_view_free(&v);
  }
  if (changed) hub_log_info("[UPGRADE] Upgrade history brought up to date after the restart\n");
}

/* ---- Console -------------------------------------------------------------- */

static void uh_reply_run(reply_t *r, const uhist_view_t *v) {
  int done = 0, failed = 0, unable = 0, already = 0, skipped = 0, idle = 0, open = 0;
  for (int i = 0; i < v->node_count; i++) {
    const char *s = v->nodes[i].state;
    if (!strcmp(s, "done")) done++;
    else if (!strcmp(s, "failed")) failed++;
    else if (!strcmp(s, "unable")) unable++;
    else if (!strcmp(s, "already")) already++;
    else if (!strcmp(s, "skipped")) skipped++;
    else if (!strcmp(s, "idle")) idle++;
    else open++;
  }
  reply_kv(r, "id", v->id);
  reply_kvi(r, "rev", v->rev);
  reply_kvi(r, "started", v->started);
  if (v->rolling_at) reply_kvi(r, "rolling", v->rolling_at);
  if (v->ended) reply_kvi(r, "ended", v->ended);
  reply_kv(r, "result", v->result);
  /* A driver that never came back never closes its record. */
  if (!strcmp(v->result, "running") && time(NULL) - (time_t)v->started > UPGRADE_PLAN_TTL)
    reply_kvb(r, "stale", true);
  if (v->bot_ver[0]) reply_kv(r, "bot_ver", v->bot_ver);
  if (v->hub_ver[0]) reply_kv(r, "hub_ver", v->hub_ver);
  reply_kv(r, "driver", v->driver_name[0] ? v->driver_name : v->driver_uuid);
  reply_kv(r, "driver_uuid", v->driver_uuid);
  if (v->by[0]) reply_kv(r, "by", v->by);
  if (v->sel[0]) reply_kv(r, "sel", v->sel);
  if (v->steps > 0) {
    reply_kvi(r, "plan", v->plan_id);
    reply_kvi(r, "step", v->step);
    reply_kvi(r, "steps", v->steps);
  }
  if (v->summary[0]) reply_kv(r, "summary", v->summary);
  reply_kvi(r, "done", done);
  reply_kvi(r, "failed", failed);
  reply_kvi(r, "unable", unable);
  reply_kvi(r, "already", already);
  reply_kvi(r, "skipped", skipped);
  reply_kvi(r, "idle", idle);
  reply_kvi(r, "open", open);
}

void hub_uhist_reply_runs(const hub_state_t *state, reply_t *r) {
  for (int i = 0; i < state->uhist_count; i++) {
    uhist_view_t v;
    if (!hub_uhist_parse(state->uhist[i].body, &v)) continue;
    reply_rec(r, "run");
    uh_reply_run(r, &v);
    hub_uhist_view_free(&v);
  }
}

/* 0 = one found (*at), -1 = none, -2 = more than one. */
static int uh_find_prefix(const hub_state_t *state, const char *pfx, int *at) {
  size_t n = strlen(pfx);
  int hits = 0;
  if (n < UHIST_MIN_PREFIX) return -1;
  for (int i = 0; i < state->uhist_count; i++)
    if (strncmp(state->uhist[i].id, pfx, n) == 0) {
      *at = i;
      hits++;
    }
  return hits == 1 ? 0 : hits == 0 ? -1 : -2;
}

int hub_uhist_reply_one(const hub_state_t *state, const char *pfx, reply_t *r) {
  int at = -1;
  int rc = uh_find_prefix(state, pfx, &at);
  if (rc != 0) return rc;
  uhist_view_t v;
  if (!hub_uhist_parse(state->uhist[at].body, &v)) return -1;
  reply_ok(r, "upg.run");
  uh_reply_run(r, &v);
  if (v.variant[0]) reply_kv(r, "variant", v.variant);
  if (v.kind[0]) reply_kv(r, "kind", v.kind);
  if (v.min_from[0]) reply_kv(r, "min_from", v.min_from);
  for (int i = 0; i < v.node_count; i++) {
    const uhist_node_t *n = &v.nodes[i];
    reply_rec(r, "node");
    reply_kv(r, "kind", n->kind[0] == 'b' ? "bot" : n->kind[0] == 'h' ? "hub" : "driver");
    reply_kv(r, "uuid", n->uuid);
    if (n->name[0]) reply_kv(r, "name", n->name);
    reply_kv(r, "state", n->state);
    if (n->from[0]) reply_kv(r, "from", n->from);
    if (n->to[0]) reply_kv(r, "to", n->to);
    if (n->base[0]) reply_kv(r, "base", n->base);
    if (n->want[0]) reply_kv(r, "want", n->want);
    if (n->arch[0]) reply_kv(r, "arch", n->arch);
    if (n->libc[0]) reply_kv(r, "libc", n->libc);
    if (n->committed) reply_kvi(r, "committed", n->committed);
    if (n->back) reply_kvi(r, "back", n->back);
    if (n->done) reply_kvi(r, "done", n->done);
    if (n->reason[0]) reply_kv(r, "reason", n->reason);
    if (n->code[0]) reply_kv(r, "code", n->code);
    if (n->build[0]) reply_kv(r, "build", n->build);
    if (n->stage_s > 0) reply_kvi(r, "stage_s", n->stage_s);
  }
  hub_uhist_view_free(&v);
  return 0;
}
