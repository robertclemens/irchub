/* hub_pool.c — the hub side of the IRC server pool (2.5.4).
 *
 * Plan: docs/plans/2026-10-29_server_pool_plan.md.  The N|/S| records live in
 * global_entries[] (hub_storage.c: hub_storage_put_record, validated by
 * pool_rec.c); this file holds what acts on them: the bots' NETWORK= reports
 * (CMD_SERVER_REPORT), learning the network's name and flagging an entry
 * wrongnet. */
#include "hub.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Volatile strike list per entry (§4.1): the distinct bots that reported it
 * wrong in the last POOL_STRIKE_WINDOW seconds. */
#define POOL_STRIKE_BOTS    4
#define POOL_STRIKE_WINDOW  3600
#define POOL_STRIKES_NEEDED 2
typedef struct {
  char uuid[POOL_UUID_LEN + 1];
  char bot[POOL_STRIKE_BOTS][64];
  time_t at[POOL_STRIKE_BOTS];
} pool_strikes_t;
static pool_strikes_t g_strikes[MAX_POOL_SERVERS];

static void announce(hub_state_t *state, const char *key, const char *value, time_t ts) {
  char line[POOL_N_LINE_MAX + POOL_S_LINE_MAX];
  int w = snprintf(line, sizeof(line), "%s|%s|%lld\n", key, value, (long long)ts);
  if (w > 0 && w < (int)sizeof(line)) hub_broadcast_sync_to_peers(state, line, -1);
  state->config_dirty = true;
  state->bot_config_pending = true;
}

/* The stored N| of `net_id`, or the default (name not learned) with *ts 0. */
static void net_get(const hub_state_t *state, const char *net_id, pool_net_t *out, time_t *ts) {
  int i = hub_global_find(state, "N", net_id);
  if (i >= 0 && pool_net_parse(state->global_entries[i].value, out)) {
    *ts = state->global_entries[i].timestamp;
    return;
  }
  memset(out, 0, sizeof(*out));
  snprintf(out->net_id, sizeof(out->net_id), "%s", net_id);
  snprintf(out->label, sizeof(out->label), "%s", net_id);
  *ts = 0;
}

bool hub_pool_net_put(hub_state_t *state, const pool_net_t *n) {
  pool_net_t cur;
  time_t cur_ts;
  net_get(state, n->net_id, &cur, &cur_ts);
  char v[POOL_N_LINE_MAX];
  if (pool_net_format(n, v, sizeof(v)) < 0) return false;
  time_t ts = hub_lww_next_ts(cur_ts);
  if (!hub_storage_put_record(state, "N", v, ts)) return false;
  announce(state, "N", v, ts);
  return true;
}

bool hub_pool_srv_put(hub_state_t *state, const pool_srv_t *s) {
  char v[POOL_S_LINE_MAX];
  if (pool_srv_format(s, v, sizeof(v)) < 0) return false;
  time_t ts = hub_lww_next_ts(hub_storage_global_ts(state, "S", v));
  if (!hub_storage_put_record(state, "S", v, ts)) return false;
  announce(state, "S", v, ts);
  return true;
}

bool hub_pool_srv_get(const hub_state_t *state, const char *uuid, pool_srv_t *out) {
  int i = hub_global_find(state, "S", uuid);
  return i >= 0 && pool_srv_parse(state->global_entries[i].value, out);
}

static pool_strikes_t *strikes_for(const char *uuid) {
  pool_strikes_t *free_slot = NULL, *oldest = &g_strikes[0];
  for (int i = 0; i < MAX_POOL_SERVERS; i++) {
    pool_strikes_t *p = &g_strikes[i];
    if (strcmp(p->uuid, uuid) == 0) return p;
    if (!p->uuid[0] && !free_slot) free_slot = p;
    if (p->at[0] < oldest->at[0]) oldest = p;
  }
  pool_strikes_t *p = free_slot ? free_slot : oldest;
  memset(p, 0, sizeof(*p));
  snprintf(p->uuid, sizeof(p->uuid), "%s", uuid);
  return p;
}

/* Record bot `who` against entry `uuid`; the number of distinct bots now. */
static int strike(const char *uuid, const char *who, time_t now, bool *added) {
  pool_strikes_t *p = strikes_for(uuid);
  int n = 0, slot = -1;
  for (int i = 0; i < POOL_STRIKE_BOTS; i++) {
    if (p->bot[i][0] && now - p->at[i] > POOL_STRIKE_WINDOW) p->bot[i][0] = '\0';
    if (p->bot[i][0] && strcmp(p->bot[i], who) == 0) slot = i;
  }
  *added = slot < 0;
  if (slot < 0)
    for (int i = 0; i < POOL_STRIKE_BOTS && slot < 0; i++)
      if (!p->bot[i][0]) slot = i;
  if (slot < 0) slot = 0;
  snprintf(p->bot[slot], sizeof(p->bot[slot]), "%s", who);
  p->at[slot] = now;
  for (int i = 0; i < POOL_STRIKE_BOTS; i++) n += p->bot[i][0] != '\0';
  return n;
}

static void strikes_clear(const char *uuid) {
  for (int i = 0; i < MAX_POOL_SERVERS; i++)
    if (strcmp(g_strikes[i].uuid, uuid) == 0) memset(&g_strikes[i], 0, sizeof(g_strikes[i]));
}

void hub_pool_strikes_clear(const char *uuid) { strikes_clear(uuid); }

static int active_bots(const hub_state_t *state) {
  int n = 0;
  for (int i = 0; i < state->bot_count; i++) n += state->bots[i].is_active;
  return n;
}

/* Printable ASCII, no '|', at most cap-1 bytes: a server name for the log. */
static bool printable_field(const char *s, size_t cap) {
  size_t n = strlen(s);
  if (n >= cap) return false;
  for (size_t i = 0; i < n; i++)
    if ((unsigned char)s[i] < 0x20 || (unsigned char)s[i] >= 0x7f) return false;
  return true;
}

/* A strike that is new here goes to every peer that keeps a pool except the
 * one it came from, which pass it on the same way: the two-bot threshold is
 * mesh-wide although each bot reports only to its own hub.  A bot already
 * struck against the entry is not forwarded again, which ends the flood. */
static void strike_forward(hub_state_t *state, int from_fd, const char *bot, const char *uuid,
                           const char *kind, const char *network, const char *server) {
  char fw[64 + POOL_UUID_LEN + POOL_NET_NAME_MAX + 300];
  int n = snprintf(fw, sizeof(fw), "%s|%s|%s|%s|%.255s", bot, uuid, kind, network, server);
  if (n <= 0 || n >= (int)sizeof(fw)) return;
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type != CLIENT_HUB || !c->authenticated || c->fd == from_fd || !hub_peer_takes_pool(state, c))
      continue;
    queued_msg_t *m = queued_msg_new(CMD_SERVER_REPORT, LANE_DELTA, (const unsigned char *)fw, n);
    if (m && !peer_enqueue(c, m)) hub_log_warning("[POOL] Could not queue a report to %s\n", c->ip);
  }
}

/* One report, from a local bot (from_fd = its fd) or a peer's forward. */
static void report_apply(hub_state_t *state, int from_fd, bool local, const char *bot,
                         const char *who, const char *uuid, const char *kind,
                         const char *network, const char *server) {
  pool_srv_t s;
  if (!hub_pool_srv_get(state, uuid, &s) || s.deleted) return;
  pool_net_t net;
  time_t net_ts;
  net_get(state, s.net_id, &net, &net_ts);

  if (strcmp(kind, "ok") == 0) {
    if (!local || !network[0]) return;
    if (!net.name[0]) {
      /* The first bot to register names the network; then it is locked
       * (plan D6).  A +s admin can change it or add aliases. */
      snprintf(net.name, sizeof(net.name), "%s", network);
      net.deleted = false;
      if (hub_pool_net_put(state, &net))
        hub_log_info("[POOL] Network %s learned as %s (from %s on %s)\n", net.net_id, network,
                     who, server[0] ? server : s.host);
    }
    if (pool_net_matches(&net, network)) strikes_clear(uuid);
    return;
  }
  if (strcmp(kind, "wrongnet") != 0 && strcmp(kind, "unverified") != 0) return;
  if (!net.name[0] || s.state != POOL_OK) return; /* nothing to be wrong against */
  if (network[0] && pool_net_matches(&net, network)) return; /* a stale report */
  bool added = false;
  int n = strike(uuid, bot, time(NULL), &added);
  if (added) strike_forward(state, from_fd, bot, uuid, kind, network, server);
  if (n < POOL_STRIKES_NEEDED && active_bots(state) > 1) {
    hub_log_info("[POOL] %s reports %s (%s) as %s (NETWORK=%s); %d of %d bots so far\n", who,
                 s.host, uuid, kind, network[0] ? network : "none", n, POOL_STRIKES_NEEDED);
    return;
  }
  s.state = POOL_WRONGNET;
  snprintf(s.seen, sizeof(s.seen), "%s", network);
  if (hub_pool_srv_put(state, &s) && ++g_hub_stats.pool_flagged)
    hub_log_warning("[POOL] Server %s (%s) flagged wrong network: NETWORK=%s, expected %s "
                    "(%d bot%s); 'server clear' or a network alias undoes it\n",
                    s.host, uuid, network[0] ? network : "none", net.name, n, n == 1 ? "" : "s");
  strikes_clear(uuid);
}

/* Split `payload` into exactly `want` '|' fields in buf; the last may not
 * hold '|'.  false when the shape is wrong. */
static bool report_fields(const char *payload, char *buf, size_t cap, char **f, int want) {
  if (!payload || strlen(payload) >= cap) return false;
  memcpy(buf, payload, strlen(payload) + 1);
  int nf = 0;
  char *p = buf;
  f[nf++] = p;
  for (; *p && nf < want; p++)
    if (*p == '|') { *p = '\0'; f[nf++] = p + 1; }
  return nf == want && !strchr(f[want - 1], '|');
}

static bool report_shape_ok(const char *uuid, const char *network, const char *server) {
  return strlen(uuid) == POOL_UUID_LEN && (!network[0] || pool_net_name_ok(network)) &&
         printable_field(server, 256);
}

void hub_pool_server_report(hub_state_t *state, hub_client_t *client, const char *payload) {
  if (client->type != CLIENT_BOT || !client->authenticated ||
      !hub_bot_version_takes_pool(client->bot_version))
    return;
  char buf[POOL_UUID_LEN + POOL_NET_NAME_MAX + 320];
  char *f[4];
  if (!report_fields(payload, buf, sizeof(buf), f, 4) || !report_shape_ok(f[0], f[2], f[3])) {
    hub_log_warning("[POOL] Ignored a malformed server report from %s\n",
                    hub_who_client(state, client));
    return;
  }
  g_hub_stats.pool_reports++;
  char who[160];
  snprintf(who, sizeof(who), "%s", hub_who_client(state, client));
  report_apply(state, client->fd, true, client->id, who, f[0], f[1], f[2], f[3]);
}

void hub_pool_peer_report(hub_state_t *state, hub_client_t *peer, const char *payload) {
  if (peer->type != CLIENT_HUB || !peer->authenticated) return;
  char buf[64 + POOL_UUID_LEN + POOL_NET_NAME_MAX + 320];
  char *f[5];
  if (!report_fields(payload, buf, sizeof(buf), f, 5) || !hub_uuid_shape(f[0]) ||
      !report_shape_ok(f[1], f[3], f[4])) {
    hub_log_warning("[POOL] Ignored a malformed server report forwarded by %s\n", peer->ip);
    return;
  }
  /* each name helper may share one static buffer: copy them one at a time */
  char bot_who[128], via[128], who[280];
  snprintf(bot_who, sizeof(bot_who), "%s", hub_who(state, 'b', f[0]));
  snprintf(via, sizeof(via), "%s", hub_who_client(state, peer));
  snprintf(who, sizeof(who), "%s (via %s)", bot_who, via);
  report_apply(state, peer->fd, false, f[0], who, f[1], f[2], f[3], f[4]);
}

bool hub_pool_link_word_ok(const char *w) {
  return strcmp(w, "connecting") == 0 || strcmp(w, "up") == 0 || strcmp(w, "down") == 0 ||
         strcmp(w, "idle") == 0;
}

bool hub_pool_irc_link(hub_state_t *state, hub_client_t *client, const char *payload) {
  (void)state;
  if (client->type != CLIENT_BOT || !client->authenticated ||
      !hub_bot_version_takes_pool(client->bot_version) || !payload)
    return false;
  char buf[POOL_NET_ID_MAX + POOL_UUID_LEN + POOL_LINK_WORD_MAX + 1100];
  if (strlen(payload) >= sizeof(buf)) return false;
  memcpy(buf, payload, strlen(payload) + 1);
  char *f[4];
  int nf = 0;
  char *p = buf;
  f[nf++] = p;
  for (; *p && nf < 4; p++)
    if (*p == '|') { *p = '\0'; f[nf++] = p + 1; }
  if (nf < 3 || !pool_net_id_ok(f[0]) || !hub_pool_link_word_ok(f[2]) ||
      (f[1][0] && strcmp(f[1], "-") != 0 && strlen(f[1]) != POOL_UUID_LEN))
    return false;
  for (const char *q = f[1]; *q; q++)
    if (!((*q >= '0' && *q <= '9') || (*q >= 'a' && *q <= 'f') || *q == '-')) return false;
  const char *ent = strcmp(f[1], "-") == 0 ? "" : f[1];
  bool changed = strcmp(client->bot_irc_entry, ent) != 0 || strcmp(client->bot_irc_link, f[2]) != 0;
  snprintf(client->bot_irc_entry, sizeof(client->bot_irc_entry), "%s", ent);
  snprintf(client->bot_irc_link, sizeof(client->bot_irc_link), "%s", f[2]);
  return changed;
}

/* ---- CMD_POOL_VIEW (plan §5.3) ----------------------------------------- */

typedef struct {
  char bot[64];
  char entry[POOL_UUID_LEN + 1];
  char server[ROSTER_SERVER_MAX + 1];
  bool up;           /* else connecting */
  time_t at;         /* local reported_at, newest wins for a bot seen twice */
} view_bot_t;

static void view_add(view_bot_t *v, int *n, int cap, const char *bot, const char *entry,
                     const char *link, const char *server, time_t at) {
  bool up = strcmp(link, "up") == 0;
  if (!entry[0] || (!up && strcmp(link, "connecting") != 0)) return;
  for (int i = 0; i < *n; i++)
    if (strcmp(v[i].bot, bot) == 0) {
      if (at < v[i].at) return;
      snprintf(v[i].entry, sizeof(v[i].entry), "%s", entry);
      snprintf(v[i].server, sizeof(v[i].server), "%s", server);
      v[i].up = up;
      v[i].at = at;
      return;
    }
  if (*n >= cap) return;
  view_bot_t *b = &v[(*n)++];
  snprintf(b->bot, sizeof(b->bot), "%s", bot);
  snprintf(b->entry, sizeof(b->entry), "%s", entry);
  snprintf(b->server, sizeof(b->server), "%s", server);
  b->up = up;
  b->at = at;
}

/* The view text; its length, or -1. */
static int view_build(hub_state_t *state, char *out, size_t cap) {
  static view_bot_t v[MAX_BOT_ROSTER + MAX_BOTS];
  int n = 0, vcap = (int)(sizeof(v) / sizeof(v[0]));
  time_t now = time(NULL);
  for (int i = 0; i < state->client_count; i++) {
    const hub_client_t *c = state->clients[i];
    if (c->type == CLIENT_BOT && c->authenticated && !c->retiring && c->bot_irc_link[0])
      view_add(v, &n, vcap, c->id, c->bot_irc_entry, c->bot_irc_link, c->bot_server, now);
  }
  for (int i = 0; i < state->roster_count; i++) {
    const bot_roster_t *r = &state->roster[i];
    if (r->irc_link[0])
      view_add(v, &n, vcap, r->bot_uuid, r->irc_entry, r->irc_link, r->server, r->reported_at);
  }
  /* Distinct real servers (the 004 names) with the bots up on each, and the
   * server index of every bot that is up. */
  static char srv[MAX_BOT_ROSTER + MAX_BOTS][ROSTER_SERVER_MAX + 1];
  static int srv_up[MAX_BOT_ROSTER + MAX_BOTS], bot_srv[MAX_BOT_ROSTER + MAX_BOTS];
  static bool mark[MAX_BOT_ROSTER + MAX_BOTS];
  int ns = 0;
  for (int i = 0; i < n; i++) {
    bot_srv[i] = -1;
    if (!v[i].up || !v[i].server[0]) continue;
    int k = 0;
    while (k < ns && strcasecmp(srv[k], v[i].server) != 0) k++;
    if (k == ns) {
      snprintf(srv[ns], sizeof(srv[ns]), "%s", v[i].server);
      srv_up[ns++] = 0;
    }
    srv_up[k]++;
    bot_srv[i] = k;
  }
  size_t off = 0;
  for (int g = 0; g < state->global_entry_count; g++) {
    const config_entry_t *e = &state->global_entries[g];
    pool_srv_t s;
    if (e->key[0] != 'S' || e->key[1] || !pool_srv_parse(e->value, &s) || s.deleted) continue;
    /* up = the bots on every real server this entry leads to now (a second
     * name for one server shares its load), plus its own bots whose server
     * is not known yet; connecting = its own bots still dialing. */
    int up = 0, conn = 0;
    memset(mark, 0, sizeof(mark[0]) * (size_t)(ns > 0 ? ns : 1));
    for (int i = 0; i < n; i++) {
      if (strcmp(v[i].entry, s.uuid) != 0) continue;
      if (!v[i].up) conn++;
      else if (bot_srv[i] < 0) up++;
      else mark[bot_srv[i]] = true;
    }
    for (int k = 0; k < ns; k++)
      if (mark[k]) up += srv_up[k];
    int w = snprintf(out + off, cap - off, "E|%s|%d|%d\n", s.uuid, up, conn);
    if (w < 0 || (size_t)w >= cap - off) return -1;
    off += (size_t)w;
  }
  return (int)off;
}

void hub_pool_view_tick(hub_state_t *state, time_t now) {
  static time_t last_sent;
  static unsigned char last_hash[32];
  static char text[(MAX_POOL_SERVERS + MAX_POOL_TOMBS) * POOL_VIEW_LINE_MAX + 16];
  if (now - last_sent < POOL_VIEW_GAP) return;
  int len = view_build(state, text, sizeof(text));
  if (len < 0) return;
  unsigned char h[32];
  EVP_Digest(text, (size_t)len, h, NULL, EVP_sha256(), NULL);
  bool changed = memcmp(h, last_hash, sizeof(h)) != 0;
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type != CLIENT_BOT || !c->authenticated || c->retiring ||
        !hub_bot_version_takes_pool(c->bot_version))
      continue;
    /* everyone on a change; a bot that has not had this view yet anyway */
    if (!changed && c->pool_view_sent) continue;
    queued_msg_t *m = queued_msg_new(CMD_POOL_VIEW, LANE_DELTA, (const unsigned char *)text, len);
    if (m && peer_enqueue(c, m)) {
      c->pool_view_sent = true;
      g_hub_stats.pool_views++;
    }
  }
  memcpy(last_hash, h, sizeof(h));
  last_sent = now;
}

int hub_pool_view_text(hub_state_t *state, char *out, size_t cap) {
  return view_build(state, out, cap);
}

int hub_pool_idle_bots(const hub_state_t *state) {
  /* local bots, then roster rows of bots not already counted */
  int n = 0;
  static char seen[MAX_BOT_ROSTER + MAX_BOTS][64];
  int ns = 0;
  for (int i = 0; i < state->client_count; i++) {
    const hub_client_t *c = state->clients[i];
    if (c->type != CLIENT_BOT || !c->authenticated || c->retiring) continue;
    if (ns < (int)(sizeof(seen) / sizeof(seen[0]))) snprintf(seen[ns++], sizeof(seen[0]), "%s", c->id);
    n += strcmp(c->bot_irc_link, "idle") == 0;
  }
  for (int i = 0; i < state->roster_count; i++) {
    const bot_roster_t *r = &state->roster[i];
    bool dup = false;
    for (int k = 0; k < ns && !dup; k++) dup = strcmp(seen[k], r->bot_uuid) == 0;
    if (dup) continue;
    if (ns < (int)(sizeof(seen) / sizeof(seen[0]))) snprintf(seen[ns++], sizeof(seen[0]), "%s", r->bot_uuid);
    n += strcmp(r->irc_link, "idle") == 0;
  }
  return n;
}

/* The stored entry an admin names: a uuid, or host[:port] in POOL_DEFAULT_NET
 * (with no port, host:POOL_DEFAULT_PORT first, else the only entry of that
 * host). */
bool hub_pool_find(const hub_state_t *state, const char *what, pool_srv_t *out) {
  if (strlen(what) == POOL_UUID_LEN && hub_pool_srv_get(state, what, out)) return true;
  char host[POOL_HOST_MAX + 1];
  int port = 0;
  if (!pool_hostport_parse(what, host, sizeof(host), &port)) return false;
  char uuid[POOL_UUID_LEN + 1];
  if (pool_srv_uuid(POOL_DEFAULT_NET, host, port, uuid) && hub_pool_srv_get(state, uuid, out))
    return true;
  bool typed_port = what[0] == '[' ? strstr(what, "]:") != NULL : strchr(what, ':') != NULL;
  if (typed_port) return false;
  int hits = 0;
  pool_srv_t one;
  memset(&one, 0, sizeof(one));
  for (int i = 0; i < state->global_entry_count; i++) {
    const config_entry_t *e = &state->global_entries[i];
    pool_srv_t s;
    if (e->key[0] == 'S' && !e->key[1] && pool_srv_parse(e->value, &s) && !s.deleted &&
        strcasecmp(s.host, host) == 0) {
      one = s;
      hits++;
    }
  }
  if (hits == 1) *out = one;
  return hits == 1;
}

void hub_pool_net_get(const hub_state_t *state, const char *net_id, pool_net_t *out, time_t *ts) {
  net_get(state, net_id, out, ts);
}
