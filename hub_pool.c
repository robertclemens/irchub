/* hub_pool.c — the hub side of the IRC server pool (2.5.4).
 *
 * Plan: docs/plans/2026-10-29_server_pool_plan.md.  The N|/S| records live in
 * global_entries[] (hub_storage.c: hub_storage_put_record, validated by
 * pool_rec.c); this file holds what acts on them: the bots' NETWORK= reports
 * (CMD_SERVER_REPORT), learning the network's name and flagging an entry
 * wrongnet. */
#include "hub.h"

#include <openssl/evp.h>
#include <stdint.h>
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

/* Volatile: the NETWORK= a "linked" report last warned about, per entry, so
 * the warning is logged once per name (once more after a restart).  Not the
 * record's seen field: that holds a wrongnet entry's name only. */
typedef struct {
  char uuid[POOL_UUID_LEN + 1];
  char net[POOL_NET_NAME_MAX + 1];
} pool_linked_t;
static pool_linked_t g_linked[MAX_POOL_SERVERS];

/* true when this entry was already noted linked under this name; else notes it */
static bool linked_noted(const char *uuid, const char *network) {
  pool_linked_t *slot = NULL;
  for (int i = 0; i < MAX_POOL_SERVERS; i++) {
    if (strcmp(g_linked[i].uuid, uuid) == 0) {
      if (strcmp(g_linked[i].net, network) == 0) return true;
      slot = &g_linked[i];
      break;
    }
    if (!slot && !g_linked[i].uuid[0]) slot = &g_linked[i];
  }
  if (!slot) slot = &g_linked[0]; /* full: more entries than the pool holds */
  snprintf(slot->uuid, sizeof(slot->uuid), "%s", uuid);
  snprintf(slot->net, sizeof(slot->net), "%s", network);
  return false;
}

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
  out->pace_gap = hub_pool_default_pace();
  *ts = 0;
}

/* The pace gap of a network with no N| stored. */
int hub_pool_default_pace(void) {
#ifdef IRC_TEST_HOOKS
  /* A testnet has every bot on one host and one server: a 15 s gap per slot
   * would hold its tenth bot off IRC for two minutes. */
  const char *hook = getenv("IRCHUB_TEST_POOL_PACE");
  if (hook && hook[0] >= '0' && hook[0] <= '9' && atoi(hook) <= POOL_PACE_GAP_MAX)
    return atoi(hook);
#endif
  return POOL_PACE_GAP_DEFAULT;
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
  if (strcmp(kind, "linked") == 0) {
    /* NETWORK= is not ours, but a trusted bot on a verified server proved the
     * link (ircbot netproof_*): usable, and the admin is told how to make it
     * plain.  Noted once per name, never a strike. */
    if (!local || !network[0] || pool_net_matches(&net, network)) return;
    strikes_clear(uuid);
    if (!linked_noted(uuid, network))
      hub_log_warning("[POOL] Server %s (%s) says NETWORK=%s, but %s proved it linked to %s; "
                      "to accept that name: network set alias=%s%s%s\n",
                      s.host, uuid, network, who, net.name, net.aliases,
                      net.aliases[0] ? "," : "", network);
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
  /* 4th field (2.5.4): the server's NETWORK=, "-" while unknown; a bad one
   * reads as unknown, the rest of the report still counts. */
  const char *net = nf == 4 && strcmp(f[3], "-") != 0 && pool_net_name_ok(f[3]) ? f[3] : "";
  const char *ent = strcmp(f[1], "-") == 0 ? "" : f[1];
  bool changed = strcmp(client->bot_irc_entry, ent) != 0 || strcmp(client->bot_irc_link, f[2]) != 0 ||
                 strcmp(client->bot_irc_network, net) != 0;
  snprintf(client->bot_irc_entry, sizeof(client->bot_irc_entry), "%s", ent);
  snprintf(client->bot_irc_link, sizeof(client->bot_irc_link), "%s", f[2]);
  snprintf(client->bot_irc_network, sizeof(client->bot_irc_network), "%s", net);
  return changed;
}

/* One channel name as RFC 2812 has it: a # & + ! start, then no NUL, BEL,
 * CR, LF, space, ',' or ':' (and no other control byte here), < MAX_CHAN. */
static bool chan_name_ok(const char *s, size_t n) {
  if (n < 2 || n >= MAX_CHAN || !strchr("#&+!", s[0])) return false;
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c <= 0x20 || c == 0x7f || c == ',' || c == ':') return false;
  }
  return true;
}

/* CMD_BOT_CHAN_STATE / j|: every token valid or the list is refused whole. */
bool hub_chan_state_ok(const char *s) {
  size_t n = s ? strlen(s) : 0;
  if (!s || n >= CHAN_STATE_MAX) return false;
  const char *p = s;
  while (*p) {
    const char *end = strchr(p, ',');
    size_t tl = end ? (size_t)(end - p) : strlen(p);
    if (tl == 0) return false;
    if (p[0] == '~') { /* the tail: N more, last token only */
      if (end || tl < 2 || tl > 6) return false;
      for (size_t i = 1; i < tl; i++)
        if (p[i] < '0' || p[i] > '9') return false;
    } else if (p[0] == '-') {
      const char *colon = memchr(p, ':', tl);
      if (!colon || !chan_name_ok(p + 1, (size_t)(colon - p - 1))) return false;
      size_t wl = tl - (size_t)(colon - p) - 1;
      char why[16];
      if (wl == 0 || wl >= sizeof(why)) return false;
      memcpy(why, colon + 1, wl);
      why[wl] = '\0';
      bool known = false;
      for (const char *w = CHAN_STATE_WHYS; *w && !known;) {
        size_t l = strcspn(w, " ");
        known = l == wl && memcmp(w, why, wl) == 0;
        w += l + (w[l] == ' ');
      }
      if (!known) return false;
    } else {
      size_t skip = (p[0] == '@' || p[0] == '%') ? 1 : 0;
      /* '+' is voice only when a channel name follows; "+chan" alone is a
       * +channel the bot is in */
      if (!skip && p[0] == '+' && tl > 2 && strchr("#&+!", p[1])) skip = 1;
      if (!chan_name_ok(p + skip, tl - skip)) return false;
    }
    p += tl + (end ? 1 : 0);
    if (end && !*p) return false; /* a trailing comma */
  }
  return true;
}

bool hub_bot_chan_state(hub_state_t *state, hub_client_t *client, const char *payload) {
  (void)state;
  if (client->type != CLIENT_BOT || !client->authenticated || !hub_chan_state_ok(payload))
    return false;
  if (strcmp(client->bot_chan_state, payload) == 0) return false;
  snprintf(client->bot_chan_state, sizeof(client->bot_chan_state), "%s", payload);
  return true;
}

/* ---- the load view: who is on which entry (console server list) ------- */

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

/* ---- server order (plan 2026-11-24_server_order_plan.md) ----------------
 *
 * Every hub computes every bot's server order from replicated config only:
 * the usable S| entries of POOL_DEFAULT_NET (weight, max), the active bots
 * and the host of each bot's published hostmask (its origin: what the IRC
 * server sees), and the network's pace gap.  The same input gives the same
 * orders on every hub, so no hub asks another anything.
 *
 *  rank   weighted rendezvous: a server's score for a bot is the highest of
 *         its `weight` hashes H(bot|server#k) (k = 0 is H(bot|server)), so
 *         a server is a bot's best with odds in proportion to its weight.
 *  first  bots in uuid order take their best server that no earlier bot of
 *         the same origin took first and that is under its share
 *         (ceil(bots * w / W), capped by max); a sibling-free server beats
 *         one under its share.
 *  rest   position by position: the best server not yet in the order that
 *         no earlier sibling holds at that position, so siblings that lose
 *         their servers together fall back to different ones.
 *  slot   siblings that share a first server take turns: slot k of m dials
 *         only at a second t with t % (m * pace_gap) == k * pace_gap (one
 *         host, one clock), so two never dial it closer than the gap.
 *
 * A bot dials in that order (ircbot pool.c); a new order never moves a
 * connected bot, it applies at its next connect. */

#define ORDER_DEBOUNCE 2 /* s an input must hold still before a recompute */

typedef struct {
  char uuid[POOL_UUID_LEN + 1];
  int weight, max;
} ord_srv_t;

typedef struct {
  char uuid[64];
  char origin[MAX_MASK_LEN];
  int first;                      /* index into the servers                 */
  int n;
  unsigned char pos[MAX_POOL_SERVERS];
  uint64_t score[MAX_POOL_SERVERS];
} ord_bot_t;

typedef struct {
  char uuid[64];
  char line[POOL_R_LINE_MAX];
} ord_out_t;

static ord_out_t g_orders[MAX_BOTS];
static int g_order_count;
static uint64_t g_order_input;
static time_t g_order_input_at;
static bool g_order_dirty = true;

static uint64_t fnv64(uint64_t h, const char *s) {
  for (; *s; s++) {
    h ^= (unsigned char)*s;
    h *= 1099511628211ULL;
  }
  return h;
}

/* The bot's rendezvous hash of one (server, k) - the first 8 bytes of
 * SHA-256("<bot>|<server>") for k = 0, of "<bot>|<server>#<k>" above.  The
 * same input the bot's own hrw() used for its view-less order. */
static uint64_t ord_hash(const char *bot, const char *srv, int k) {
  char in[160];
  int n = k ? snprintf(in, sizeof(in), "%s|%s#%d", bot, srv, k)
            : snprintf(in, sizeof(in), "%s|%s", bot, srv);
  unsigned char h[EVP_MAX_MD_SIZE];
  unsigned int hl = 0;
  if (n < 0 || (size_t)n >= sizeof(in) || !EVP_Digest(in, (size_t)n, h, &hl, EVP_sha256(), NULL) ||
      hl < 8)
    return 0;
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) v = (v << 8) | h[i];
  return v;
}

/* The host of a "nick!ident@host" mask, lower-cased; "" without one. */
static void ord_origin(const char *mask, char *out, size_t cap) {
  out[0] = '\0';
  const char *at = mask ? strrchr(mask, '@') : NULL;
  if (!at || !at[1]) return;
  size_t n = 0;
  for (const char *p = at + 1; *p && n + 1 < cap; p++)
    out[n++] = (*p >= 'A' && *p <= 'Z') ? (char)(*p - 'A' + 'a') : *p;
  out[n] = '\0';
}

static int ord_srv_cmp(const void *a, const void *b) {
  return strcmp(((const ord_srv_t *)a)->uuid, ((const ord_srv_t *)b)->uuid);
}
static int ord_bot_cmp(const void *a, const void *b) {
  return strcmp(((const ord_bot_t *)a)->uuid, ((const ord_bot_t *)b)->uuid);
}

/* The inputs, sorted; their digest.  Returns the bot count. */
static int ord_inputs(const hub_state_t *state, ord_srv_t *srv, int *nsrv, ord_bot_t *bots,
                      int *gap, uint64_t *digest) {
  int ns = 0, nb = 0;
  for (int i = 0; i < state->global_entry_count && ns < MAX_POOL_SERVERS; i++) {
    const config_entry_t *e = &state->global_entries[i];
    pool_srv_t s;
    if (e->key[0] != 'S' || e->key[1] || !pool_srv_parse(e->value, &s) || s.deleted ||
        s.state != POOL_OK || strcmp(s.net_id, POOL_DEFAULT_NET) != 0)
      continue;
    memcpy(srv[ns].uuid, s.uuid, sizeof(srv[ns].uuid));
    srv[ns].weight = s.weight > 0 ? s.weight : 1;
    srv[ns].max = s.max;
    ns++;
  }
  qsort(srv, (size_t)ns, sizeof(srv[0]), ord_srv_cmp);
  for (int i = 0; i < state->bot_count && nb < MAX_BOTS; i++) {
    const bot_config_t *b = &state->bots[i];
    if (!b->is_active || strlen(b->uuid) != POOL_UUID_LEN) continue;
    memset(&bots[nb], 0, sizeof(bots[nb]));
    snprintf(bots[nb].uuid, sizeof(bots[nb].uuid), "%s", b->uuid);
    for (int j = 0; j < b->entry_count; j++)
      if (strcmp(b->entries[j].key, "h") == 0)
        ord_origin(b->entries[j].value, bots[nb].origin, sizeof(bots[nb].origin));
    nb++;
  }
  qsort(bots, (size_t)nb, sizeof(bots[0]), ord_bot_cmp);
  pool_net_t net;
  time_t ts;
  net_get(state, POOL_DEFAULT_NET, &net, &ts);
  *gap = net.pace_gap;
  uint64_t h = 14695981039346656037ULL;
  char num[48];
  snprintf(num, sizeof(num), "g%d\n", *gap);
  h = fnv64(h, num);
  for (int i = 0; i < ns; i++) {
    snprintf(num, sizeof(num), "|%d|%d\n", srv[i].weight, srv[i].max);
    h = fnv64(fnv64(h, srv[i].uuid), num);
  }
  for (int i = 0; i < nb; i++) h = fnv64(fnv64(fnv64(h, bots[i].uuid), "|"), bots[i].origin);
  *nsrv = ns;
  *digest = h;
  return nb;
}

/* Two bots of one origin.  A bot with no published mask is its own. */
static bool ord_siblings(const ord_bot_t *a, const ord_bot_t *b) {
  return a->origin[0] && strcmp(a->origin, b->origin) == 0;
}

static void ord_compute(const ord_srv_t *srv, int ns, ord_bot_t *bots, int nb) {
  /* rank: each bot's servers by score, best first (ties: server uuid). */
  for (int b = 0; b < nb; b++) {
    uint64_t sc[MAX_POOL_SERVERS];
    for (int s = 0; s < ns; s++) {
      uint64_t best = 0;
      for (int k = 0; k < srv[s].weight; k++) {
        uint64_t v = ord_hash(bots[b].uuid, srv[s].uuid, k);
        if (v > best) best = v;
      }
      sc[s] = best;
    }
    /* rank[] = server indexes by score; insertion sort, ns <= 64 */
    int rank[MAX_POOL_SERVERS];
    for (int s = 0; s < ns; s++) {
      int j = s;
      while (j > 0 && sc[rank[j - 1]] < sc[s]) {
        rank[j] = rank[j - 1];
        j--;
      }
      rank[j] = s; /* equal scores keep uuid order: srv[] is sorted */
    }
    for (int s = 0; s < ns; s++) {
      bots[b].pos[s] = (unsigned char)rank[s];
      bots[b].score[s] = sc[rank[s]];
    }
    bots[b].n = 0;
  }
  long long wsum = 0;
  for (int s = 0; s < ns; s++) wsum += srv[s].weight;
  int load[MAX_POOL_SERVERS] = {0}, cap[MAX_POOL_SERVERS];
  for (int s = 0; s < ns; s++) {
    /* the exact share ceil(nb * w / W), at least 1: a new order moves no
     * connected bot, so a tight bound costs nothing */
    long long c = wsum > 0 ? ((long long)nb * srv[s].weight + wsum - 1) / wsum : nb;
    if (c < 1) c = 1;
    if (srv[s].max > 0 && c > srv[s].max) c = srv[s].max;
    cap[s] = (int)c;
  }
  /* first: rank order, preferring (no sibling, under cap) > (no sibling) >
   * (under cap) > best. */
  for (int b = 0; b < nb; b++) {
    int pick[4] = {-1, -1, -1, -1};
    for (int r = 0; r < ns; r++) {
      int s = bots[b].pos[r];
      bool sib = false;
      for (int o = 0; o < b && !sib; o++)
        sib = ord_siblings(&bots[o], &bots[b]) && bots[o].first == s;
      bool under = load[s] < cap[s];
      int cls = !sib && under ? 0 : !sib ? 1 : under ? 2 : 3;
      if (pick[cls] < 0) pick[cls] = s;
    }
    int f = pick[0] >= 0 ? pick[0] : pick[1] >= 0 ? pick[1] : pick[2] >= 0 ? pick[2] : pick[3];
    bots[b].first = f;
    load[f]++;
  }
  /* the order: first, then position by position */
  for (int b = 0; b < nb; b++) {
    unsigned char out[MAX_POOL_SERVERS];
    bool used[MAX_POOL_SERVERS] = {false};
    out[0] = (unsigned char)bots[b].first;
    used[bots[b].first] = true;
    for (int p = 1; p < ns; p++) {
      /* free of every earlier sibling at p > free of the siblings that share
       * this bot's order so far (they lose their servers together) > any */
      int take = -1, mid = -1, any = -1;
      for (int r = 0; r < ns && take < 0; r++) {
        int s = bots[b].pos[r];
        if (used[s]) continue;
        if (any < 0) any = s;
        bool held = false, close = false;
        for (int o = 0; o < b; o++) {
          if (!ord_siblings(&bots[o], &bots[b]) || bots[o].n <= p || bots[o].pos[p] != s) continue;
          held = true;
          if (memcmp(bots[o].pos, out, (size_t)p) == 0) close = true;
        }
        if (!held) take = s;
        else if (!close && mid < 0) mid = s;
      }
      if (take < 0) take = mid >= 0 ? mid : any;
      out[p] = (unsigned char)take;
      used[take] = true;
    }
    /* pos[] is reused as the final order (earlier bots' finals are read
     * above through n > p) */
    memcpy(bots[b].pos, out, (size_t)ns);
    bots[b].n = ns;
  }
}

/* Recompute when the inputs changed and held still; true when any order
 * changed (the caller pushes configs). */
static bool ord_refresh(hub_state_t *state, time_t now) {
  static ord_srv_t srv[MAX_POOL_SERVERS];
  static ord_bot_t bots[MAX_BOTS];
  int ns = 0, gap = 0;
  uint64_t digest = 0;
  int nb = ord_inputs(state, srv, &ns, bots, &gap, &digest);
  if (digest != g_order_input) {
    g_order_input = digest;
    g_order_input_at = now;
    g_order_dirty = true;
    return false;
  }
  if (!g_order_dirty || now - g_order_input_at < ORDER_DEBOUNCE) return false;
  g_order_dirty = false;
  bool changed = false;
  static ord_out_t next[MAX_BOTS];
  int nn = 0;
  if (ns > 0) {
    ord_compute(srv, ns, bots, nb);
    for (int b = 0; b < nb; b++) {
      static pool_order_t o;
      memset(&o, 0, sizeof(o));
      o.gap = gap;
      int slot = 0, slots = 0;
      for (int x = 0; x < nb; x++) {
        bool same = x == b || (ord_siblings(&bots[x], &bots[b]) && bots[x].pos[0] == bots[b].pos[0]);
        slots += same;
        slot += same && x < b;
      }
      o.slot = slot;
      o.slots = slots > POOL_ORDER_SLOTS_MAX ? POOL_ORDER_SLOTS_MAX : slots;
      if (o.slot >= o.slots) o.slot = o.slots - 1;
      o.n = bots[b].n > POOL_ORDER_MAX ? POOL_ORDER_MAX : bots[b].n;
      for (int p = 0; p < o.n; p++)
        memcpy(o.ids[p], srv[bots[b].pos[p]].uuid, sizeof(o.ids[p]));
      memcpy(next[nn].uuid, bots[b].uuid, sizeof(next[nn].uuid)); /* both [64] */
      if (pool_order_format(&o, next[nn].line, sizeof(next[nn].line)) < 0) continue;
      nn++;
    }
  }
  /* changed = a bot's line differs (or appeared/went) */
  if (nn != g_order_count) changed = true;
  for (int i = 0; i < nn && !changed; i++)
    changed = strcmp(next[i].uuid, g_orders[i].uuid) != 0 ||
              strcmp(next[i].line, g_orders[i].line) != 0;
  if (changed) {
    memcpy(g_orders, next, sizeof(next[0]) * (size_t)nn);
    g_order_count = nn;
    g_hub_stats.pool_orders++;
    hub_log_debug("[POOL] Server orders recomputed: %d bot%s over %d server%s\n", nn,
                  nn == 1 ? "" : "s", ns, ns == 1 ? "" : "s");
  }
  return changed;
}

void hub_pool_order_tick(hub_state_t *state, time_t now) {
  static time_t last;
  if (now == last) return;
  last = now;
  if (ord_refresh(state, now)) state->bot_config_pending = true;
}

/* A bot's order as computed: its first server and its slot of slots.  False
 * when it has none. */
bool hub_pool_order_first(const char *bot_uuid, char *first, size_t cap, int *slot, int *slots) {
  for (int i = 0; i < g_order_count; i++) {
    if (strcmp(g_orders[i].uuid, bot_uuid) != 0) continue;
    static pool_order_t o;
    if (!pool_order_parse(g_orders[i].line, &o)) return false;
    snprintf(first, cap, "%s", o.ids[0]);
    if (slot) *slot = o.slot;
    if (slots) *slots = o.slots;
    return true;
  }
  return false;
}

/* Where a pool entry sits in a bot's computed order: *place 1-based, *of
 * the order's length.  False when the bot has no order or the entry is not
 * in it (bot show: "1st of 3 in its order"). */
bool hub_pool_order_place(const char *bot_uuid, const char *entry, int *place, int *of) {
  if (!entry || !entry[0]) return false;
  for (int i = 0; i < g_order_count; i++) {
    if (strcmp(g_orders[i].uuid, bot_uuid) != 0) continue;
    static pool_order_t o;
    if (!pool_order_parse(g_orders[i].line, &o)) return false;
    for (int k = 0; k < o.n; k++)
      if (strcmp(o.ids[k], entry) == 0) {
        *place = k + 1;
        *of = o.n;
        return true;
      }
    return false;
  }
  return false;
}

/* How many bots have this server first. */
int hub_pool_order_first_count(const char *srv_uuid) {
  int n = 0;
  for (int i = 0; i < g_order_count; i++) {
    /* "<gen>|<slot>|<slots>|<gap>|<first>,..." */
    const char *p = g_orders[i].line;
    for (int bars = 0; *p && bars < 4; p++) bars += *p == '|';
    n += strncmp(p, srv_uuid, POOL_UUID_LEN) == 0;
  }
  return n;
}

/* A bot's IRC link as this hub knows it (its own bot, else the roster): the
 * link word ("" = unknown) and the entry it is on. */
const char *hub_pool_bot_link(const hub_state_t *state, const char *bot_uuid, char *entry,
                              size_t cap) {
  entry[0] = '\0';
  for (int i = 0; i < state->client_count; i++) {
    const hub_client_t *c = state->clients[i];
    if (c->type == CLIENT_BOT && c->authenticated && !c->retiring && strcmp(c->id, bot_uuid) == 0) {
      snprintf(entry, cap, "%s", c->bot_irc_entry);
      return c->bot_irc_link;
    }
  }
  const char *word = "";
  time_t at = 0;
  for (int i = 0; i < state->roster_count; i++) {
    const bot_roster_t *r = &state->roster[i];
    if (strcmp(r->bot_uuid, bot_uuid) != 0 || r->reported_at < at) continue;
    at = r->reported_at;
    snprintf(entry, cap, "%s", r->irc_entry);
    word = r->irc_link;
  }
  return word;
}

/* The bot's origin as the order uses it (the host of its h| mask). */
void hub_pool_bot_origin(const hub_state_t *state, const char *bot_uuid, char *out, size_t cap) {
  out[0] = '\0';
  for (int i = 0; i < state->bot_count; i++) {
    const bot_config_t *b = &state->bots[i];
    if (strcmp(b->uuid, bot_uuid) != 0) continue;
    for (int j = 0; j < b->entry_count; j++)
      if (strcmp(b->entries[j].key, "h") == 0) ord_origin(b->entries[j].value, out, cap);
    return;
  }
}

/* The bots with an order, in uuid order (for the console and rebalance). */
int hub_pool_order_bots(char (*uuids)[64], int max) {
  int n = 0;
  for (int i = 0; i < g_order_count && n < max; i++)
    memcpy(uuids[n++], g_orders[i].uuid, sizeof(uuids[0]));
  return n;
}

const char *hub_pool_order_line(const hub_state_t *state, const char *bot_uuid) {
  (void)state;
  for (int i = 0; i < g_order_count; i++)
    if (strcmp(g_orders[i].uuid, bot_uuid) == 0) return g_orders[i].line;
  return NULL;
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
