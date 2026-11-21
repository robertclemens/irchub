/* hub_presence2.c - presence v2, phases 1-2: one versioned record per hub.
 *
 * Plan: docs/plans/2026-11-14_presence_v2_plan.md (§9 phase 1, §10 phase 2).
 * Reference state machine, simulator and differential fuzz:
 * ~/ircbot-testnet/proto/presence2 (SPEC.md).  The Rust hub
 * (irchub.rs/src/presence2.rs) speaks the same frames byte for byte.
 *
 * Each hub publishes {origin, epoch, seq, caps, links, bots}.  epoch is a boot
 * counter kept in P2_EPOCH_FILE, so a clock that steps or runs fast can never
 * make a restart look old.  Each change to it is one D frame (b+ b- l+ l-),
 * flooded at once with a per-origin seen window and split horizon; a seq gap
 * makes the receiver pull the record (R -> S), and a pulled record is passed
 * on, so a repair spreads in one go.  Each bot and each peer link is damped on
 * its own (P2_FLAP_*), so one flapping entity never slows anyone else's news;
 * past a token bucket (P2_BUCKET_*) changes go silent and one snapshot per
 * P2_STORM_GAP_MS carries them.  The whole record is flooded again every
 * P2_FULL_EVERY_MS at a new seq, and every link carries H|count|fnv64 every
 * P2_DIGEST_MS: on a mismatch the two sides swap full digests and pull.
 *
 * Reachability is a breadth-first walk over the records; a link counts only
 * when both ends list it.  Phase 1 runs beside the CMD_BOT_ROSTER rounds and
 * only ever shortens how long the roster shows something that is gone:
 *   - a reachable hub's record is authoritative for which bots it has: a bot
 *     it no longer lists is dropped at once (hub_roster_p2_reconcile);
 *   - a hub unreachable for P2_GRACE_MS loses its roster entries and its
 *     mesh-map entry (hub_roster_p2_drop_hub), the tree hides it at once.
 * Both run only on change: a record accepted, a roster entry of that hub
 * upserted (hub_p2_roster_touched) or the hub turning reachable again.
 * Both need every linked peer to speak v2 and every mesh-map hub to have a
 * record ("ready"): behind a hub that never publishes nothing can be walked,
 * and today's view stays in charge. */
#include "hub.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int64_t p2_now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ---------- validation ---------- */

static bool p2_id_ok(const char *s) {
  size_t n = 0;
  for (; s[n]; n++) {
    char c = s[n];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || c == '-')) return false;
  }
  return n >= 1 && n <= P2_ID_MAX;
}

/* 1..19 decimal digits, <= INT64_MAX. */
static bool p2_num_ok(const char *s, uint64_t *out) {
  size_t n = strlen(s);
  if (n < 1 || n > 19) return false;
  uint64_t v = 0;
  for (size_t i = 0; i < n; i++) {
    if (s[i] < '0' || s[i] > '9') return false;
    v = v * 10 + (uint64_t)(s[i] - '0');
  }
  if (v > (uint64_t)INT64_MAX) return false;
  *out = v;
  return true;
}

/* Split in place on sep; -1 when more than max fields. */
static int p2_split(char *s, char sep, char **f, int max) {
  int n = 0;
  f[n++] = s;
  for (char *c = s; *c; c++) {
    if (*c != sep) continue;
    if (n >= max) return -1;
    *c = '\0';
    f[n++] = c + 1;
  }
  return n;
}

static bool p2_es_sane(uint64_t e, uint64_t s) { return e <= P2_EPOCH_MAX && s <= P2_SEQ_MAX; }

/* ---------- epoch file ---------- */

static uint64_t p2_epoch_read(void) {
  FILE *f = fopen(P2_EPOCH_FILE, "r");
  if (!f) return 0;
  char buf[32] = "";
  bool got = fgets(buf, sizeof(buf), f) != NULL;
  fclose(f);
  buf[strcspn(buf, "\r\n")] = '\0';
  uint64_t v = 0;
  if (!got || !p2_num_ok(buf, &v) || v >= P2_EPOCH_MAX) {
    hub_log_warning("[PRESENCE] %s unreadable: boot counter restarts (peers heal it)\n",
                    P2_EPOCH_FILE);
    return 0;
  }
  return v;
}

static void p2_epoch_write(uint64_t epoch) {
  char tmp[64], buf[32];
  snprintf(tmp, sizeof(tmp), "%s.tmp", P2_EPOCH_FILE);
  int n = snprintf(buf, sizeof(buf), "%" PRIu64 "\n", epoch);
  int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  bool ok = fd >= 0;
  if (ok) {
    ok = write(fd, buf, (size_t)n) == (ssize_t)n && fsync(fd) == 0;
    ok = close(fd) == 0 && ok;
  }
  if (ok) ok = rename(tmp, P2_EPOCH_FILE) == 0;
  if (!ok) {
    hub_log_error("[PRESENCE] cannot write %s: %s\n", P2_EPOCH_FILE, strerror(errno));
    unlink(tmp);
  }
}

/* ---------- records ---------- */

static p2_rec_t *p2_rec_find(p2_state_t *p, const char *o) {
  for (int i = 0; i < p->nrecs; i++)
    if (strcmp(p->recs[i].origin, o) == 0) return &p->recs[i];
  return NULL;
}

static const p2_rec_t *p2_rec_find_c(const p2_state_t *p, const char *o) {
  for (int i = 0; i < p->nrecs; i++)
    if (strcmp(p->recs[i].origin, o) == 0) return &p->recs[i];
  return NULL;
}

/* When an unreachable record went (gone_ms); one never reached has none and
 * counts as the newest, so it is the last to be evicted. */
static int64_t p2_gone_key(const p2_rec_t *r) { return r->gone_ms ? r->gone_ms : INT64_MAX; }

/* Find or create.  Full: reuse the record unreachable the longest, never a
 * reachable one. */
static p2_rec_t *p2_rec_get(p2_state_t *p, const char *o) {
  p2_rec_t *r = p2_rec_find(p, o);
  if (r) return r;
  if (p->nrecs < MAX_MESH_HUBS) {
    r = &p->recs[p->nrecs++];
  } else {
    for (int i = 0; i < p->nrecs; i++)
      if (!p->recs[i].reach && (!r || p2_gone_key(&p->recs[i]) < p2_gone_key(r)))
        r = &p->recs[i];
    if (!r) return NULL;
    free(r->bots);
  }
  memset(r, 0, sizeof(*r));
  snprintf(r->origin, sizeof(r->origin), "%s", o);
  return r;
}

static int p2_link_idx(const p2_rec_t *r, const char *id) {
  for (int i = 0; i < r->nlinks; i++)
    if (strcmp(r->links[i], id) == 0) return i;
  return -1;
}

static int p2_bot_idx(const p2_bot_t *b, int n, const char *id) {
  for (int i = 0; i < n; i++)
    if (strcmp(b[i].id, id) == 0) return i;
  return -1;
}

/* S|origin|epoch|seq|ttl|caps|links|bots */
static int p2_snap_frame(const p2_rec_t *r, int ttl, char *out, size_t cap) {
  size_t o = 0;
  int w = snprintf(out, cap, "S|%s|%" PRIu64 "|%" PRIu64 "|%d|%s|", r->origin, r->epoch, r->seq,
                   ttl, r->caps[0] ? r->caps : "-");
  if (w < 0 || (size_t)w >= cap) return -1;
  o = (size_t)w;
  if (r->nlinks == 0) {
    if (o + 1 >= cap) return -1;
    out[o++] = '-';
  }
  for (int i = 0; i < r->nlinks; i++) {
    w = snprintf(out + o, cap - o, "%s%s", i ? "," : "", r->links[i]);
    if (w < 0 || (size_t)w >= cap - o) return -1;
    o += (size_t)w;
  }
  if (o + 1 >= cap) return -1;
  out[o++] = '|';
  if (r->nbots == 0) {
    if (o + 1 >= cap) return -1;
    out[o++] = '-';
  }
  for (int i = 0; i < r->nbots; i++) {
    w = snprintf(out + o, cap - o, "%s%s:%lld", i ? "," : "", r->bots[i].id, r->bots[i].since);
    if (w < 0 || (size_t)w >= cap - o) return -1;
    o += (size_t)w;
  }
  out[o] = '\0';
  return (int)o;
}

/* ---------- peers ---------- */

/* The configured peer uuid behind an authenticated hub connection, or "". */
static const char *p2_peer_uuid(const hub_state_t *state, const hub_client_t *c) {
  if (!c || c->type != CLIENT_HUB || !c->authenticated || !c->peer_heard || c->fd < 0)
    return "";
  for (int i = 0; i < state->peer_count; i++)
    if (state->peers[i].connected && state->peers[i].fd == c->fd) return state->peers[i].uuid;
  return "";
}

/* Linked peers in configuration order, one connection each. */
static int p2_linked(hub_state_t *state, hub_client_t **out, const char **ids, int max) {
  int n = 0;
  for (int p = 0; p < state->peer_count && n < max; p++) {
    const hub_peer_config_t *pc = &state->peers[p];
    if (!pc->connected || pc->fd <= 0 || !p2_id_ok(pc->uuid)) continue;
    bool dup = false;
    for (int k = 0; k < n; k++)
      if (strcmp(ids[k], pc->uuid) == 0) dup = true;
    if (dup) continue;
    for (int c = 0; c < state->client_count; c++) {
      hub_client_t *cl = state->clients[c];
      if (cl->type == CLIENT_HUB && cl->authenticated && cl->peer_heard && cl->fd == pc->fd) {
        out[n] = cl;
        ids[n] = pc->uuid;
        n++;
        break;
      }
    }
  }
  return n;
}

static void p2_tx(hub_state_t *state, hub_client_t *c, const char *frame) {
  queued_msg_t *m = queued_msg_new(CMD_PRESENCE2, LANE_DELTA, (const unsigned char *)frame,
                                   (int)strlen(frame));
  if (!m) return;
  if (peer_enqueue(c, m)) state->p2->c_tx++;
}

/* To every linked peer but the sender, the origin and the hubs the origin
 * lists as linked (they had it first hand). */
static void p2_relay(hub_state_t *state, const char *frame, const hub_client_t *from,
                     const p2_rec_t *r) {
  hub_client_t *cl[MAX_PEERS];
  const char *ids[MAX_PEERS];
  int n = p2_linked(state, cl, ids, MAX_PEERS);
  for (int i = 0; i < n; i++) {
    if (cl[i] == from || strcmp(ids[i], r->origin) == 0 || p2_link_idx(r, ids[i]) >= 0) continue;
    p2_tx(state, cl[i], frame);
    state->p2->c_relays++;
  }
}

static void p2_flood_self(hub_state_t *state) {
  p2_state_t *p = state->p2;
  char *buf = malloc(P2_MAX_FRAME);
  if (!buf) return;
  if (p2_snap_frame(&p->self, P2_TTL_HOPS, buf, P2_MAX_FRAME) >= 0) {
    hub_client_t *cl[MAX_PEERS];
    const char *ids[MAX_PEERS];
    int n = p2_linked(state, cl, ids, MAX_PEERS);
    for (int i = 0; i < n; i++) p2_tx(state, cl[i], buf);
  }
  free(buf);
  p->dirty = false;
  p->last_flood_ms = p2_now_ms();
}

static void p2_send_digest(hub_state_t *state, hub_client_t *c, char kind) {
  p2_state_t *p = state->p2;
  char *buf = malloc(P2_MAX_FRAME);
  if (!buf) return;
  size_t o = 0;
  int w = snprintf(buf, P2_MAX_FRAME, "%c|%s:%" PRIu64 ":%" PRIu64, kind, p->self.origin,
                   p->self.epoch, p->self.seq);
  bool ok = w > 0 && w < P2_MAX_FRAME;
  if (ok) o = (size_t)w;
  for (int i = 0; ok && i < p->nrecs; i++) {
    if (p->recs[i].epoch == 0) continue;
    w = snprintf(buf + o, P2_MAX_FRAME - o, ",%s:%" PRIu64 ":%" PRIu64, p->recs[i].origin,
                 p->recs[i].epoch, p->recs[i].seq);
    ok = w > 0 && (size_t)w < P2_MAX_FRAME - o;
    if (ok) o += (size_t)w;
  }
  if (ok) p2_tx(state, c, buf);
  free(buf);
}

/* FNV-1a 64 over "origin:epoch:seq;" for us and every record with epoch > 0,
 * sorted by origin; *count = entries. */
static uint64_t p2_hash(const p2_state_t *p, int *count) {
  const p2_rec_t *v[MAX_MESH_HUBS + 1];
  int n = 0;
  v[n++] = &p->self;
  for (int i = 0; i < p->nrecs; i++)
    if (p->recs[i].epoch > 0) v[n++] = &p->recs[i];
  for (int i = 1; i < n; i++)
    for (int k = i; k > 0 && strcmp(v[k - 1]->origin, v[k]->origin) > 0; k--) {
      const p2_rec_t *t = v[k];
      v[k] = v[k - 1];
      v[k - 1] = t;
    }
  uint64_t h = 0xcbf29ce484222325ULL;
  for (int i = 0; i < n; i++) {
    char ent[P2_ID_MAX + 48];
    int w = snprintf(ent, sizeof(ent), "%s:%" PRIu64 ":%" PRIu64 ";", v[i]->origin, v[i]->epoch,
                     v[i]->seq);
    for (int k = 0; k < w && k < (int)sizeof(ent) - 1; k++) {
      h ^= (unsigned char)ent[k];
      h *= 0x100000001b3ULL;
    }
  }
  *count = n;
  return h;
}

static void p2_send_hash(hub_state_t *state, hub_client_t *c) {
  int n = 0;
  uint64_t h = p2_hash(state->p2, &n);
  char buf[48];
  snprintf(buf, sizeof(buf), "H|%d|%016" PRIx64, n, h);
  p2_tx(state, c, buf);
}

static void p2_pull(hub_state_t *state, p2_rec_t *r, hub_client_t *c) {
  int64_t now = p2_now_ms();
  if (now < r->pull_next_ms) return;
  r->pull_next_ms = now + P2_PULL_RETRY_MS;
  char buf[P2_ID_MAX + 8];
  snprintf(buf, sizeof(buf), "R|%s", r->origin);
  p2_tx(state, c, buf);
  state->p2->c_pulls++;
}

/* ---------- own record ---------- */

/* ---------- own record: entities, deltas, storm cap ---------- */

static p2_ent_t *p2_ent_get(p2_state_t *p, char kind, const char *id) {
  for (int i = 0; i < p->nents; i++)
    if (p->ents[i].kind == kind && strcmp(p->ents[i].id, id) == 0) return &p->ents[i];
  if (p->nents >= P2_MAX_ENTS) return NULL;
  p2_ent_t *e = &p->ents[p->nents++];
  memset(e, 0, sizeof(*e));
  e->kind = kind;
  size_t n = strnlen(id, sizeof(e->id) - 1); /* ids passed p2_id_ok: never cut */
  memcpy(e->id, id, n);
  e->id[n] = '\0';
  return e;
}

/* A bot or link of ours changed: count the flip; past P2_FLAP_FREE flips in
 * one window it is held 1, 2, 4 ... P2_HOLD_MAX_MS, and the hold publishes the
 * net change when it ends. */
static void p2_ent_event(p2_state_t *p, p2_ent_t *e, bool live, long long since, int64_t now) {
  if (now - e->window_ms >= P2_FLAP_WINDOW_MS) {
    e->flips = 0;
    e->window_ms = now;
  }
  e->flips++;
  e->live = live;
  e->since = since;
  if (e->flips > P2_FLAP_FREE) {
    int sh = e->flips - P2_FLAP_FREE - 1;
    if (sh > 15) sh = 15;
    int64_t hold = (int64_t)1000 << sh;
    e->hold_ms = now + (hold > P2_HOLD_MAX_MS ? P2_HOLD_MAX_MS : hold);
    p->c_held++;
  }
}

static bool p2_take_token(p2_state_t *p, int64_t now) {
  if (now > p->bucket_ms) {
    p->tokens_milli += (now - p->bucket_ms) * P2_BUCKET_RATE;
    if (p->tokens_milli > (int64_t)P2_BUCKET_BURST * 1000) p->tokens_milli = (int64_t)P2_BUCKET_BURST * 1000;
  }
  p->bucket_ms = now;
  if (p->tokens_milli < 1000) return false;
  p->tokens_milli -= 1000;
  return true;
}

/* One published change of ours: seq moves on, and a D goes to every linked
 * peer but `skip` while the bucket allows and no storm snapshot is pending;
 * otherwise the change stays silent and the next snapshot carries it. */
static void p2_publish(hub_state_t *state, const hub_client_t *skip, const char *op,
                       const char *id, long long since, int64_t now) {
  p2_state_t *p = state->p2;
  p->self.seq++;
  hub_client_t *cl[MAX_PEERS];
  const char *ids[MAX_PEERS];
  int n = p2_linked(state, cl, ids, MAX_PEERS);
  bool any = false;
  for (int i = 0; i < n; i++) any = any || cl[i] != skip;
  if (!any) return; /* nobody to tell: link-up sends the record */
  if (p->dirty || !p2_take_token(p, now)) {
    p->dirty = true;
    return;
  }
  char buf[P2_ID_MAX * 2 + 96];
  snprintf(buf, sizeof(buf), "D|%s|%" PRIu64 "|%" PRIu64 "|%d|%s|%s|%lld", p->self.origin,
           p->self.epoch, p->self.seq, P2_TTL_HOPS, op, id, since);
  for (int i = 0; i < n; i++)
    if (cl[i] != skip) p2_tx(state, cl[i], buf);
  p->c_deltas++;
}

/* Compare the live links and bots with our entities, then publish every
 * entity that is not held and differs from the record.  `skip`: a link
 * coming up gets the whole record instead. */
static void p2_refresh_self(hub_state_t *state, const hub_client_t *skip) {
  p2_state_t *p = state->p2;
  int64_t now = p2_now_ms();
  hub_client_t *cl[MAX_PEERS];
  const char *ids[MAX_PEERS];
  int nl = p2_linked(state, cl, ids, MAX_PEERS);
  if (nl > P2_MAX_LINKS) nl = P2_MAX_LINKS;
  p2_bot_t bots[P2_MAX_BOTS];
  int nb = 0;
  for (int i = 0; i < state->client_count && nb < P2_MAX_BOTS; i++) {
    const hub_client_t *c = state->clients[i];
    if (c->type != CLIENT_BOT || !c->authenticated || c->superseded || !p2_id_ok(c->id) ||
        p2_bot_idx(bots, nb, c->id) >= 0)
      continue;
    snprintf(bots[nb].id, sizeof(bots[nb].id), "%s", c->id);
    bots[nb].since = (long long)c->connected_at;
    nb++;
  }
  for (int i = 0; i < nl; i++) {
    p2_ent_t *e = p2_ent_get(p, 'l', ids[i]);
    if (e && !e->live) p2_ent_event(p, e, true, 0, now);
  }
  for (int i = 0; i < nb; i++) {
    p2_ent_t *e = p2_ent_get(p, 'b', bots[i].id);
    if (e && (!e->live || e->since != bots[i].since)) p2_ent_event(p, e, true, bots[i].since, now);
  }
  for (int i = 0; i < p->nents; i++) {
    p2_ent_t *e = &p->ents[i];
    if (!e->live) continue;
    bool there = false;
    if (e->kind == 'l')
      for (int k = 0; k < nl && !there; k++) there = strcmp(ids[k], e->id) == 0;
    else
      there = p2_bot_idx(bots, nb, e->id) >= 0;
    if (!there) p2_ent_event(p, e, false, 0, now);
  }
  for (int i = 0; i < p->nents; i++) {
    p2_ent_t *e = &p->ents[i];
    if (now < e->hold_ms) continue;
    if (e->kind == 'l') {
      int k = p2_link_idx(&p->self, e->id);
      if (e->live && k < 0 && p->self.nlinks < P2_MAX_LINKS) {
        snprintf(p->self.links[p->self.nlinks++], P2_ID_MAX + 1, "%s", e->id);
        p2_publish(state, skip, "l+", e->id, 0, now);
      } else if (!e->live && k >= 0) {
        memmove(p->self.links[k], p->self.links[k + 1],
                (size_t)(p->self.nlinks - k - 1) * sizeof(p->self.links[0]));
        p->self.nlinks--;
        p2_publish(state, skip, "l-", e->id, 0, now);
      }
      continue;
    }
    int k = p2_bot_idx(p->self.bots, p->self.nbots, e->id);
    if (e->live && (k < 0 || p->self.bots[k].since != e->since)) {
      if (k < 0) {
        if (p->self.nbots >= P2_MAX_BOTS) continue;
        p2_bot_t *nbuf = realloc(p->self.bots, (size_t)(p->self.nbots + 1) * sizeof(*nbuf));
        if (!nbuf) continue;
        p->self.bots = nbuf;
        k = p->self.nbots++;
        snprintf(p->self.bots[k].id, sizeof(p->self.bots[k].id), "%s", e->id);
      }
      p->self.bots[k].since = e->since;
      p2_publish(state, skip, "b+", e->id, e->since, now);
    } else if (!e->live && k >= 0) {
      memmove(&p->self.bots[k], &p->self.bots[k + 1],
              (size_t)(p->self.nbots - k - 1) * sizeof(p->self.bots[0]));
      p->self.nbots--;
      p2_publish(state, skip, "b-", e->id, 0, now);
    }
  }
  /* Forget entities that are gone, published and past their flap window. */
  for (int i = 0; i < p->nents;) {
    const p2_ent_t *e = &p->ents[i];
    bool listed = e->kind == 'l' ? p2_link_idx(&p->self, e->id) >= 0
                                 : p2_bot_idx(p->self.bots, p->self.nbots, e->id) >= 0;
    if (!e->live && !listed && now >= e->hold_ms && now - e->window_ms >= P2_FLAP_WINDOW_MS) {
      memmove(&p->ents[i], &p->ents[i + 1], (size_t)(p->nents - i - 1) * sizeof(p->ents[0]));
      p->nents--;
      continue;
    }
    i++;
  }
}

/* Someone claims a version of OUR record above ours (a lost epoch file, a bug,
 * a forged frame): jump above it and flood the truth.  Claims near the limits
 * are ignored, so a heal always stays well inside the sane range. */
static void p2_self_claim(hub_state_t *state, uint64_t e, uint64_t s) {
  p2_state_t *p = state->p2;
  if (e >= P2_EPOCH_MAX || s >= P2_SEQ_MAX / 2) return;
  if (e > p->self.epoch) {
    p->self.epoch = e + 1;
    p->self.seq = 0;
    p2_epoch_write(p->self.epoch);
    hub_log_warning("[PRESENCE] a peer holds our record at epoch %" PRIu64
                    ": boot counter moved to %" PRIu64 "\n", e, p->self.epoch);
  } else if (e == p->self.epoch && s > p->self.seq) {
    p->self.seq = s;
  } else {
    return;
  }
  p->self.seq++;
  p->dirty = true;
  p->c_heals++;
}

/* Unsigned records: a reachable hub moves its epoch by one per boot and its
 * seq by a few thousand at most between our hearing from it.  A relayed claim
 * far above that is a bug or a forgery that would freeze the origin at the
 * ceiling, so it is refused.  The origin on its own link, an unreachable
 * origin (it may have rebooted many times while cut off) and a first sighting
 * pass. */
static bool p2_jump_refused(hub_state_t *state, const hub_client_t *from, const p2_rec_t *r,
                            uint64_t e, uint64_t s) {
  if (strcmp(p2_peer_uuid(state, from), r->origin) == 0 || !r->reach || r->epoch == 0)
    return false;
  if (e > r->epoch + P2_EPOCH_JUMP || (e == r->epoch && s > r->seq + P2_SEQ_JUMP)) {
    state->p2->c_jumps++;
    return true;
  }
  return false;
}

/* ---------- frames ---------- */

static void p2_rx_snap(hub_state_t *state, hub_client_t *from, char **f) {
  p2_state_t *p = state->p2;
  uint64_t e, s, ttl;
  if (!p2_id_ok(f[1]) || !p2_num_ok(f[2], &e) || !p2_num_ok(f[3], &s) || !p2_num_ok(f[4], &ttl) ||
      ttl > P2_TTL_HOPS || !p2_es_sane(e, s) || e == 0 || strlen(f[5]) > P2_CAPS_MAX) {
    p->c_rx_bad++;
    return;
  }
  for (const char *c = f[5]; *c; c++)
    if (!((*c >= 'a' && *c <= 'z') || *c == ',' || *c == '-')) {
      p->c_rx_bad++;
      return;
    }
  char links[P2_MAX_LINKS][P2_ID_MAX + 1];
  int nl = 0;
  if (strcmp(f[6], "-") != 0) {
    char *l[P2_MAX_LINKS];
    int n = p2_split(f[6], ',', l, P2_MAX_LINKS);
    if (n < 0) {
      p->c_rx_bad++;
      return;
    }
    for (int i = 0; i < n; i++) {
      for (int k = 0; k < nl; k++)
        if (strcmp(links[k], l[i]) == 0) {
          p->c_rx_bad++;
          return;
        }
      if (!p2_id_ok(l[i])) {
        p->c_rx_bad++;
        return;
      }
      snprintf(links[nl++], P2_ID_MAX + 1, "%s", l[i]);
    }
  }
  p2_bot_t *bots = NULL;
  int nb = 0;
  if (strcmp(f[7], "-") != 0) {
    char *b[P2_MAX_BOTS];
    int n = p2_split(f[7], ',', b, P2_MAX_BOTS);
    if (n < 0 || !(bots = calloc((size_t)n, sizeof(*bots)))) {
      p->c_rx_bad++;
      return;
    }
    for (int i = 0; i < n; i++) {
      char *kv[2] = {NULL, NULL};
      uint64_t since;
      if (p2_split(b[i], ':', kv, 2) != 2 || !p2_id_ok(kv[0]) || !p2_num_ok(kv[1], &since) ||
          p2_bot_idx(bots, nb, kv[0]) >= 0) {
        free(bots);
        p->c_rx_bad++;
        return;
      }
      snprintf(bots[nb].id, sizeof(bots[nb].id), "%s", kv[0]);
      bots[nb++].since = (long long)since;
    }
  }
  if (strcmp(f[1], p->self.origin) == 0) {
    free(bots);
    p2_self_claim(state, e, s);
    return;
  }
  p2_rec_t *r = p2_rec_get(p, f[1]);
  if (!r || !(e > r->epoch || (e == r->epoch && s > r->seq)) ||
      p2_jump_refused(state, from, r, e, s)) {
    free(bots);
    return;
  }
  snprintf(r->caps, sizeof(r->caps), "%s", strcmp(f[5], "-") ? f[5] : "");
  r->epoch = e;
  r->seq = s;
  r->nlinks = nl;
  memcpy(r->links, links, sizeof(links));
  free(r->bots);
  r->bots = bots;
  r->nbots = nb;
  r->stamp = ++p->stamp_ctr;
  r->rdirty = true;
  /* A pulled (ttl 0) record is news to our other peers too: pass it on, so a
   * repair spreads at once instead of one exchange per hop. */
  uint64_t out_ttl = ttl == 0 ? P2_TTL_HOPS - 1 : ttl - 1;
  if (out_ttl > 0) {
    char *buf = malloc(P2_MAX_FRAME);
    if (buf && p2_snap_frame(r, (int)out_ttl, buf, P2_MAX_FRAME) >= 0) p2_relay(state, buf, from, r);
    free(buf);
  }
  /* Reconcile now if it is reachable (the walk next tick catches the rest). */
  if (r->reach) {
    r->rdirty = false;
    hub_roster_p2_reconcile(state, r);
  }
}

/* True when (e, s) is new in r's P2_SEEN_WINDOW-wide window. */
static bool p2_win_new(p2_rec_t *r, uint64_t e, uint64_t s) {
  if (e != r->win_epoch) {
    if (e < r->win_epoch) return false;
    r->win_epoch = e;
    r->win_top = s;
    r->win_mask = 1;
    return true;
  }
  if (s > r->win_top) {
    uint64_t d = s - r->win_top;
    r->win_mask = d >= P2_SEEN_WINDOW ? 0 : r->win_mask << d;
    r->win_mask |= 1;
    r->win_top = s;
    return true;
  }
  uint64_t d = r->win_top - s;
  if (d >= P2_SEEN_WINDOW || (r->win_mask & (1ULL << d))) return false;
  r->win_mask |= 1ULL << d;
  return true;
}

/* Apply one change; false when it cannot be (a list is full): pull instead.
 * Adding what is there or removing what is not leaves the record as the
 * origin has it. */
static bool p2_apply(p2_rec_t *r, const char *op, const char *id, long long since) {
  if (op[0] == 'l') {
    int k = p2_link_idx(r, id);
    if (op[1] == '+') {
      if (k >= 0) return true;
      if (r->nlinks >= P2_MAX_LINKS) return false;
      snprintf(r->links[r->nlinks++], P2_ID_MAX + 1, "%s", id);
    } else if (k >= 0) {
      memmove(r->links[k], r->links[k + 1], (size_t)(r->nlinks - k - 1) * sizeof(r->links[0]));
      r->nlinks--;
    }
    return true;
  }
  int k = p2_bot_idx(r->bots, r->nbots, id);
  if (op[1] == '+') {
    if (k < 0) {
      if (r->nbots >= P2_MAX_BOTS) return false;
      p2_bot_t *nbuf = realloc(r->bots, (size_t)(r->nbots + 1) * sizeof(*nbuf));
      if (!nbuf) return false;
      r->bots = nbuf;
      k = r->nbots++;
      snprintf(r->bots[k].id, sizeof(r->bots[k].id), "%s", id);
    }
    r->bots[k].since = since;
  } else if (k >= 0) {
    memmove(&r->bots[k], &r->bots[k + 1], (size_t)(r->nbots - k - 1) * sizeof(r->bots[0]));
    r->nbots--;
  }
  return true;
}

/* D|origin|epoch|seq|ttl|op|id|since */
static void p2_rx_delta(hub_state_t *state, hub_client_t *from, char **f) {
  p2_state_t *p = state->p2;
  uint64_t e, s, ttl, since;
  bool op_ok = (f[5][0] == 'b' || f[5][0] == 'l') && (f[5][1] == '+' || f[5][1] == '-') &&
               f[5][2] == '\0';
  if (!p2_id_ok(f[1]) || !p2_num_ok(f[2], &e) || !p2_num_ok(f[3], &s) || !p2_num_ok(f[4], &ttl) ||
      ttl < 1 || ttl > P2_TTL_HOPS || !p2_es_sane(e, s) || e == 0 || s == 0 || !op_ok ||
      !p2_id_ok(f[6]) || !p2_num_ok(f[7], &since) || (f[5][0] == 'l' && !strcmp(f[6], f[1]))) {
    p->c_rx_bad++;
    return;
  }
  if (strcmp(f[1], p->self.origin) == 0) {
    p2_self_claim(state, e, s);
    return;
  }
  p2_rec_t *r = p2_rec_get(p, f[1]);
  if (!r || p2_jump_refused(state, from, r, e, s) || !p2_win_new(r, e, s)) return;
  if (e < r->epoch || (e == r->epoch && s <= r->seq)) return; /* stale: a snapshot had it */
  bool applied = false;
  if (e == r->epoch && s == r->seq + 1) {
    applied = p2_apply(r, f[5], f[6], (long long)since);
  } else if (e > r->epoch && s == 1) {
    r->epoch = e; /* a restart: its first change, on an empty record */
    r->seq = 0;
    r->nlinks = 0;
    free(r->bots);
    r->bots = NULL;
    r->nbots = 0;
    applied = p2_apply(r, f[5], f[6], (long long)since);
  }
  if (applied) {
    r->seq = s;
    r->stamp = ++p->stamp_ctr;
    r->rdirty = true;
  } else {
    p2_pull(state, r, from); /* a gap (or a full list): fetch the record */
  }
  if (ttl > 1) {
    char buf[P2_ID_MAX * 2 + 96];
    snprintf(buf, sizeof(buf), "D|%s|%" PRIu64 "|%" PRIu64 "|%d|%s|%s|%" PRIu64, f[1], e, s,
             (int)ttl - 1, f[5], f[6], since);
    p2_relay(state, buf, from, r);
  }
  if (applied && r->reach) {
    r->rdirty = false;
    hub_roster_p2_reconcile(state, r);
  }
}

/* H|count|hash: a mismatch with ours asks for the sender's full digest. */
static void p2_rx_hash(hub_state_t *state, hub_client_t *from, char **f) {
  p2_state_t *p = state->p2;
  uint64_t cnt;
  size_t hl = strlen(f[2]);
  bool ok = p2_num_ok(f[1], &cnt) && cnt <= MAX_MESH_HUBS + 1 && hl == 16;
  for (size_t i = 0; ok && i < hl; i++)
    ok = (f[2][i] >= '0' && f[2][i] <= '9') || (f[2][i] >= 'a' && f[2][i] <= 'f');
  if (!ok) {
    p->c_rx_bad++;
    return;
  }
  int n = 0;
  char mine[17];
  snprintf(mine, sizeof(mine), "%016" PRIx64, p2_hash(p, &n));
  if ((uint64_t)n == cnt && strcmp(mine, f[2]) == 0) return;
  p->c_digest_miss++;
  p2_send_digest(state, from, 'W');
}

/* G / W: pull every origin the sender holds newer.  All entries are checked
 * before any is acted on: a bad digest does nothing. */
static bool p2_rx_digest(hub_state_t *state, hub_client_t *from, char *list) {
  p2_state_t *p = state->p2;
  char *ent[MAX_MESH_HUBS + 1];
  int n = p2_split(list, ',', ent, MAX_MESH_HUBS + 1);
  if (n < 0) {
    p->c_rx_bad++;
    return false;
  }
  uint64_t es[MAX_MESH_HUBS + 1], ss[MAX_MESH_HUBS + 1];
  char *os[MAX_MESH_HUBS + 1];
  for (int i = 0; i < n; i++) {
    char *kv[3] = {NULL, NULL, NULL};
    if (p2_split(ent[i], ':', kv, 3) != 3 || !p2_id_ok(kv[0]) || !p2_num_ok(kv[1], &es[i]) ||
        !p2_num_ok(kv[2], &ss[i]) || !p2_es_sane(es[i], ss[i])) {
      p->c_rx_bad++;
      return false;
    }
    os[i] = kv[0];
  }
  for (int i = 0; i < n; i++) {
    if (strcmp(os[i], p->self.origin) == 0) {
      p2_self_claim(state, es[i], ss[i]);
      continue;
    }
    p2_rec_t *r = p2_rec_get(p, os[i]);
    if (!r) continue;
    if ((es[i] > r->epoch || (es[i] == r->epoch && ss[i] > r->seq)) &&
        !p2_jump_refused(state, from, r, es[i], ss[i]))
      p2_pull(state, r, from);
  }
  return true;
}

void hub_p2_rx(hub_state_t *state, hub_client_t *from, const char *payload) {
  p2_state_t *p = state->p2;
  if (!p || !payload) return;
  if (!p2_peer_uuid(state, from)[0]) return; /* not a configured, linked peer */
  p->c_rx++;
  size_t len = strnlen(payload, P2_MAX_FRAME + 1);
  if (len > P2_MAX_FRAME) {
    p->c_rx_bad++;
    return;
  }
  char *copy = malloc(len + 1);
  if (!copy) return;
  memcpy(copy, payload, len + 1);
  char *f[9];
  int n = p2_split(copy, '|', f, 9);
  if (n == 8 && strcmp(f[0], "S") == 0) {
    from->p2_seen = true;
    p2_rx_snap(state, from, f);
  } else if (n == 8 && strcmp(f[0], "D") == 0) {
    from->p2_seen = true;
    p2_rx_delta(state, from, f);
  } else if (n == 3 && strcmp(f[0], "H") == 0) {
    p2_rx_hash(state, from, f);
  } else if (n == 2 && strcmp(f[0], "G") == 0) {
    p2_rx_digest(state, from, f[1]);
  } else if (n == 2 && strcmp(f[0], "W") == 0) {
    if (p2_rx_digest(state, from, f[1])) p2_send_digest(state, from, 'G');
  } else if (n == 2 && strcmp(f[0], "R") == 0) {
    if (!p2_id_ok(f[1])) {
      p->c_rx_bad++;
    } else {
      const p2_rec_t *r = strcmp(f[1], p->self.origin) == 0 ? &p->self : p2_rec_find(p, f[1]);
      char *buf = malloc(P2_MAX_FRAME);
      if (buf && r && r->epoch > 0 && p2_snap_frame(r, 0, buf, P2_MAX_FRAME) >= 0)
        p2_tx(state, from, buf);
      free(buf);
    }
  } else if (n < 1 || strlen(f[0]) != 1) {
    p->c_rx_bad++;
  } /* else: a tag of a later phase, ignored */
  free(copy);
}

/* ---------- link-up, tick ---------- */

void hub_p2_init(hub_state_t *state) {
  if (state->p2) return;
  state->p2 = calloc(1, sizeof(*state->p2));
  if (!state->p2) {
    hub_log_error("[PRESENCE] OOM: presence v2 off\n");
    return;
  }
  p2_state_t *p = state->p2;
  snprintf(p->self.origin, sizeof(p->self.origin), "%s", state->hub_uuid);
  snprintf(p->self.caps, sizeof(p->self.caps), "rollcall");
  p->self.epoch = p2_epoch_read() + 1;
  p2_epoch_write(p->self.epoch);
  int64_t now = p2_now_ms();
  /* The full round lands half a digest period off the digest ticks. */
  p->next_full_ms = now + P2_FULL_EVERY_MS + P2_DIGEST_MS / 2;
  p->next_digest_ms = now + P2_DIGEST_MS;
  p->tokens_milli = (int64_t)P2_BUCKET_BURST * 1000;
  p->bucket_ms = now;
}

/* A peer link just authenticated: our record (ttl 0, for it alone) and our
 * digest, so each side pulls what the other holds newer, far hubs included. */
void hub_p2_link_up(hub_state_t *state, hub_client_t *peer) {
  p2_state_t *p = state->p2;
  if (!p || !p2_peer_uuid(state, peer)[0]) return;
  p2_refresh_self(state, peer); /* the others hear of this link as a delta */
  char *buf = malloc(P2_MAX_FRAME);
  if (buf && p2_snap_frame(&p->self, 0, buf, P2_MAX_FRAME) >= 0) p2_tx(state, peer, buf);
  free(buf);
  p2_send_digest(state, peer, 'G');
}

/* Every hub here linked to a v2 peer (a dialled link once it has answered) and
 * every hub in the mesh map with a record: only then may the walk say "gone". */
static bool p2_ready(const hub_state_t *state) {
  const p2_state_t *p = state->p2;
  for (int i = 0; i < state->client_count; i++) {
    const hub_client_t *c = state->clients[i];
    if (c->type == CLIENT_HUB && c->authenticated && c->peer_heard && !c->p2_seen) return false;
  }
  for (int i = 0; i < state->mesh_hub_count; i++) {
    const char *u = state->mesh_hubs[i].uuid;
    if (strcmp(u, p->self.origin) == 0) continue;
    const p2_rec_t *r = p2_rec_find_c(p, u);
    if (!r || r->epoch == 0) return false;
  }
  return true;
}

static void p2_reach(hub_state_t *state, int64_t now) {
  p2_state_t *p = state->p2;
  char queue[MAX_MESH_HUBS * 2][P2_ID_MAX + 1];
  int qh = 0, qt = 0;
  bool mark[MAX_MESH_HUBS] = {0};
  for (int i = 0; i < p->self.nlinks && qt < MAX_MESH_HUBS * 2; i++)
    snprintf(queue[qt++], P2_ID_MAX + 1, "%s", p->self.links[i]);
  while (qh < qt) {
    const p2_rec_t *r = p2_rec_find(p, queue[qh++]);
    if (!r) continue;
    mark[r - p->recs] = true;
    for (int l = 0; l < r->nlinks; l++) {
      const char *q = r->links[l];
      if (strcmp(q, p->self.origin) == 0) continue;
      const p2_rec_t *rq = p2_rec_find(p, q);
      if (rq && rq->epoch > 0 && p2_link_idx(rq, r->origin) < 0) continue;
      bool dup = false;
      for (int k = 0; k < qt && !dup; k++) dup = strcmp(queue[k], q) == 0;
      if (!dup && qt < MAX_MESH_HUBS * 2) snprintf(queue[qt++], P2_ID_MAX + 1, "%s", q);
    }
  }
  for (int i = 0; i < p->nrecs; i++) {
    p2_rec_t *r = &p->recs[i];
    if (mark[i]) {
      if (!r->reach) r->rdirty = true;
      r->reach = true;
      r->purged = false;
    } else {
      if (r->reach || r->gone_ms == 0) r->gone_ms = now;
      r->reach = false;
    }
  }
}

/* Runs from every maintenance pass; the work below needs no finer clock than
 * P2_TICK_MS, so a busy select() loop does not repeat it per event. */
void hub_p2_tick(hub_state_t *state) {
  p2_state_t *p = state->p2;
  if (!p) return;
  int64_t now = p2_now_ms();
  if (p->last_tick_ms && now - p->last_tick_ms < P2_TICK_MS) return;
  p->last_tick_ms = now;
  p2_refresh_self(state, NULL);
  if (now >= p->next_full_ms) {
    p->next_full_ms = now + P2_FULL_EVERY_MS;
    p->self.seq++;
    p->dirty = true;
  }
  if (p->dirty && now - p->last_flood_ms >= P2_STORM_GAP_MS) {
    p2_flood_self(state);
    p->c_snaps++;
  }
  if (now >= p->next_digest_ms) {
    p->next_digest_ms = now + P2_DIGEST_MS;
    hub_client_t *cl[MAX_PEERS];
    const char *ids[MAX_PEERS];
    int n = p2_linked(state, cl, ids, MAX_PEERS);
    for (int i = 0; i < n; i++) p2_send_hash(state, cl[i]);
  }
  p2_reach(state, now);
  bool ready = p2_ready(state);
  p->ready = ready;
  bool rec_due = now >= p->next_reconcile_ms;
  if (rec_due) p->next_reconcile_ms = now + P2_RECONCILE_MS;
  for (int i = 0; i < p->nrecs; i++) {
    p2_rec_t *r = &p->recs[i];
    if (r->epoch == 0) continue;
    if (r->reach) {
      /* Only when its record or its roster entries changed since. */
      if (rec_due && r->rdirty) {
        r->rdirty = false;
        hub_roster_p2_reconcile(state, r);
      }
    } else if (ready && now - r->gone_ms >= P2_GRACE_MS && (!r->purged || r->rdirty)) {
      /* Once per outage, and again only if a late frame brought entries of
       * it back (roster_upsert marks rdirty). */
      r->rdirty = false;
      int n = hub_roster_p2_drop_hub(state, r->origin);
      if (!r->purged && n > 0) {
        hub_log_info("[PRESENCE] %s unreachable: dropped from the mesh view\n",
                     hub_who(state, 'h', r->origin));
        p->c_purges++;
      }
      r->purged = true;
    }
  }
}

/* roster_upsert touched an entry of `hub_uuid`: its record is compared with
 * the roster again on the next reconcile pass (P2_RECONCILE_MS), and only
 * then; an idle mesh costs no reconcile work. */
void hub_p2_roster_touched(hub_state_t *state, const char *hub_uuid) {
  if (!state->p2 || !hub_uuid) return;
  p2_rec_t *r = p2_rec_find(state->p2, hub_uuid);
  if (r) r->rdirty = true;
}

/* For display: a hub the walk cannot reach right now (no grace). */
bool hub_p2_hub_gone(const hub_state_t *state, const char *uuid) {
  const p2_state_t *p = state->p2;
  if (!p || !uuid || !uuid[0]) return false;
  const p2_rec_t *r = p2_rec_find_c(p, uuid);
  return r && r->epoch > 0 && !r->reach && p->ready; /* the last tick's p2_ready */
}

/* phase 3: a link whose keepalive is the 15 s digest rather than pings — a
 * connected configured peer: every hub the mesh admits (MESH_MIN_VERSION
 * 2.5.3) runs v2 and sends `H` every P2_DIGEST_MS from link-up.  Its liveness
 * is the digest; it is pinged no more and dropped after P2_LINK_TIMEOUT
 * unheard.  A bot and an unconfigured inbound hub are not such links and keep
 * the ping and CLIENT_TIMEOUT. */
bool hub_p2_digest_keepalive(const hub_state_t *state, const hub_client_t *c) {
  if (!c || c->type != CLIENT_HUB || !c->authenticated) return false;
  for (int p = 0; p < state->peer_count; p++)
    if (state->peers[p].connected && state->peers[p].fd == c->fd) return true;
  return false;
}
