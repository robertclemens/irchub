/* hub_access.c — admin flags (uf|) and oper channel bindings (uc|).
 *
 * docs/plans/2026-10-16_user_flags_plan.md §3: one uf| per user uuid, one uc|
 * per (user uuid, channel).  Both are last-writer-wins and fail closed: no
 * flags record means no flags, no live binding means no channel access.
 * Every writer of these records (config load, bot push, peer sync, console)
 * goes through hub_uflag_put / hub_uchan_put, which validate and cap every
 * field, so the bulk ceilings in hub.h stay hard bounds. */
#include "hub.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static bool uuid_shape(const char *u) {
  if (!u || strlen(u) != 36) return false;
  for (int i = 0; i < 36; i++) {
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (u[i] != '-') return false;
    } else if (!isxdigit((unsigned char)u[i])) {
      return false;
    }
  }
  return true;
}

/* Letters only, each from USER_FLAG_LETTERS, any order, repeats allowed;
 * out gets them once each in canonical order.  "" is valid (no flags). */
bool hub_uflags_canon(const char *in, char *out, size_t cap) {
  if (!in || !out || cap < USER_FLAGS_MAX + 1) return false;
  bool have[sizeof(USER_FLAG_LETTERS)] = {false};
  for (const char *p = in; *p; p++) {
    const char *at = strchr(USER_FLAG_LETTERS, *p);
    if (!at || !*p) return false;
    have[at - USER_FLAG_LETTERS] = true;
  }
  size_t o = 0;
  for (size_t i = 0; i < sizeof(USER_FLAG_LETTERS) - 1; i++)
    if (have[i]) out[o++] = USER_FLAG_LETTERS[i];
  out[o] = '\0';
  return true;
}

/* A flag change as typed: "+c-u" edits cur, "chu" (or "+chu" with no '-')
 * replaces it.  A leading '+' alone ("+a") is a replace, so "user add admin
 * … +a" and "chattr x +a" read the same.  false on an unknown letter or an
 * empty spec. */
bool hub_uflags_edit(const char *cur, const char *spec, char *out, size_t cap) {
  if (!spec || !spec[0] || cap < USER_FLAGS_MAX + 1) return false;
  if (!strchr(spec, '-')) {
    return hub_uflags_canon(spec[0] == '+' ? spec + 1 : spec, out, cap) &&
           (spec[0] != '+' || spec[1]);
  }
  char work[USER_FLAGS_MAX + 1];
  if (!hub_uflags_canon(cur ? cur : "", work, sizeof(work))) work[0] = '\0';
  bool have[sizeof(USER_FLAG_LETTERS)] = {false};
  for (const char *p = work; *p; p++) have[strchr(USER_FLAG_LETTERS, *p) - USER_FLAG_LETTERS] = true;
  int sign = 0;
  bool any = false;
  for (const char *p = spec; *p; p++) {
    if (*p == '+' || *p == '-') {
      sign = *p == '+' ? 1 : -1;
      continue;
    }
    const char *at = strchr(USER_FLAG_LETTERS, *p);
    if (!at || !sign) return false;
    have[at - USER_FLAG_LETTERS] = sign > 0;
    any = true;
  }
  if (!any) return false;
  size_t o = 0;
  for (size_t i = 0; i < sizeof(USER_FLAG_LETTERS) - 1; i++)
    if (have[i]) out[o++] = USER_FLAG_LETTERS[i];
  out[o] = '\0';
  return true;
}

/* LWW for a flag set: newer stamp wins; on a tie the fewer rights win (no
 * 'a' beats 'a', then the shorter string, then the byte-wise smaller), so
 * every node picks the same side and a race never grants. */
bool hub_uflags_accepts(time_t in_ts, const char *in, time_t cur_ts, const char *cur) {
  if (in_ts != cur_ts) return in_ts > cur_ts;
  bool ia = strchr(in, 'a') != NULL, ca = strchr(cur, 'a') != NULL;
  if (ia != ca) return !ia;
  size_t il = strlen(in), cl = strlen(cur);
  if (il != cl) return il < cl;
  return strcmp(in, cur) < 0;
}

/* "*", or a channel name: # or & then 1..MAX_CHAN-2 bytes with no blank,
 * comma, '|', control byte or 0x7f. */
bool hub_uchan_name_ok(const char *chan) {
  if (!chan || !chan[0]) return false;
  if (strcmp(chan, "*") == 0) return true;
  size_t n = strlen(chan);
  if ((chan[0] != '#' && chan[0] != '&') || n < 2 || n >= MAX_CHAN) return false;
  for (const char *p = chan; *p; p++) {
    unsigned char c = (unsigned char)*p;
    if (c <= 0x20 || c == 0x7f || c == ',' || c == '|' || c == ':') return false;
  }
  return true;
}

hub_uflag_record_t *hub_uflag_find(hub_state_t *state, const char *uuid) {
  for (int i = 0; i < state->uflag_record_count; i++)
    if (strcmp(state->uflag_records[i].uuid, uuid) == 0) return &state->uflag_records[i];
  return NULL;
}

hub_uchan_record_t *hub_uchan_find(hub_state_t *state, const char *uuid, const char *chan) {
  for (int i = 0; i < state->uchan_record_count; i++) {
    hub_uchan_record_t *r = &state->uchan_records[i];
    if (strcmp(r->uuid, uuid) == 0 && strcasecmp(r->chan, chan) == 0) return r;
  }
  return NULL;
}

/* Store a uf| if it wins LWW.  true = stored (a change). */
bool hub_uflag_put(hub_state_t *state, const char *uuid, const char *flags, time_t ts) {
  char canon[USER_FLAGS_MAX + 1];
  if (!uuid_shape(uuid) || !hub_uflags_canon(flags, canon, sizeof(canon)) || ts <= 0)
    return false;
  hub_uflag_record_t *r = hub_uflag_find(state, uuid);
  if (!r) {
    if (state->uflag_record_count >= MAX_HUB_USER_FLAGS) {
      hub_log_warning("[ACCESS] Flag table full (%d): uf| for %s dropped\n",
                      MAX_HUB_USER_FLAGS, uuid);
      return false;
    }
    r = &state->uflag_records[state->uflag_record_count++];
    memset(r, 0, sizeof(*r));
    snprintf(r->uuid, sizeof(r->uuid), "%s", uuid);
  } else if (!hub_uflags_accepts(ts, canon, r->timestamp, r->flags)) {
    return false;
  }
  snprintf(r->flags, sizeof(r->flags), "%s", canon);
  r->timestamp = ts;
  state->config_dirty = true;
  return true;
}

/* Store a uc| if it wins LWW.  true = stored (a change). */
bool hub_uchan_put(hub_state_t *state, const char *uuid, const char *chan, bool active,
                   time_t ts) {
  if (!uuid_shape(uuid) || !hub_uchan_name_ok(chan) || ts <= 0) return false;
  hub_uchan_record_t *r = hub_uchan_find(state, uuid, chan);
  if (!r) {
    if (state->uchan_record_count >= MAX_HUB_CHAN_BINDS) {
      hub_log_warning("[ACCESS] Binding table full (%d): uc| %s for %s dropped\n",
                      MAX_HUB_CHAN_BINDS, chan, uuid);
      return false;
    }
    r = &state->uchan_records[state->uchan_record_count++];
    memset(r, 0, sizeof(*r));
    snprintf(r->uuid, sizeof(r->uuid), "%s", uuid);
    snprintf(r->chan, sizeof(r->chan), "%s", chan);
  } else if (!hub_lww_accepts(ts, active, r->timestamp, r->is_active)) {
    return false;
  }
  r->is_active = active;
  r->timestamp = ts;
  state->config_dirty = true;
  return true;
}

/* The flags a user holds ("" for none or an unknown uuid). */
const char *hub_user_flags(hub_state_t *state, const char *uuid) {
  hub_uflag_record_t *r = hub_uflag_find(state, uuid);
  return r ? r->flags : "";
}

/* Admin flag check: 'a' passes every letter. */
bool hub_user_has_flag(hub_state_t *state, const char *uuid, char flag) {
  const char *f = hub_user_flags(state, uuid);
  return strchr(f, 'a') != NULL || (flag && strchr(f, flag) != NULL);
}

/* An oper's channel access: a live "*" or a live binding to chan. */
bool hub_user_chan_ok(hub_state_t *state, const char *uuid, const char *chan) {
  for (int i = 0; i < state->uchan_record_count; i++) {
    const hub_uchan_record_t *r = &state->uchan_records[i];
    if (!r->is_active || strcmp(r->uuid, uuid) != 0) continue;
    if (strcmp(r->chan, "*") == 0 || (chan && strcasecmp(r->chan, chan) == 0)) return true;
  }
  return false;
}

/* Live bindings of one user: *global set when "*" is among them. */
int hub_user_chan_count(hub_state_t *state, const char *uuid, bool *global) {
  int n = 0;
  if (global) *global = false;
  for (int i = 0; i < state->uchan_record_count; i++) {
    const hub_uchan_record_t *r = &state->uchan_records[i];
    if (!r->is_active || strcmp(r->uuid, uuid) != 0) continue;
    n++;
    if (global && strcmp(r->chan, "*") == 0) *global = true;
  }
  return n;
}

/* A user an older node would over-trust (§3.2): an admin whose uf| is not
 * exactly "a", or an oper with uc| records but no live "*".  A user with no
 * records yet is not: hub_access_migrate makes it +a / * at the end of the
 * batch that brought it, which is what an older node assumes anyway. */
bool hub_user_restricted(hub_state_t *state, const hub_user_record_t *u) {
  if (!u || !u->is_active) return false;
  if (u->type == 'a') {
    hub_uflag_record_t *f = hub_uflag_find(state, u->uuid);
    return f && strcmp(f->flags, "a") != 0;
  }
  bool any = false;
  for (int i = 0; i < state->uchan_record_count && !any; i++)
    any = strcmp(state->uchan_records[i].uuid, u->uuid) == 0;
  bool global = false;
  hub_user_chan_count(state, u->uuid, &global);
  return any && !global;
}

int hub_format_uflag(const hub_uflag_record_t *r, char *buf, size_t cap) {
  return snprintf(buf, cap, "uf|%s|%s|%lld\n", r->uuid, r->flags, (long long)r->timestamp);
}

int hub_format_uchan(const hub_uchan_record_t *r, char *buf, size_t cap) {
  return snprintf(buf, cap, "uc|%s|%s|%s|%lld\n", r->uuid, r->chan,
                  r->is_active ? "add" : "del", (long long)r->timestamp);
}

/* Split v on '|' into at most max fields (in place).  The count found. */
static int split_pipes(char *v, char **f, int max) {
  int n = 0;
  f[n++] = v;
  for (char *p = v; *p && n < max; p++)
    if (*p == '|') {
      *p = '\0';
      f[n++] = p + 1;
    }
  return n;
}

/* One record body (after "uf|" / "uc|").  kind 'f' or 'c'.  *changed set when
 * it was stored; false on a malformed line.  need_user: drop a record whose
 * user this hub does not hold (peer sync, bot push: the a|/o| lines come
 * first in every generated payload). */
bool hub_access_ingest(hub_state_t *state, char kind, const char *body, bool need_user,
                       bool *changed) {
  if (changed) *changed = false;
  char v[UC_LINE_MAX];
  if (!body || strlen(body) >= sizeof(v)) return false;
  memcpy(v, body, strlen(body) + 1);
  size_t vl = strlen(v);
  while (vl > 0 && (v[vl - 1] == '\n' || v[vl - 1] == '\r')) v[--vl] = '\0';
  char *f[6];
  int n = split_pipes(v, f, 6);
  if (need_user) {
    bool known = false;
    for (int i = 0; i < state->user_record_count && !known; i++)
      known = strcmp(state->user_records[i].uuid, f[0]) == 0;
    if (!known) return false;
  }
  bool ok;
  if (kind == 'f') {
    if (n != 3) return false;
    ok = hub_uflag_put(state, f[0], f[1], (time_t)atoll(f[2]));
  } else {
    if (n != 4 || (strcmp(f[2], "add") != 0 && strcmp(f[2], "del") != 0)) return false;
    ok = hub_uchan_put(state, f[0], f[1], f[2][0] == 'a', (time_t)atoll(f[3]));
  }
  if (changed) *changed = ok;
  return true;
}

/* §3.3: every live admin without a uf| becomes "a", every live oper without
 * any uc| becomes "*" -- what they could do before flags existed.  Run after
 * config load and after every ingest batch.
 *
 * Stamped USER_ACCESS_MIGRATE_TS (1), never "now": a node that holds a user
 * but not yet its records (it just upgraded, or the records are still on the
 * way) must not out-date a real restriction made elsewhere.  Any real record
 * beats it, and a channel-bound oper is always created with an explicit
 * "*" del (hub_access_purge keeps those) so its "*" add@1 loses too.
 * Returns how many records it wrote. */
int hub_access_migrate(hub_state_t *state) {
  const time_t now = USER_ACCESS_MIGRATE_TS;
  int made = 0;
  for (int i = 0; i < state->user_record_count; i++) {
    const hub_user_record_t *u = &state->user_records[i];
    if (!u->is_active) continue;
    if (u->type == 'a' && !hub_uflag_find(state, u->uuid)) {
      if (hub_uflag_put(state, u->uuid, "a", now)) made++;
    } else if (u->type == 'o') {
      bool any = false;
      for (int j = 0; j < state->uchan_record_count && !any; j++)
        any = strcmp(state->uchan_records[j].uuid, u->uuid) == 0;
      if (!any && hub_uchan_put(state, u->uuid, "*", true, now)) made++;
    }
  }
  if (made)
    hub_log_info("[ACCESS] Migrated %d user%s to flags / channel bindings "
                 "(admins: +a, opers: *)\n", made, made == 1 ? "" : "s");
  return made;
}

/* The dedup at load merged two user records into one uuid: follow it. */
void hub_access_remap_uuid(hub_state_t *state, const char *from, const char *to) {
  for (int i = 0; i < state->uflag_record_count; i++)
    if (strcmp(state->uflag_records[i].uuid, from) == 0) {
      hub_uflag_record_t *dst = hub_uflag_find(state, to);
      hub_uflag_record_t *src = &state->uflag_records[i];
      if (!dst) {
        snprintf(src->uuid, sizeof(src->uuid), "%s", to);
      } else if (dst != src && hub_uflags_accepts(src->timestamp, src->flags, dst->timestamp,
                                                  dst->flags)) {
        snprintf(dst->flags, sizeof(dst->flags), "%s", src->flags);
        dst->timestamp = src->timestamp;
      }
    }
  for (int i = 0; i < state->uchan_record_count; i++)
    if (strcmp(state->uchan_records[i].uuid, from) == 0) {
      hub_uchan_record_t *src = &state->uchan_records[i];
      hub_uchan_record_t *dst = hub_uchan_find(state, to, src->chan);
      if (!dst) {
        snprintf(src->uuid, sizeof(src->uuid), "%s", to);
      } else if (dst != src && hub_lww_accepts(src->timestamp, src->is_active, dst->timestamp,
                                               dst->is_active)) {
        dst->is_active = src->is_active;
        dst->timestamp = src->timestamp;
      }
    }
  /* a record left on `from` (its target already had one) goes with the next
   * hub_access_prune */
}

/* Drop records whose user is gone from user_records, records still keyed by
 * a remapped uuid (the dedup above), and keep the arrays dense. */
void hub_access_prune(hub_state_t *state) {
  int o = 0;
  for (int i = 0; i < state->uflag_record_count; i++) {
    bool keep = false;
    for (int u = 0; u < state->user_record_count && !keep; u++)
      keep = strcmp(state->user_records[u].uuid, state->uflag_records[i].uuid) == 0;
    for (int j = 0; j < o && keep; j++)
      keep = strcmp(state->uflag_records[j].uuid, state->uflag_records[i].uuid) != 0;
    if (keep) state->uflag_records[o++] = state->uflag_records[i];
  }
  state->uflag_record_count = o;
  o = 0;
  for (int i = 0; i < state->uchan_record_count; i++) {
    const hub_uchan_record_t *r = &state->uchan_records[i];
    bool keep = false;
    for (int u = 0; u < state->user_record_count && !keep; u++)
      keep = strcmp(state->user_records[u].uuid, r->uuid) == 0;
    for (int j = 0; j < o && keep; j++)
      keep = !(strcmp(state->uchan_records[j].uuid, r->uuid) == 0 &&
               strcasecmp(state->uchan_records[j].chan, r->chan) == 0);
    if (keep) state->uchan_records[o++] = *r;
  }
  state->uchan_record_count = o;
}

/* Purge: drop binding tombstones older than cutoff (0 = all of them).  Flags
 * have no tombstone; they go with their user (hub_access_prune).  A "*" del
 * of a live user is never purged: it is what keeps hub_access_migrate from
 * making a channel-bound oper global again.  Returns how many it dropped. */
int hub_access_purge(hub_state_t *state, time_t cutoff) {
  int o = 0, dropped = 0;
  for (int i = 0; i < state->uchan_record_count; i++) {
    const hub_uchan_record_t *r = &state->uchan_records[i];
    bool live_user = false;
    for (int u = 0; u < state->user_record_count && !live_user; u++)
      live_user = state->user_records[u].is_active &&
                  strcmp(state->user_records[u].uuid, r->uuid) == 0;
    if (!r->is_active && (cutoff == 0 || r->timestamp < cutoff) &&
        !(live_user && strcmp(r->chan, "*") == 0)) {
      dropped++;
      continue;
    }
    state->uchan_records[o++] = *r;
  }
  state->uchan_record_count = o;
  hub_access_prune(state);
  if (dropped) state->config_dirty = true;
  return dropped;
}

/* Append every uf| and uc| line for users that pass keep (NULL = all) to buf
 * at *off.  Stops (false) when buf is full -- callers size buf from
 * USER_ACCESS_RECORDS_MAX, so that never happens. */
bool hub_access_append(hub_state_t *state, char *buf, int cap, int *off,
                       bool (*keep)(hub_state_t *, const char *uuid, void *), void *arg) {
  for (int i = 0; i < state->uflag_record_count; i++) {
    const hub_uflag_record_t *r = &state->uflag_records[i];
    if (keep && !keep(state, r->uuid, arg)) continue;
    int w = hub_format_uflag(r, buf + *off, (size_t)(cap - *off));
    if (w < 0 || w >= cap - *off) return false;
    *off += w;
  }
  for (int i = 0; i < state->uchan_record_count; i++) {
    const hub_uchan_record_t *r = &state->uchan_records[i];
    if (keep && !keep(state, r->uuid, arg)) continue;
    int w = hub_format_uchan(r, buf + *off, (size_t)(cap - *off));
    if (w < 0 || w >= cap - *off) return false;
    *off += w;
  }
  return true;
}

/* ---- Older nodes (plan §3.2, T2) -----------------------------------------
 * A bot below BOT_PROTO_USER_FLAGS or a hub older than USER_FLAGS_MIN_HUB does
 * not know uf| / uc|: it would treat a restricted admin as full and a
 * channel-bound oper as global.  So:
 *   - it never gets uf| / uc| lines;
 *   - it sees each user at hub_access_user_ts (the newest of the user record
 *     and its access records), so a later change always reaches it;
 *   - a restricted user reaches it as a tombstone ("tomb" mode: a node whose
 *     version we know to be older) or not at all (a node whose version we do
 *     not know yet -- a tombstone to a node that turns out to be new would
 *     delete the user there), and never with its masks;
 *   - whatever such a node sends about a restricted user is ignored
 *     (hub_access_from_old_ok), so a tombstone it holds never comes back. */

/* The newest stamp of a user's own record and its uf| / uc| records. */
time_t hub_access_user_ts(hub_state_t *state, const hub_user_record_t *u) {
  time_t ts = u->timestamp;
  hub_uflag_record_t *f = hub_uflag_find(state, u->uuid);
  if (f && f->timestamp > ts) ts = f->timestamp;
  for (int i = 0; i < state->uchan_record_count; i++) {
    const hub_uchan_record_t *r = &state->uchan_records[i];
    if (strcmp(r->uuid, u->uuid) == 0 && r->timestamp > ts) ts = r->timestamp;
  }
  return ts;
}

/* u's a|/o| line for an older node.  0 = left out (a restricted user and not
 * tomb), else as hub_format_user_record. */
int hub_format_user_for_old(hub_state_t *state, const hub_user_record_t *u, bool legacy_v1,
                            bool tomb, char *buf, size_t cap) {
  bool restricted = hub_user_restricted(state, u);
  if (restricted && !tomb) {
    if (cap) buf[0] = '\0';
    return 0;
  }
  hub_user_record_t c = *u;
  c.timestamp = hub_access_user_ts(state, u);
  if (restricted) c.is_active = false;
  return hub_format_user_record(&c, legacy_v1, buf, cap);
}

/* A record an older node sent about user uuid may be taken in: not about a
 * restricted user. */
bool hub_access_from_old_ok(hub_state_t *state, const char *uuid) {
  for (int i = 0; i < state->user_record_count; i++)
    if (strcmp(state->user_records[i].uuid, uuid) == 0)
      return !hub_user_restricted(state, &state->user_records[i]);
  return true;
}

static hub_user_record_t *user_by_uuid(hub_state_t *state, const char *uuid) {
  for (int i = 0; i < state->user_record_count; i++)
    if (strcmp(state->user_records[i].uuid, uuid) == 0) return &state->user_records[i];
  return NULL;
}

/* A sync payload rewritten for an older hub: uf| / uc| / rv| / hs| and a
 * bot's b|<uuid>|hl| dropped (an older hub's parser turns an unknown rv| or
 * hs| line into a phantom bot; its whitelist refuses hl), a| / o|
 * re-stamped (hub_format_user_for_old), m| of a restricted user dropped;
 * every other line as it was.  NULL on out of memory.  The result is never
 * longer than USER_LINE_MAX per user line plus the input. */
char *hub_access_downgrade(hub_state_t *state, const char *payload, bool tomb) {
  size_t in_len = strlen(payload);
  size_t cap = in_len + (size_t)state->user_record_count * USER_LINE_MAX + 1;
  char *out = malloc(cap);
  if (!out) return NULL;
  size_t o = 0;
  for (const char *p = payload; *p;) {
    const char *nl = strchr(p, '\n');
    size_t ll = nl ? (size_t)(nl - p) : strlen(p);
    const char *next = nl ? nl + 1 : p + ll;
    if (ll == 0) {
      p = next;
      continue;
    }
    bool keep = true;
    if (ll > 3 && p[0] == 'u' && (p[1] == 'f' || p[1] == 'c') && p[2] == '|') {
      keep = false;
    } else if (ll > 3 && ((p[0] == 'r' && p[1] == 'v') || (p[0] == 'h' && p[1] == 's')) &&
               p[2] == '|') {
      keep = false;
    } else if (ll > 41 && p[0] == 'b' && p[1] == '|' && p[38] == '|' &&
               !memcmp(p + 39, "hl|", 3)) {
      keep = false; /* a bot's hub list: an older hub's whitelist refuses it */
    } else if (ll > 38 && (p[0] == 'a' || p[0] == 'o' || p[0] == 'm') && p[1] == '|' &&
               p[38] == '|') {
      char uuid[37];
      memcpy(uuid, p + 2, 36);
      uuid[36] = '\0';
      hub_user_record_t *u = user_by_uuid(state, uuid);
      if (u && p[0] == 'm') {
        keep = !hub_user_restricted(state, u);
      } else if (u) {
        char line[USER_LINE_MAX];
        int w = hub_format_user_for_old(state, u, false, tomb, line, sizeof(line));
        if (w > 0 && w < (int)sizeof(line) && o + (size_t)w < cap) {
          memcpy(out + o, line, (size_t)w);
          o += (size_t)w;
        }
        keep = false;
      }
    }
    if (keep && o + ll + 1 < cap) {
      memcpy(out + o, p, ll);
      o += ll;
      out[o++] = '\n';
    }
    p = next;
  }
  out[o] = '\0';
  return out;
}

/* ---- Console helpers (T4) ------------------------------------------------ */

/* A user's live bindings as the console shows them: "*" when global, else
 * the channels comma-joined in table order ("" for none). */
void hub_user_chans(hub_state_t *state, const char *uuid, char *out, size_t cap) {
  if (!cap) return;
  out[0] = '\0';
  bool global = false;
  hub_user_chan_count(state, uuid, &global);
  if (global) {
    snprintf(out, cap, "*");
    return;
  }
  size_t o = 0;
  for (int i = 0; i < state->uchan_record_count; i++) {
    const hub_uchan_record_t *r = &state->uchan_records[i];
    if (!r->is_active || strcmp(r->uuid, uuid) != 0) continue;
    int w = snprintf(out + o, cap - o, "%s%s", o ? "," : "", r->chan);
    if (w < 0 || (size_t)w >= cap - o) {
      out[o] = '\0';
      return;
    }
    o += (size_t)w;
  }
}

/* The stamp for a change to uuid's access records: now, past every stamp
 * those records already carry, so each line written wins everywhere. */
time_t hub_access_next_ts(hub_state_t *state, const char *uuid) {
  time_t prev = 0;
  hub_uflag_record_t *f = hub_uflag_find(state, uuid);
  if (f) prev = f->timestamp;
  for (int i = 0; i < state->uchan_record_count; i++)
    if (strcmp(state->uchan_records[i].uuid, uuid) == 0 && state->uchan_records[i].timestamp > prev)
      prev = state->uchan_records[i].timestamp;
  return hub_lww_next_ts(prev);
}

/* Write an oper binding change the U10 way, appending every uc| line written
 * to out (cap bytes).  add "*": "*" add and every live channel del; add #c:
 * #c add and "*" del; del "*": every live binding del; del #c: #c del.
 * Returns how many lines it wrote, -1 when the table is full. */
int hub_access_chan_change(hub_state_t *state, const char *uuid, bool add, const char *chan,
                           char *out, size_t cap) {
  time_t ts = hub_access_next_ts(state, uuid);
  bool star = strcmp(chan, "*") == 0;
  int n = 0;
  size_t o = strlen(out);
#define UC_EMIT(c_, act_)                                                     \
  do {                                                                        \
    if (!hub_uchan_put(state, uuid, (c_), (act_), ts)) return -1;             \
    hub_uchan_record_t *r_ = hub_uchan_find(state, uuid, (c_));               \
    int w_ = r_ ? hub_format_uchan(r_, out + o, cap - o) : -1;                \
    if (w_ > 0 && (size_t)w_ < cap - o) o += (size_t)w_;                      \
    n++;                                                                      \
  } while (0)
  if (add) {
    UC_EMIT(chan, true);
    /* the other kind goes: "*" clears the channels, a channel clears "*" */
    for (int i = 0; i < state->uchan_record_count; i++) {
      hub_uchan_record_t *r = &state->uchan_records[i];
      if (!r->is_active || strcmp(r->uuid, uuid) != 0) continue;
      bool r_star = strcmp(r->chan, "*") == 0;
      if (star ? !r_star : r_star) {
        char c[MAX_CHAN];
        snprintf(c, sizeof(c), "%s", r->chan);
        UC_EMIT(c, false);
      }
    }
    /* a channel-bound oper always carries a "*" del (hub_access_migrate) */
    if (!star && !hub_uchan_find(state, uuid, "*")) UC_EMIT("*", false);
  } else if (star) {
    for (int i = 0; i < state->uchan_record_count; i++) {
      hub_uchan_record_t *r = &state->uchan_records[i];
      if (!r->is_active || strcmp(r->uuid, uuid) != 0) continue;
      char c[MAX_CHAN];
      snprintf(c, sizeof(c), "%s", r->chan);
      UC_EMIT(c, false);
    }
    if (!hub_uchan_find(state, uuid, "*")) UC_EMIT("*", false);
  } else {
    UC_EMIT(chan, false);
  }
#undef UC_EMIT
  return n;
}
