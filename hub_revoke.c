/* Revoked bots and mesh-wide hub settings
 * (docs/plans/2026-10-17_bot_revoke_plan.md).
 *
 * rv|<uuid>|<pub>|<pub_ts>|<nick>|<wiped_ts>|<del_ts>
 *   A deleted bot's identity, kept for good: when the bot connects again —
 *   next week or in five years — it proves its key against this pub, is told
 *   to wipe its config (CMD_BOT_RETIRE) and is closed.  The list only grows,
 *   so hubs merge it as a union and never disagree.
 *
 * hs|<name>|<value>|<ts>
 *   One hub setting the whole mesh shares, each with its own stamp so two
 *   settings changed on two hubs at once both survive.  Newer stamp wins, on
 *   a tie the greater value. */

#include "hub.h"

#include <ctype.h>
#include <errno.h>
#include <stddef.h>

/* ---- hs| registry -------------------------------------------------------- */

typedef struct {
  const char *name;
  int max;
  size_t val_off;   /* int    in hub_state_t */
  size_t ts_off;    /* time_t in hub_state_t */
} gsetting_t;

static const gsetting_t GSET[] = {
    {"autopurge", 36500, offsetof(hub_state_t, purge_days_setting),
     offsetof(hub_state_t, purge_days_ts)},
};
#define GSET_COUNT ((int)(sizeof(GSET) / sizeof(GSET[0])))
_Static_assert(sizeof(GSET) / sizeof(GSET[0]) <= HUB_GSETTINGS_MAX,
               "HUB_GSETTINGS_MAX bounds the hs| lines in a bulk payload");

static int *gs_val(hub_state_t *s, const gsetting_t *g) {
  return (int *)(void *)((char *)s + g->val_off);
}
static time_t *gs_ts(hub_state_t *s, const gsetting_t *g) {
  return (time_t *)(void *)((char *)s + g->ts_off);
}
static const gsetting_t *gs_find(const char *name, size_t len) {
  for (int i = 0; i < GSET_COUNT; i++)
    if (strlen(GSET[i].name) == len && strncmp(GSET[i].name, name, len) == 0)
      return &GSET[i];
  return NULL;
}

int hub_gsetting_format(hub_state_t *state, const char *name, char *buf, size_t cap) {
  const gsetting_t *g = gs_find(name, strlen(name));
  if (!g || cap == 0) return -1;
  return snprintf(buf, cap, "hs|%s|%d|%lld\n", g->name, *gs_val(state, g),
                  (long long)*gs_ts(state, g));
}

bool hub_gsetting_set(hub_state_t *state, const char *name, int value) {
  const gsetting_t *g = gs_find(name, strlen(name));
  if (!g || value < 0 || value > g->max) return false;
  *gs_ts(state, g) = hub_lww_next_ts(*gs_ts(state, g));
  *gs_val(state, g) = value;
  state->config_dirty = true;
  return true;
}

/* rest = "<name>|<value>|<ts>".  False if it does not parse or names a
 * setting this hub does not have; *changed when it won. */
bool hub_gsetting_ingest(hub_state_t *state, const char *rest, bool *changed) {
  *changed = false;
  const char *p1 = strchr(rest, '|');
  if (!p1) return false;
  const gsetting_t *g = gs_find(rest, (size_t)(p1 - rest));
  if (!g) return false;
  char *end;
  errno = 0;
  long v = strtol(p1 + 1, &end, 10);
  if (end == p1 + 1 || *end != '|' || errno || v < 0 || v > g->max) return false;
  const char *ts_s = end + 1;
  long long ts = strtoll(ts_s, &end, 10);
  if (end == ts_s || *end || ts <= 0) return false;
  time_t *cur_ts = gs_ts(state, g);
  int *cur = gs_val(state, g);
  if ((time_t)ts > *cur_ts || ((time_t)ts == *cur_ts && (int)v > *cur)) {
    *cur = (int)v;
    *cur_ts = (time_t)ts;
    state->config_dirty = true;
    *changed = true;
  }
  return true;
}

/* Every stamped setting, for a full sync or the config file. */
bool hub_gsetting_append(hub_state_t *state, char *buf, int max_len, int *off) {
  for (int i = 0; i < GSET_COUNT; i++) {
    if (*gs_ts(state, &GSET[i]) <= 0) continue;
    int w = hub_gsetting_format(state, GSET[i].name, buf + *off, (size_t)(max_len - *off));
    if (w < 0 || w >= max_len - *off) return false;
    *off += w;
  }
  return true;
}

/* ---- rv| revoke list ----------------------------------------------------- */

static bool rv_uuid_ok(const char *s, size_t n) {
  if (n != 36) return false;
  for (size_t i = 0; i < 36; i++) {
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (s[i] != '-') return false;
    } else if (!isxdigit((unsigned char)s[i])) {
      return false;
    }
  }
  return true;
}

static bool rv_pub_ok(const char *s) {
  if (strlen(s) != COMBINED_KEY_B64) return false;
  int n = 0;
  unsigned char *d = base64_decode(s, &n);
  bool ok = d && n == COMBINED_KEY_LEN;
  free(d);
  return ok;
}

/* A nick as the console may show it: printable, no '|', never truncated
 * mid-way into something else (too long = dropped). */
static void rv_nick_copy(char *dst, const char *src, size_t n) {
  dst[0] = '\0';
  if (n >= MAX_NICK) return;
  for (size_t i = 0; i < n; i++)
    if ((unsigned char)src[i] <= 0x20 || src[i] == 0x7f || src[i] == '|' ||
        (unsigned char)src[i] >= 0x80)
      return;
  memcpy(dst, src, n);
  dst[n] = '\0';
}

hub_revoked_t *hub_revoke_find(hub_state_t *state, const char *uuid) {
  if (!uuid) return NULL;
  for (int i = 0; i < state->revoked_count; i++)
    if (strcmp(state->revoked[i].uuid, uuid) == 0) return &state->revoked[i];
  return NULL;
}

/* Union merge of one record.  True when the list changed. */
bool hub_revoke_merge(hub_state_t *state, const hub_revoked_t *in) {
  hub_revoked_t *r = hub_revoke_find(state, in->uuid);
  if (!r) {
    if (state->revoked_count >= MAX_REVOKED) {
      int old = 0;
      for (int i = 1; i < state->revoked_count; i++)
        if (state->revoked[i].del_ts < state->revoked[old].del_ts ||
            (state->revoked[i].del_ts == state->revoked[old].del_ts &&
             strcmp(state->revoked[i].uuid, state->revoked[old].uuid) < 0))
          old = i;
      /* Every hub drops the same one, so the lists stay equal. */
      if (in->del_ts < state->revoked[old].del_ts ||
          (in->del_ts == state->revoked[old].del_ts &&
           strcmp(in->uuid, state->revoked[old].uuid) < 0))
        return false;
      hub_log_warning("[REVOKE] Revoke list full (%d): dropping the oldest, %s (%s); "
                      "it can no longer be wiped if it connects\n",
                      MAX_REVOKED, state->revoked[old].uuid,
                      state->revoked[old].nick[0] ? state->revoked[old].nick : "no nick");
      state->revoked[old] = state->revoked[--state->revoked_count];
    }
    state->revoked[state->revoked_count++] = *in;
    state->config_dirty = true;
    return true;
  }
  bool changed = false;
  if (in->pub_ts > r->pub_ts ||
      (in->pub_ts == r->pub_ts && strcmp(in->pub, r->pub) > 0)) {
    memcpy(r->pub, in->pub, sizeof(r->pub));
    r->pub_ts = in->pub_ts;
    changed = true;
  }
  if (!r->nick[0] && in->nick[0]) {
    memcpy(r->nick, in->nick, sizeof(r->nick));
    changed = true;
  }
  if (in->wiped_ts > r->wiped_ts) {
    r->wiped_ts = in->wiped_ts;
    changed = true;
  }
  if (in->del_ts < r->del_ts) {
    r->del_ts = in->del_ts;
    changed = true;
  }
  if (changed) state->config_dirty = true;
  return changed;
}

/* rest = everything after "rv|".  Every field is checked; a bad line is
 * dropped whole. */
bool hub_revoke_parse(const char *rest, hub_revoked_t *out) {
  const char *f[6];
  size_t fl[6];
  int n = 0;
  const char *p = rest;
  while (n < 6) {
    const char *bar = strchr(p, '|');
    f[n] = p;
    fl[n] = bar ? (size_t)(bar - p) : strlen(p);
    n++;
    if (!bar) break;
    p = bar + 1;
  }
  if (n != 6 || strchr(f[5], '|')) return false;
  memset(out, 0, sizeof(*out));
  if (!rv_uuid_ok(f[0], fl[0]) || fl[1] != COMBINED_KEY_B64) return false;
  memcpy(out->uuid, f[0], 36);
  memcpy(out->pub, f[1], fl[1]);
  out->pub[fl[1]] = '\0';
  if (!rv_pub_ok(out->pub)) return false;
  rv_nick_copy(out->nick, f[3], fl[3]);
  const int num[] = {2, 4, 5};
  long long v[3];
  for (int i = 0; i < 3; i++) {
    char tmp[24];
    if (fl[num[i]] == 0 || fl[num[i]] >= sizeof(tmp)) return false;
    memcpy(tmp, f[num[i]], fl[num[i]]);
    tmp[fl[num[i]]] = '\0';
    char *end;
    v[i] = strtoll(tmp, &end, 10);
    if (*end || v[i] < 0) return false;
  }
  out->pub_ts = (time_t)v[0];
  out->wiped_ts = (time_t)v[1];
  out->del_ts = (time_t)v[2];
  return out->del_ts > 0;
}

int hub_revoke_format(const hub_revoked_t *r, char *buf, size_t cap) {
  return snprintf(buf, cap, "rv|%s|%s|%lld|%s|%lld|%lld\n", r->uuid, r->pub,
                  (long long)r->pub_ts, r->nick, (long long)r->wiped_ts,
                  (long long)r->del_ts);
}

bool hub_revoke_append(hub_state_t *state, char *buf, int max_len, int *off) {
  for (int i = 0; i < state->revoked_count; i++) {
    int w = hub_revoke_format(&state->revoked[i], buf + *off, (size_t)(max_len - *off));
    if (w < 0 || w >= max_len - *off) return false;
    *off += w;
  }
  return true;
}

/* A deleted bot that has a key goes on the list (bot del, a synced delete).
 * True when the list changed. */
bool hub_revoke_from_bot(hub_state_t *state, const bot_config_t *b) {
  if (!b || b->is_active) return false;
  hub_revoked_t in;
  memset(&in, 0, sizeof(in));
  if (!rv_uuid_ok(b->uuid, strlen(b->uuid))) return false;
  memcpy(in.uuid, b->uuid, 36);
  bool have_pub = false;
  for (int j = 0; j < b->entry_count; j++) {
    const config_entry_t *e = &b->entries[j];
    if (strcmp(e->key, "pub") == 0 && rv_pub_ok(e->value)) {
      memcpy(in.pub, e->value, COMBINED_KEY_B64);
      in.pub_ts = e->timestamp;
      have_pub = true;
    } else if (strcmp(e->key, "n") == 0) {
      rv_nick_copy(in.nick, e->value, strlen(e->value));
    } else if (strcmp(e->key, "d") == 0) {
      in.del_ts = e->timestamp;
    }
  }
  if (!have_pub || in.del_ts <= 0) return false;
  return hub_revoke_merge(state, &in);
}

/* The bot wiped itself: stamp it.  The rv| line to sync goes into line. */
bool hub_revoke_mark_wiped(hub_state_t *state, const char *uuid, time_t now, char *line,
                           size_t cap) {
  hub_revoked_t *r = hub_revoke_find(state, uuid);
  if (!r) return false;
  if (now > r->wiped_ts) r->wiped_ts = now;
  state->config_dirty = true;
  int w = hub_revoke_format(r, line, cap);
  return w > 0 && (size_t)w < cap;
}
