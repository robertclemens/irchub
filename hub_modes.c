#include "hub.h"
#include "glob_overlap.h"

/* ==========================================================================
 * Modes, channel settings, network defaults, bans (docs/modes.md, 2.4.5)
 *
 * The records themselves (C|, D|, B|) live in global_entries[] and enter the
 * store only through hub_storage_put_record (hub_storage.c): validation, LWW
 * and the ceilings are there.  This file is everything around them: the
 * setting table, the console-facing store functions, the ban rules (including
 * the bot-written ones), the expiry sweep, the older-hub check and the
 * CMD_CHAN_EVENT receipt.
 * ========================================================================== */

/* ---- setting table ------------------------------------------------------ */

typedef enum { ST_FLAG, ST_NUM, ST_FLOOD, ST_SENDQ } st_kind_t;

typedef struct {
  const char *name;
  st_kind_t   kind;
  long        lo, hi;     /* ST_NUM range                                  */
  const char *def;        /* built-in value                                */
  bool        net_only;   /* only legal in D| (bot floods, ignore time)    */
} setting_def_t;

/* Names, ranges and built-ins: the contract (docs/modes.md §4, §8.1, §9.1). */
static const setting_def_t SETTINGS[] = {
    {"enforcemodes", ST_FLAG, 0, 1, "0", false},
    {"bitch", ST_FLAG, 0, 1, "0", false},
    {"protectops", ST_FLAG, 0, 1, "1", false},
    {"revenge", ST_FLAG, 0, 1, "0", false},
    {"stopnethack", ST_FLAG, 0, 1, "0", false},
    {"enforcebans", ST_FLAG, 0, 1, "0", false},
    {"dynamicbans", ST_FLAG, 0, 1, "1", false},
    {"dontkickops", ST_FLAG, 0, 1, "1", false},
    {"cycle", ST_FLAG, 0, 1, "1", false},
    {"dynamiclimit", ST_FLAG, 0, 1, "0", false},
    {"bantime", ST_NUM, 0, 525600, "120", false},
    {"bantype", ST_NUM, 0, 9, "2", false},
    {"banidle", ST_NUM, 1, 10080, "60", false},
    {"limitgap", ST_NUM, 1, 1000, "5", false},
    {"limitdelay", ST_NUM, 10, 3600, "60", false},
    {"flood chan", ST_FLOOD, 0, 0, "15:60", false},
    {"flood ctcp", ST_FLOOD, 0, 0, "3:60", false},
    {"flood join", ST_FLOOD, 0, 0, "5:60", false},
    {"flood nick", ST_FLOOD, 0, 0, "5:60", false},
    {"flood deop", ST_FLOOD, 0, 0, "3:10", false},
    {"flood kick", ST_FLOOD, 0, 0, "3:10", false},
    {"flood ban", ST_FLOOD, 0, 0, "3:10", false},
    {"bflood cmd", ST_FLOOD, 0, 0, "10:30", true},
    {"bflood msg", ST_FLOOD, 0, 0, "5:60", true},
    {"bflood ctcp", ST_FLOOD, 0, 0, "3:60", true},
    {"ignoretime", ST_NUM, 1, 1440, "10", true},
    {"sendq", ST_SENDQ, 0, 0, "10:100", true},  /* B:I, B 1-100 lines, I 0-10000 ms */
};
#define NSETTINGS (sizeof(SETTINGS) / sizeof(SETTINGS[0]))

static const setting_def_t *setting_find(const char *name) {
  for (size_t i = 0; i < NSETTINGS; i++)
    if (strcmp(SETTINGS[i].name, name) == 0) return &SETTINGS[i];
  return NULL;
}

/* The setting table for the console (channel set / network set views). */
int hub_setting_count(void) { return (int)NSETTINGS; }

const char *hub_setting_name(int i) {
  return i >= 0 && i < (int)NSETTINGS ? SETTINGS[i].name : NULL;
}

const char *hub_setting_kind(const char *name) {
  const setting_def_t *d = name ? setting_find(name) : NULL;
  if (!d) return NULL;
  return d->kind == ST_FLAG ? "flag" : d->kind == ST_NUM ? "num" : d->kind == ST_SENDQ ? "sendq" : "flood";
}

bool hub_setting_range(const char *name, long *lo, long *hi) {
  const setting_def_t *d = name ? setting_find(name) : NULL;
  if (!d || d->kind != ST_NUM) return false;
  if (lo) *lo = d->lo;
  if (hi) *hi = d->hi;
  return true;
}

bool hub_setting_net_only(const char *name) {
  const setting_def_t *d = name ? setting_find(name) : NULL;
  return d && d->net_only;
}

/* Strict unsigned decimal: 1..9 digits, nothing else. */
static bool parse_num(const char *s, long *out) {
  size_t n = strlen(s);
  if (n == 0 || n > 9) return false;
  long v = 0;
  for (size_t i = 0; i < n; i++) {
    if (s[i] < '0' || s[i] > '9') return false;
    v = v * 10 + (s[i] - '0');
  }
  *out = v;
  return true;
}

hub_modes_status_t hub_setting_check(const char *name, const char *value,
                                     bool net_default) {
  const setting_def_t *d = name && value ? setting_find(name) : NULL;
  if (!d || (d->net_only && !net_default)) return HUB_MODES_BAD_SETTING;
  long v;
  switch (d->kind) {
  case ST_FLAG:
    return (strcmp(value, "0") == 0 || strcmp(value, "1") == 0) ? HUB_MODES_OK
                                                                : HUB_MODES_BAD_SETTING;
  case ST_NUM:
    return parse_num(value, &v) && v >= d->lo && v <= d->hi ? HUB_MODES_OK
                                                           : HUB_MODES_BAD_SETTING;
  case ST_FLOOD: {
    if (strcmp(value, "off") == 0) return HUB_MODES_OK;
    const char *colon = strchr(value, ':');
    char left[16];
    long n, sec;
    if (!colon || (size_t)(colon - value) >= sizeof(left)) return HUB_MODES_BAD_SETTING;
    memcpy(left, value, (size_t)(colon - value));
    left[colon - value] = '\0';
    if (!parse_num(left, &n) || !parse_num(colon + 1, &sec)) return HUB_MODES_BAD_SETTING;
    return n >= 1 && n <= 1000 && sec >= 1 && sec <= 3600 ? HUB_MODES_OK
                                                           : HUB_MODES_BAD_SETTING;
  }
  case ST_SENDQ: {
    const char *colon = strchr(value, ':');
    char left[16];
    long b, ms;
    if (!colon || (size_t)(colon - value) >= sizeof(left)) return HUB_MODES_BAD_SETTING;
    memcpy(left, value, (size_t)(colon - value));
    left[colon - value] = '\0';
    if (!parse_num(left, &b) || !parse_num(colon + 1, &ms)) return HUB_MODES_BAD_SETTING;
    return b >= 1 && b <= 100 && ms >= 0 && ms <= 10000 ? HUB_MODES_OK : HUB_MODES_BAD_SETTING;
  }
  }
  return HUB_MODES_BAD_SETTING;
}

/* Walk "a=b,c d=e": calls f(name, value, ctx) per token; false from f stops. */
typedef bool (*tok_fn)(const char *name, const char *value, void *ctx);
static bool settings_walk(const char *settings, tok_fn f, void *ctx) {
  const char *p = settings;
  while (*p) {
    const char *end = strchr(p, ',');
    size_t tl = end ? (size_t)(end - p) : strlen(p);
    const char *eq = memchr(p, '=', tl);
    char name[48], value[48];
    if (tl && eq && eq > p) {
      size_t nl = (size_t)(eq - p), vl = tl - nl - 1;
      if (nl < sizeof(name) && vl < sizeof(value)) {
        memcpy(name, p, nl);
        name[nl] = '\0';
        memcpy(value, eq + 1, vl);
        value[vl] = '\0';
        if (!f(name, value, ctx)) return false;
      } else if (!f("", "", ctx)) {
        return false;  /* over-long token: unknown to every table */
      }
    } else if (!f("", "", ctx)) {
      return false;
    }
    p += tl;
    if (*p == ',') p++;
  }
  return true;
}

typedef struct {
  bool net_default;
  char *bad;
  size_t bad_cap;
  hub_modes_status_t st;
} check_ctx_t;

static bool check_tok(const char *name, const char *value, void *vctx) {
  check_ctx_t *c = vctx;
  /* A name this build does not know is kept verbatim and ignored (a newer
   * hub's setting); a known name must carry a legal value. */
  if (!name[0] || !setting_find(name)) {
    if (!name[0]) {
      c->st = HUB_MODES_BAD_SETTING;
      if (c->bad && c->bad_cap) snprintf(c->bad, c->bad_cap, "?");
      return false;
    }
    return true;
  }
  if (hub_setting_check(name, value, c->net_default) != HUB_MODES_OK) {
    c->st = HUB_MODES_BAD_SETTING;
    if (c->bad && c->bad_cap) snprintf(c->bad, c->bad_cap, "%s", name);
    return false;
  }
  return true;
}

hub_modes_status_t hub_settings_check(const char *settings, bool net_default,
                                      char *bad, size_t bad_cap) {
  if (bad && bad_cap) bad[0] = '\0';
  if (!settings) return HUB_MODES_OK;
  size_t cap = C_SETTINGS_MAX;
  if (net_default) cap = D_SETTINGS_MAX;
  if (strlen(settings) > cap) return HUB_MODES_TOO_LONG;
  check_ctx_t c = {net_default, bad, bad_cap, HUB_MODES_OK};
  settings_walk(settings, check_tok, &c);
  return c.st;
}

typedef struct {
  const char *want;
  char *out;
  size_t cap;
  bool found;
} get_ctx_t;

static bool get_tok(const char *name, const char *value, void *vctx) {
  get_ctx_t *g = vctx;
  if (strcmp(name, g->want) != 0) return true;
  g->found = true;
  if (g->out && g->cap) snprintf(g->out, g->cap, "%s", value);
  return false;
}

bool hub_settings_get(const char *settings, const char *name, char *out, size_t cap) {
  get_ctx_t g = {name, out, cap, false};
  if (out && cap) out[0] = '\0';
  if (settings && name) settings_walk(settings, get_tok, &g);
  return g.found;
}

hub_modes_status_t hub_settings_set(char *settings, size_t cap, const char *name,
                                    const char *value) {
  if (!settings || !cap || !name || !name[0] || strchr(name, '=') ||
      strchr(name, ',') || (value && (strchr(value, ',') || strchr(value, '|'))))
    return HUB_MODES_BAD_SETTING;
  char out[C_SETTINGS_MAX + 64];
  size_t o = 0;
  out[0] = '\0';
  const char *p = settings;
  while (*p) {
    const char *end = strchr(p, ',');
    size_t tl = end ? (size_t)(end - p) : strlen(p);
    const char *eq = memchr(p, '=', tl);
    bool same = eq && (size_t)(eq - p) == strlen(name) &&
                memcmp(p, name, strlen(name)) == 0;
    if (tl && !same) {
      if (o + tl + 2 >= sizeof(out)) return HUB_MODES_TOO_LONG;
      if (o) out[o++] = ',';
      memcpy(out + o, p, tl);
      o += tl;
      out[o] = '\0';
    }
    p += tl;
    if (*p == ',') p++;
  }
  if (value) {
    int w = snprintf(out + o, sizeof(out) - o, "%s%s=%s", o ? "," : "", name, value);
    if (w < 0 || (size_t)w >= sizeof(out) - o) return HUB_MODES_TOO_LONG;
    o += (size_t)w;
  }
  if (o >= cap) return HUB_MODES_TOO_LONG;
  memcpy(settings, out, o + 1);
  return HUB_MODES_OK;
}

/* ---- mode strings (§3.2) ------------------------------------------------ */

/* The STORED form: "+stnkl 20" -- letters with signs, then the limit number
 * when +l is set.  The key is not in it (it lives in c|), so +k takes no
 * argument here.  Empty = the network default. */
hub_modes_status_t hub_modes_check(const char *modes) {
  if (!modes || !modes[0]) return HUB_MODES_OK;
  if (strlen(modes) > C_MODES_MAX) return HUB_MODES_TOO_LONG;
  const char *sp = strchr(modes, ' ');
  size_t ml = sp ? (size_t)(sp - modes) : strlen(modes);
  char sign = 0;
  bool seen[256] = {false}, plus_l = false;
  unsigned char plus[256] = {0};
  int letters = 0;
  for (size_t i = 0; i < ml; i++) {
    char c = modes[i];
    if (c == '+' || c == '-') {
      sign = c;
      continue;
    }
    if (!sign || !strchr("imnpstkl", c)) return HUB_MODES_BAD_MODES;
    if (seen[(unsigned char)c]) return HUB_MODES_BAD_MODES;  /* a letter twice */
    seen[(unsigned char)c] = true;
    plus[(unsigned char)c] = (unsigned char)(sign == '+');
    letters++;
    if (c == 'l' && sign == '+') plus_l = true;
  }
  if (letters == 0) return HUB_MODES_BAD_MODES;
  if (plus['s'] && plus['p']) return HUB_MODES_BAD_MODES;  /* s and p together */
  if (sp) {
    long lim;
    if (!plus_l || strchr(sp + 1, ' ') || !parse_num(sp + 1, &lim) || lim < 1 ||
        lim > 99999)
      return HUB_MODES_BAD_MODES;
  } else if (plus_l) {
    return HUB_MODES_BAD_MODES;  /* +l needs its number */
  }
  return HUB_MODES_OK;
}

/* ---- store helpers ------------------------------------------------------- */

static bool frozen(const hub_state_t *state) {
  return strchr(state->opt_flags, OPT_CONFIG_FROZEN) != NULL;
}

/* Send one accepted record to the peers and owe the bots a push. */
static void announce_record(hub_state_t *state, const char *key, const char *value,
                            time_t ts) {
  char line[1200];
  int w = snprintf(line, sizeof(line), "%s|%s|%ld\n", key, value, (long)ts);
  if (w > 0 && w < (int)sizeof(line)) hub_broadcast_sync_to_peers(state, line, -1);
  state->config_dirty = true;
  state->bot_config_pending = true;
}

static bool chan_name_shape(const char *s) {
  size_t n = s ? strlen(s) : 0;
  if (n < 2 || n >= MAX_CHAN || (s[0] != '#' && s[0] != '&')) return false;
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c <= 0x20 || c == ',' || c == 0x7f || c == '|') return false;
  }
  return true;
}

/* A B| value's reason (may hold '|') and op: between the 5th '|' and the
 * last, and after the last. */
static void ban_reason(const config_entry_t *e, char *out, size_t cap) {
  const char *p = e->value, *last = strrchr(e->value, '|');
  for (int i = 0; i < 5 && p; i++) {
    p = strchr(p, '|');
    if (p) p++;
  }
  out[0] = '\0';
  if (!p || !last || last < p) return;
  size_t n = (size_t)(last - p);
  if (n >= cap) n = cap - 1;
  memcpy(out, p, n);
  out[n] = '\0';
}

static void entry_field(const config_entry_t *e, int idx, char *out, size_t cap) {
  const char *p = e->value;
  for (int i = 0; i < idx; i++) {
    p = strchr(p, '|');
    if (!p) {
      out[0] = '\0';
      return;
    }
    p++;
  }
  size_t n = strcspn(p, "|");
  if (n >= cap) n = cap - 1;
  memcpy(out, p, n);
  out[n] = '\0';
}

bool hub_chanset_get(const hub_state_t *state, const char *chan, hub_chanset_t *out) {
  memset(out, 0, sizeof(*out));
  int i = chan ? hub_global_find(state, "C", chan) : -1;
  if (i < 0 || !hub_global_value_active(state->global_entries[i].value)) return false;
  const config_entry_t *e = &state->global_entries[i];
  entry_field(e, 0, out->chan, sizeof(out->chan));
  entry_field(e, 1, out->modes, sizeof(out->modes));
  entry_field(e, 2, out->settings, sizeof(out->settings));
  out->ts = e->timestamp;
  out->present = true;
  return true;
}

bool hub_netset_get(const hub_state_t *state, hub_chanset_t *out) {
  memset(out, 0, sizeof(*out));
  int i = hub_global_find(state, "D", "");
  if (i < 0) return false;
  const config_entry_t *e = &state->global_entries[i];
  entry_field(e, 0, out->modes, sizeof(out->modes));
  entry_field(e, 1, out->settings, sizeof(out->settings));
  out->ts = e->timestamp;
  out->present = out->modes[0] || out->settings[0];
  return out->present;
}

hub_modes_status_t hub_chanset_put(hub_state_t *state, const char *chan,
                                   const char *modes, const char *settings) {
  if (frozen(state)) return HUB_MODES_FROZEN;
  if (!chan_name_shape(chan)) return HUB_MODES_BAD_CHAN;
  char name[MAX_CHAN];
  if (!hub_chan_live(state, chan, name, sizeof(name))) return HUB_MODES_NOT_MANAGED;
  if (!modes) modes = "";
  if (!settings) settings = "";
  hub_modes_status_t st = hub_modes_check(modes);
  if (st != HUB_MODES_OK) return st;
  st = hub_settings_check(settings, false, NULL, 0);
  if (st != HUB_MODES_OK) return st;

  hub_chanset_t cur;
  bool had = hub_chanset_get(state, name, &cur);
  char value[C_MODES_MAX + C_SETTINGS_MAX + MAX_CHAN + 16];
  if (!modes[0] && !settings[0]) {
    if (!had) return HUB_MODES_OK;  /* already the defaults */
    snprintf(value, sizeof(value), "%s|||del", name);
  } else {
    snprintf(value, sizeof(value), "%s|%s|%s|add", name, modes, settings);
  }
  time_t ts = hub_lww_next_ts(hub_storage_global_ts(state, "C", name));
  if (!hub_storage_put_record(state, "C", value, ts)) return HUB_MODES_FULL;
  announce_record(state, "C", value, ts);
  return HUB_MODES_OK;
}

hub_modes_status_t hub_netset_put(hub_state_t *state, const char *modes,
                                  const char *settings) {
  if (frozen(state)) return HUB_MODES_FROZEN;
  if (!modes) modes = "";
  if (!settings) settings = "";
  hub_modes_status_t st = hub_modes_check(modes);
  if (st != HUB_MODES_OK) return st;
  st = hub_settings_check(settings, true, NULL, 0);
  if (st != HUB_MODES_OK) return st;
  char value[C_MODES_MAX + D_SETTINGS_MAX + 8];
  snprintf(value, sizeof(value), "%s|%s", modes, settings);
  time_t ts = hub_lww_next_ts(hub_storage_global_ts(state, "D", ""));
  if (!hub_storage_put_record(state, "D", value, ts)) return HUB_MODES_FULL;
  announce_record(state, "D", value, ts);
  return HUB_MODES_OK;
}

int hub_setting_effective(const hub_state_t *state, const char *chan,
                          const char *name, char *out, size_t cap) {
  const setting_def_t *d = name ? setting_find(name) : NULL;
  if (!d) {
    if (out && cap) out[0] = '\0';
    return 0;
  }
  hub_chanset_t cs;
  if (chan && !d->net_only && hub_chanset_get(state, chan, &cs) &&
      hub_settings_get(cs.settings, name, out, cap))
    return 'c';
  if (hub_netset_get(state, &cs) && hub_settings_get(cs.settings, name, out, cap))
    return 'n';
  if (out && cap) snprintf(out, cap, "%s", d->def);
  return 'b';
}

/* ---- ban protection (§6.2 step 2) ---------------------------------------- */

static bool bot_entry_value(const bot_config_t *b, const char *key, char *out,
                            size_t cap) {
  for (int k = 0; k < b->entry_count; k++)
    if (strcmp(b->entries[k].key, key) == 0) {
      snprintf(out, cap, "%s", b->entries[k].value);
      return true;
    }
  if (cap) out[0] = '\0';
  return false;
}

/* `pat` (with '*' and '?') matches the literal string `s`, ASCII
 * case-insensitively. */
static unsigned char gm_fold(unsigned char c) {
  return (c >= 'A' && c <= 'Z') ? (unsigned char)(c + 32) : c;
}

static bool glob_match(const char *pat, const char *s) {
  const char *star = NULL, *mark = s;
  while (*s) {
    if (*pat == '*') {
      star = pat++;
      mark = s;
    } else if (*pat == '?' || (*pat && gm_fold((unsigned char)*pat) ==
                                           gm_fold((unsigned char)*s))) {
      pat++;
      s++;
    } else if (star) {
      pat = star + 1;
      s = ++mark;
    } else {
      return false;
    }
  }
  while (*pat == '*') pat++;
  return !*pat;
}

hub_modes_status_t hub_ban_protected(const hub_state_t *state, const char *mask,
                                     char *who, size_t who_cap) {
  if (who && who_cap) who[0] = '\0';
  if (!mask || !mask[0]) return HUB_MODES_BAD_MASK;
  /* Trusted bots: the hostmask each one reported. */
  for (int i = 0; i < state->bot_count; i++) {
    const bot_config_t *b = &state->bots[i];
    char h[MAX_MASK_LEN], n[MAX_NICK];
    if (!b->is_active || !bot_entry_value(b, "h", h, sizeof(h)) || !h[0]) continue;
    if (!glob_match(mask, h)) continue;  /* h is a literal host, not a pattern */
    if (who && who_cap) {
      bot_entry_value(b, "n", n, sizeof(n));
      snprintf(who, who_cap, "bot %s", n[0] ? n : b->uuid);
    }
    return HUB_MODES_PROTECTED;
  }
  /* Active usermasks of active admins and opers. */
  for (int i = 0; i < state->mask_record_count; i++) {
    const hub_mask_record_t *m = &state->mask_records[i];
    if (!m->is_active) continue;
    const hub_user_record_t *u = NULL;
    for (int k = 0; k < state->user_record_count; k++)
      if (strcmp(state->user_records[k].uuid, m->uuid) == 0) {
        u = &state->user_records[k];
        break;
      }
    if (!u || !u->is_active || !hostmask_overlap(mask, m->mask)) continue;
    if (who && who_cap) snprintf(who, who_cap, "user %s", u->name);
    return HUB_MODES_PROTECTED;
  }
  return HUB_MODES_OK;
}

/* ---- bans ----------------------------------------------------------------- */

static bool mask_shape(const char *s) {
  size_t n = s ? strlen(s) : 0;
  if (n == 0 || n > BAN_MASK_MAX) return false;
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c <= 0x20 || c >= 0x7f || c == ',' || c == '|') return false;
  }
  return true;
}

/* "chan|mask" key for the ban lookup. */
static int ban_find(const hub_state_t *state, const char *chan, const char *mask) {
  char id[MAX_CHAN + BAN_MASK_MAX + 4];
  snprintf(id, sizeof(id), "%s|%s", chan, mask);
  return hub_global_find(state, "B", id);
}

static bool entry_live(const config_entry_t *e) {
  return hub_global_value_active(e->value);
}

static int ban_count_live(const hub_state_t *state, const char *chan) {
  int n = 0;
  for (int i = 0; i < state->global_entry_count; i++) {
    const config_entry_t *e = &state->global_entries[i];
    char c[MAX_CHAN];
    if (strcmp(e->key, "B") != 0 || !entry_live(e)) continue;
    entry_field(e, 0, c, sizeof(c));
    if (hub_ascii_ieq(c, chan)) n++;
  }
  return n;
}

hub_modes_status_t hub_ban_add(hub_state_t *state, const char *chan, const char *mask,
                               time_t expires, bool sticky, const char *setter,
                               const char *reason, char *who, size_t who_cap) {
  if (who && who_cap) who[0] = '\0';
  if (frozen(state)) return HUB_MODES_FROZEN;
  bool global = chan && strcmp(chan, "*") == 0;
  char cname[MAX_CHAN];
  if (global) {
    snprintf(cname, sizeof(cname), "*");
  } else {
    if (!chan_name_shape(chan)) return HUB_MODES_BAD_CHAN;
    if (!hub_chan_live(state, chan, cname, sizeof(cname))) return HUB_MODES_NOT_MANAGED;
  }
  if (!mask_shape(mask)) return HUB_MODES_BAD_MASK;
  if (!reason) reason = "";
  if (strlen(reason) > BAN_REASON_MAX) return HUB_MODES_BAD_REASON;
  for (const char *p = reason; *p; p++)
    if ((unsigned char)*p < 0x20 || *p == 0x7f) return HUB_MODES_BAD_REASON;
  time_t now = time(NULL);
  if (expires != 0 && (expires <= now || expires > now + 10 * 365 * 86400L))
    return HUB_MODES_BAD_EXPIRY;
  hub_modes_status_t st = hub_ban_protected(state, mask, who, who_cap);
  if (st != HUB_MODES_OK) return st;

  int idx = ban_find(state, cname, mask);
  bool exists = idx >= 0 && entry_live(&state->global_entries[idx]);
  int ceiling = MAX_BANS_PER_CHAN;
  if (global) ceiling = MAX_GLOBAL_BANS;
  if (!exists && ban_count_live(state, cname) >= ceiling)
    return HUB_MODES_FULL;

  /* The setter is stored as one token: anything outside [A-Za-z0-9._-]
   * (an admin name may hold more) becomes '_'. */
  char who_set[BAN_SETTER_MAX];
  snprintf(who_set, sizeof(who_set), "%s", setter ? setter : "");
  for (char *p = who_set; *p; p++) {
    unsigned char c = (unsigned char)*p;
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
          c == '.' || c == '_' || c == '-'))
      *p = '_';
  }
  /* Keep the stored mask spelling when the ban already exists. */
  char mname[BAN_MASK_MAX + 1];
  if (idx >= 0)
    entry_field(&state->global_entries[idx], 1, mname, sizeof(mname));
  else
    snprintf(mname, sizeof(mname), "%s", mask);

  char value[B_LINE_MAX + 64];
  int w = snprintf(value, sizeof(value), "%s|%s|%lld|%s|%s|%s|add", cname, mname,
                   (long long)expires, sticky ? "s" : "", who_set, reason);
  if (w <= 0 || w >= (int)sizeof(value)) return HUB_MODES_TOO_LONG;
  time_t prev = idx >= 0 ? state->global_entries[idx].timestamp : 0;
  time_t ts = hub_lww_next_ts(prev);
  if (!hub_storage_put_record(state, "B", value, ts)) return HUB_MODES_FULL;
  announce_record(state, "B", value, ts);
  return HUB_MODES_OK;
}

hub_modes_status_t hub_ban_del(hub_state_t *state, const char *chan, const char *mask) {
  if (frozen(state)) return HUB_MODES_FROZEN;
  bool global = chan && strcmp(chan, "*") == 0;
  if (!global && !chan_name_shape(chan)) return HUB_MODES_BAD_CHAN;
  if (!mask_shape(mask)) return HUB_MODES_BAD_MASK;
  int idx = ban_find(state, chan, mask);
  if (idx < 0 || !entry_live(&state->global_entries[idx])) return HUB_MODES_NOT_FOUND;
  const config_entry_t *e = &state->global_entries[idx];
  char c[MAX_CHAN], m[BAN_MASK_MAX + 1], value[B_LINE_MAX + 64];
  entry_field(e, 0, c, sizeof(c));
  entry_field(e, 1, m, sizeof(m));
  snprintf(value, sizeof(value), "%s|%s|0||||del", c, m);
  time_t ts = hub_lww_next_ts(e->timestamp);
  if (!hub_storage_put_record(state, "B", value, ts)) return HUB_MODES_NOT_FOUND;
  announce_record(state, "B", value, ts);
  return HUB_MODES_OK;
}

static int ban_cmp_ts(const void *a, const void *b) {
  const hub_ban_t *x = a, *y = b;
  return x->ts < y->ts ? -1 : x->ts > y->ts ? 1 : strcmp(x->mask, y->mask);
}

int hub_ban_list(const hub_state_t *state, const char *chan, hub_ban_t *out, int max) {
  int n = 0;
  for (int i = 0; i < state->global_entry_count && n < max; i++) {
    const config_entry_t *e = &state->global_entries[i];
    if (strcmp(e->key, "B") != 0 || !entry_live(e)) continue;
    hub_ban_t *b = &out[n];
    char ex[16];
    entry_field(e, 0, b->chan, sizeof(b->chan));
    if (chan && !hub_ascii_ieq(b->chan, chan)) continue;
    entry_field(e, 1, b->mask, sizeof(b->mask));
    entry_field(e, 2, ex, sizeof(ex));
    b->expires = (time_t)atoll(ex);
    entry_field(e, 3, b->flags, sizeof(b->flags));
    entry_field(e, 4, b->setter, sizeof(b->setter));
    ban_reason(e, b->reason, sizeof(b->reason));
    b->ts = e->timestamp;
    b->last_used = e->last_used;
    n++;
  }
  if (n > 1) qsort(out, (size_t)n, sizeof(out[0]), ban_cmp_ts);
  return n;
}

time_t *hub_ban_used_slot(hub_state_t *state, const char *chan, const char *mask) {
  int i = ban_find(state, chan, mask);
  if (i < 0 || !entry_live(&state->global_entries[i])) return NULL;
  return &state->global_entries[i].last_used;
}

/* Effective bantime of `chan` in minutes (0 = permanent). */
static long chan_bantime(const hub_state_t *state, const char *chan) {
  char v[16];
  long m = BANTIME_DEFAULT_MIN;
  hub_setting_effective(state, chan, "bantime", v, sizeof(v));
  parse_num(v, &m);
  return m;
}

bool hub_ban_bot_write(hub_state_t *state, const char *bot_uuid, const char *value,
                       time_t ts) {
  time_t now = time(NULL);
  if (!bot_uuid || !value || ts <= 0 || ts > now + 300) return false;
  if (frozen(state) || !hub_record_valid("B", value)) return false;

  config_entry_t probe;  /* parse the fields with the entry helpers */
  snprintf(probe.key, sizeof(probe.key), "B");
  snprintf(probe.value, sizeof(probe.value), "%s", value);
  char chan[MAX_CHAN], mask[BAN_MASK_MAX + 1], ex[16], flags[8], setter[BAN_SETTER_MAX],
      op[8];
  entry_field(&probe, 0, chan, sizeof(chan));
  entry_field(&probe, 1, mask, sizeof(mask));
  entry_field(&probe, 2, ex, sizeof(ex));
  entry_field(&probe, 3, flags, sizeof(flags));
  entry_field(&probe, 4, setter, sizeof(setter));
  {
    const char *lp = strrchr(probe.value, '|');
    snprintf(op, sizeof(op), "%s", lp ? lp + 1 : "");
  }

  /* A bot bans in one channel the hub manages, and signs its own bans. */
  if (chan[0] == '*' || !hub_chan_live(state, chan, NULL, 0)) return false;
  if (strcmp(setter, bot_uuid) != 0) return false;

  int idx = ban_find(state, chan, mask);
  if (strcmp(op, "del") == 0) {
    /* Only a ban this bot wrote, and only while it is live. */
    if (idx < 0 || !entry_live(&state->global_entries[idx])) return false;
    char stored[BAN_SETTER_MAX];
    entry_field(&state->global_entries[idx], 4, stored, sizeof(stored));
    if (strcmp(stored, bot_uuid) != 0) return false;
    return hub_storage_put_record(state, "B", value, ts);
  }

  /* add: timed, no longer than the channel's bantime (+ slack), not sticky,
   * and never over an admin's (or another bot's) live ban. */
  long long expires = atoll(ex);
  if (expires <= (long long)now || flags[0]) return false;
  long bt = chan_bantime(state, chan);
  long long cap_s = (bt > 0 ? (long long)bt : 525600LL) * 60 + BAN_BOT_SLACK;
  if (expires - (long long)now > cap_s) return false;
  if (idx >= 0 && entry_live(&state->global_entries[idx])) {
    char stored[BAN_SETTER_MAX];
    entry_field(&state->global_entries[idx], 4, stored, sizeof(stored));
    if (strcmp(stored, bot_uuid) != 0) return false;
  }
  /* Never over a trusted bot's or an admin's / oper's own mask. */
  if (hub_ban_protected(state, mask, NULL, 0) != HUB_MODES_OK) {
    hub_log_warning("[BANS] ban %s in %s from %s refused (protected mask)\n", mask,
                    chan, hub_who(state, 'b', bot_uuid));
    return false;
  }
  /* A bot holds at most BOT_BANS_PER_CHAN live bans per channel; renewing its
   * own live ban takes no new place. */
  if (idx < 0 || !entry_live(&state->global_entries[idx])) {
    int mine = 0;
    for (int i = 0; i < state->global_entry_count; i++) {
      const config_entry_t *e = &state->global_entries[i];
      char c[MAX_CHAN], st[BAN_SETTER_MAX];
      if (strcmp(e->key, "B") != 0 || !entry_live(e)) continue;
      entry_field(e, 0, c, sizeof(c));
      entry_field(e, 4, st, sizeof(st));
      if (hub_ascii_ieq(c, chan) && strcmp(st, bot_uuid) == 0) mine++;
    }
    if (mine >= BOT_BANS_PER_CHAN) {
      hub_log_warning("[BANS] ban in %s from %s refused (%d live bans)\n", chan,
                      hub_who(state, 'b', bot_uuid), mine);
      return false;
    }
  }
  return hub_storage_put_record(state, "B", value, ts);
}

void hub_bans_sweep(hub_state_t *state, time_t now) {
  static time_t last = 0;
  if (last != 0 && now - last < BAN_SWEEP_INTERVAL) return;
  last = now;
  if (frozen(state)) return;
  char out[8192];
  size_t off = 0;
  int swept = 0;
  for (int i = 0; i < state->global_entry_count; i++) {
    const config_entry_t *e = &state->global_entries[i];
    char ex[16];
    if (strcmp(e->key, "B") != 0 || !entry_live(e)) continue;
    entry_field(e, 2, ex, sizeof(ex));
    time_t expires = (time_t)atoll(ex);
    if (expires <= 0 || expires > now) continue;
    char c[MAX_CHAN], m[BAN_MASK_MAX + 1], value[B_LINE_MAX + 64];
    entry_field(e, 0, c, sizeof(c));
    entry_field(e, 1, m, sizeof(m));
    snprintf(value, sizeof(value), "%s|%s|0||||del", c, m);
    /* One second past the record's own stamp: every hub sweeping the same ban
     * writes the same tombstone at the same stamp, so they agree without
     * talking, and any newer edit (an extension made on another hub) wins. */
    time_t ts = hub_ts_add(e->timestamp, 1);
    if (!hub_storage_put_record(state, "B", value, ts)) continue;
    swept++;
    int w = snprintf(out + off, sizeof(out) - off, "B|%s|%ld\n", value, (long)ts);
    if (w > 0 && (size_t)w < sizeof(out) - off) {
      off += (size_t)w;
    } else {
      out[off] = '\0'; /* drop the cut-off line: send complete lines only */
      if (off) hub_broadcast_sync_to_peers(state, out, -1);
      w = snprintf(out, sizeof(out), "B|%s|%ld\n", value, (long)ts);
      off = w > 0 ? (size_t)w : 0;
    }
  }
  if (off) hub_broadcast_sync_to_peers(state, out, -1);
  if (swept) {
    hub_log_info("[BANS] %d expired ban(s) removed\n", swept);
    state->config_dirty = true;
    state->bot_config_pending = true;
  }
}

/* ---- CMD_CHAN_EVENT (D42) --------------------------------------------------- */

static bool event_action_ok(const char *a) {
  static const char *const ok[] = {"deop", "reop", "kick", "ban", "unban",
                                   "moderevert", "limit", "floodtrip", "ignore"};
  for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++)
    if (strcmp(a, ok[i]) == 0) return true;
  return false;
}

static bool no_ctrl(const char *s) {
  for (; *s; s++)
    if ((unsigned char)*s < 0x20 || *s == 0x7f) return false;
  return true;
}

void hub_chan_event_receive(hub_state_t *state, hub_client_t *client,
                            const char *payload) {
  if (!client || client->type != CLIENT_BOT || !client->authenticated || !payload) return;
  time_t now = time(NULL);
  if (now - client->chan_ev_window >= CHAN_EVENT_WINDOW) {
    if (client->chan_ev_dropped > 0)
      hub_log_debug("[CHAN] %d event(s) from %s dropped (rate limit)\n",
                    client->chan_ev_dropped, hub_who_client(state, client));
    client->chan_ev_window = now;
    client->chan_ev_count = 0;
    client->chan_ev_dropped = 0;
  }
  /* Every event received counts, valid or not: junk must not be free. */
  if (client->chan_ev_count >= CHAN_EVENT_MAX_PER_WINDOW) {
    client->chan_ev_dropped++;
    return;
  }
  client->chan_ev_count++;

  /* #chan|action|target|detail -- detail is the tail and may hold '|'. */
  char buf[MAX_CHAN + 16 + CHAN_EVENT_TARGET_MAX + CHAN_EVENT_DETAIL_MAX + 8];
  size_t n = strlen(payload);
  if (n >= sizeof(buf)) {
    hub_log_debug("[CHAN] oversize event from %s dropped\n", hub_who_client(state, client));
    return;
  }
  memcpy(buf, payload, n + 1);
  char *chan = buf, *action = NULL, *target = NULL, *detail = NULL;
  char *p = strchr(chan, '|');
  if (p) { *p = '\0'; action = p + 1; p = strchr(action, '|'); }
  if (p) { *p = '\0'; target = p + 1; p = strchr(target, '|'); }
  if (p) { *p = '\0'; detail = p + 1; }
  if (!detail || !chan_name_shape(chan) || !event_action_ok(action) || !target[0] ||
      strlen(target) > CHAN_EVENT_TARGET_MAX || strlen(detail) > CHAN_EVENT_DETAIL_MAX ||
      !no_ctrl(target) || !no_ctrl(detail)) {
    hub_log_debug("[CHAN] malformed event from %s dropped\n", hub_who_client(state, client));
    return;
  }
  hub_log_info("[CHAN] chan %s %s %s by %s: %s\n", chan, action, target,
               hub_who_client(state, client), detail);
}
