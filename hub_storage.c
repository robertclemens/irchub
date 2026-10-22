#include "hub.h"
#include <ctype.h>

#include <strings.h>

void hub_storage_init(void) {}

static bot_config_t *get_or_create_bot(hub_state_t *state, const char *uuid) {
  for (int i = 0; i < state->bot_count; i++) {
    if (strcmp(state->bots[i].uuid, uuid) == 0) {
      return &state->bots[i];
    }
  }

  if (state->bot_count < MAX_BOTS) {
    bot_config_t *b = &state->bots[state->bot_count++];
    memset(b, 0, sizeof(bot_config_t));
    snprintf(b->uuid, sizeof(b->uuid), "%s", uuid);
    b->is_active = true;
    return b;
  }

  return NULL;
}

/* ASCII-only fold: a locale must never change which channel or mask a name
 * is (D39).  Non-ASCII bytes compare as they are. */
static unsigned char afold(unsigned char c) {
  return (c >= 'A' && c <= 'Z') ? (unsigned char)(c + 32) : c;
}

bool hub_ascii_ieq(const char *a, const char *b) {
  if (!a || !b) return false;
  for (; *a && *b; a++, b++)
    if (afold((unsigned char)*a) != afold((unsigned char)*b)) return false;
  return *a == *b;
}

/* A bot's hl| value: up to HL_ENTRIES_MAX comma-separated "<addr>/<fp>",
 * <addr> empty or 1..HL_ADDR_MAX bytes of [A-Za-z0-9.:_[]-], <fp> exactly
 * HL_FP_LEN lowercase hex.  "" (a bot with no keyed hub) is valid. */
bool hub_hublist_valid(const char *v) {
  if (!v) return false;
  if (!v[0]) return true;
  int n = 0;
  for (const char *p = v;;) {
    if (++n > HL_ENTRIES_MAX) return false;
    const char *slash = strchr(p, '/');
    const char *end = strchr(p, ',');
    if (!end) end = p + strlen(p);
    if (!slash || slash > end || (size_t)(slash - p) > HL_ADDR_MAX ||
        end - slash - 1 != HL_FP_LEN)
      return false;
    for (const char *q = p; q < slash; q++)
      if (!isalnum((unsigned char)*q) && !strchr(".:_[]-", *q)) return false;
    for (const char *q = slash + 1; q < end; q++)
      if (!isdigit((unsigned char)*q) && (*q < 'a' || *q > 'f')) return false;
    if (!*end) return true;
    p = end + 1;
  }
}

/* Record kinds that live in global_entries[] beside c|/m|/o|. */
static bool key_is_modes(const char *key) {
  return key[0] && !key[1] && (key[0] == 'C' || key[0] == 'D' || key[0] == 'B');
}

/* Length of a value's identity prefix: the channel (c|, C|), channel|mask
 * (B|), else the first field. */
static size_t ident_len(const char *key, const char *v) {
  int fields = (key[0] == 'B' && !key[1]) ? 2 : 1;
  const char *p = v;
  for (int f = 0; f < fields; f++) {
    const char *bar = strchr(p, '|');
    if (!bar) return strlen(v);
    if (f == fields - 1) return (size_t)(bar - v);
    p = bar + 1;
  }
  return strlen(v);
}

/* ---- index and counts over global_entries[] -------------------------------
 * global_idx[]: open-addressing hash (entry index + 1, 0 = free) keyed on the
 * class and the folded identity -- the equality hub_global_identity_eq
 * defines -- so hub_global_find is O(1).  Entries only disappear in bulk
 * (evict, purge), which rebuild it; an insert adds one slot.
 * global_n_*: entries per class; global_ban_chan[]: live bans per channel
 * (rep = a B entry naming the channel, compared with entry_chan_eq). */
static bool key_singleton(const char *key) {
  return strcmp(key, "a") == 0 || strcmp(key, "p") == 0 || strcmp(key, "D") == 0;
}

static bool key_ci(const char *key) {
  return strcmp(key, "c") == 0 || strcmp(key, "C") == 0 || strcmp(key, "B") == 0;
}

static uint32_t fnv_step(uint32_t h, unsigned char c) { return (h ^ c) * 16777619u; }

static uint32_t gkey_hash(const char *key, const char *value) {
  uint32_t h = 2166136261u;
  for (const char *k = key; *k; k++) h = fnv_step(h, (unsigned char)*k);
  h = fnv_step(h, 0xff);
  if (key_singleton(key)) return h;
  size_t n = ident_len(key, value);
  bool ci = key_ci(key);
  for (size_t i = 0; i < n; i++)
    h = fnv_step(h, ci ? afold((unsigned char)value[i]) : (unsigned char)value[i]);
  return h;
}

bool hub_global_identity_eq(const char *key, const char *a, const char *b) {
  if (!key || !a || !b) return false;
  /* Singletons: a|, p|, D| -- one record per key. */
  if (key_singleton(key)) return true;
  size_t la = ident_len(key, a), lb = ident_len(key, b);
  if (la != lb) return false;
  bool ci = key_ci(key);
  for (size_t i = 0; i < la; i++) {
    unsigned char x = (unsigned char)a[i], y = (unsigned char)b[i];
    if (ci ? afold(x) != afold(y) : x != y) return false;
  }
  return true;
}

/* Slot holding the entry that (key, value) addresses, or the free slot where
 * it would go.  The table never fills (load <= 0.5). */
static uint32_t gidx_pos(const hub_state_t *state, const char *key, const char *value) {
  uint32_t p = gkey_hash(key, value) % GLOBAL_IDX_SLOTS;
  for (;; p = (p + 1) % GLOBAL_IDX_SLOTS) {
    int v = state->global_idx[p];
    if (!v) return p;
    const config_entry_t *e = &state->global_entries[v - 1];
    if (strcmp(e->key, key) == 0 && hub_global_identity_eq(key, e->value, value))
      return p;
  }
}

/* Index of the stored global entry that `value` under `key` addresses
 * (a|/p|/D| are singletons; the rest match on their identity prefix,
 * channel and ban mask ASCII case-insensitively).  -1 if none. */
int hub_global_find(const hub_state_t *state, const char *key, const char *value) {
  return state->global_idx[gidx_pos(state, key, value)] - 1;
}

static bool entry_chan_eq(const config_entry_t *e, const char *chan);

/* Slot of channel `chan` in global_ban_chan[]: its own, or the free one. */
static uint32_t gban_pos(const hub_state_t *state, const char *chan) {
  uint32_t h = 2166136261u;
  for (const char *c = chan; *c; c++) h = fnv_step(h, afold((unsigned char)*c));
  uint32_t p = h % GLOBAL_IDX_SLOTS;
  for (;; p = (p + 1) % GLOBAL_IDX_SLOTS) {
    int rep = state->global_ban_chan[p].rep;
    if (!rep || entry_chan_eq(&state->global_entries[rep - 1], chan)) return p;
  }
}

/* The ban in entry i went live (d = 1) or was deleted (d = -1). */
static void gban_adjust(hub_state_t *state, int i, int d) {
  char chan[MAX_CHAN];
  const char *v = state->global_entries[i].value;
  size_t cl = strcspn(v, "|");
  if (cl >= sizeof(chan)) return;
  memcpy(chan, v, cl);
  chan[cl] = '\0';
  global_ban_slot_t *g = &state->global_ban_chan[gban_pos(state, chan)];
  if (!g->rep) g->rep = i + 1;
  g->live += d;
}

void hub_global_note_new(hub_state_t *state, int i) {
  const config_entry_t *e = &state->global_entries[i];
  uint32_t p = gidx_pos(state, e->key, e->value);
  if (!state->global_idx[p]) state->global_idx[p] = i + 1;  /* a duplicate keeps the first */
  if (key_is_modes(e->key)) {
    if (e->key[0] == 'C') state->global_n_C++;
    else if (e->key[0] == 'D') state->global_n_D++;
    else state->global_n_B++;
  } else {
    state->global_n_old++;
  }
  if (e->key[0] == 'B' && !e->key[1] && hub_global_value_active(e->value))
    gban_adjust(state, i, 1);
}

void hub_global_reindex(hub_state_t *state) {
  memset(state->global_idx, 0, sizeof(state->global_idx));
  memset(state->global_ban_chan, 0, sizeof(state->global_ban_chan));
  state->global_n_old = state->global_n_C = state->global_n_D = state->global_n_B = 0;
  for (int i = 0; i < state->global_entry_count; i++) hub_global_note_new(state, i);
}

static int global_entry_find(const hub_state_t *state, const char *key,
                             const char *value) {
  return hub_global_find(state, key, value);
}

/* Room for one more entry of `key`'s class: the old c/m/o rows share
 * MAX_BOT_ENTRIES, C| has MAX_CHANNELS, D| one, B| MAX_BANS_TOTAL. */
static bool global_room(const hub_state_t *state, const char *key) {
  int n, cap;
  if (key_is_modes(key)) {
    n = key[0] == 'C' ? state->global_n_C
        : key[0] == 'D' ? state->global_n_D : state->global_n_B;
    cap = key[0] == 'C' ? MAX_CHANNELS : key[0] == 'D' ? 1 : MAX_BANS_TOTAL;
  } else {
    n = state->global_n_old;
    cap = MAX_BOT_ENTRIES;
  }
  return n < cap && state->global_entry_count < MAX_GLOBAL_ENTRIES;
}

bool hub_global_room(const hub_state_t *state, const char *key) {
  return global_room(state, key);
}

time_t hub_storage_global_ts(const hub_state_t *state, const char *key,
                             const char *value) {
  int i = global_entry_find(state, key, value);
  return i >= 0 ? state->global_entries[i].timestamp : 0;
}

// Global Storage Update
bool hub_storage_update_global_entry(hub_state_t *state, const char *key,
                                     const char *value, const char *extra,
                                     const char *op, time_t ts) {
  char combined_value[1024];

  /* C|, D| and B| carry their own op and field set: they go through
   * hub_storage_put_record, never through this c/m/o composer. */
  if (key_is_modes(key)) {
    hub_log_warning("[STORAGE] Global %s: not a c/m/o record (use put_record)\n", key);
    return false;
  }

  /* A channel already stored keeps its first writer's spelling (D39). */
  char stored_chan[MAX_CHAN + 8];
  int found_idx = global_entry_find(state, key, value);
  if (found_idx >= 0 && strcmp(key, "c") == 0) {
    size_t n = strcspn(state->global_entries[found_idx].value, "|");
    if (n >= sizeof(stored_chan)) n = sizeof(stored_chan) - 1;
    memcpy(stored_chan, state->global_entries[found_idx].value, n);
    stored_chan[n] = 0;
    value = stored_chan;
  }

  // Sanitize op parameter - strip leading and trailing pipes from malformed input
  char clean_op[16] = "";
  if (op) {
    snprintf(clean_op, sizeof(clean_op), "%s", op);
    // Strip leading pipes
    char *op_start = clean_op;
    while (*op_start == '|') {
      op_start++;
    }
    // Strip trailing pipes
    char *op_end = op_start + strlen(op_start);
    while (op_end > op_start && *(op_end - 1) == '|') {
      *(--op_end) = '\0';
    }
    // Move cleaned string to beginning if needed
    if (op_start != clean_op && *op_start) {
      memmove(clean_op, op_start, strlen(op_start) + 1);
    } else if (!*op_start) {
      clean_op[0] = '\0';
    }
  }
  const char *safe_op = clean_op[0] ? clean_op : "add";

  // Format value based on key type
  if (strcmp(key, "c") == 0) {
    if (extra && extra[0])
      snprintf(combined_value, sizeof(combined_value), "%s|%s|%s", value, extra,
               safe_op);
    else
      snprintf(combined_value, sizeof(combined_value), "%s||%s", value,
               safe_op);
  } else if (strcmp(key, "m") == 0) {
    snprintf(combined_value, sizeof(combined_value), "%s|%s", value,
             safe_op);
  } else if (strcmp(key, "o") == 0) {
    /* Legacy global oper mask: the password slot is always stored empty.
     * Oper passwords are retired; one arriving from an old config, an old
     * peer or an old admin client must not be kept, synced or listed. */
    (void)extra;
    snprintf(combined_value, sizeof(combined_value), "%s||%s", value, safe_op);
  } else {
    snprintf(combined_value, sizeof(combined_value), "%s", value);
  }

  int i = found_idx;
  if (i >= 0) {
    if (hub_lww_accepts(ts, hub_global_value_active(combined_value),
                        state->global_entries[i].timestamp,
                        hub_global_value_active(state->global_entries[i].value))) {
      hub_log_debug("[STORAGE] Global %s=%s: incoming_ts=%ld %s stored_ts=%ld -> UPDATED\n",
              key, value, (long)ts,
              ts > state->global_entries[i].timestamp ? ">" : "== (del beats add)",
              (long)state->global_entries[i].timestamp);
      size_t len = strlen(combined_value);
      if (len >= sizeof(state->global_entries[i].value))
        len = sizeof(state->global_entries[i].value) - 1;
      memcpy(state->global_entries[i].value, combined_value, len);
      state->global_entries[i].value[len] = 0;
      state->global_entries[i].timestamp = ts;
      /* A channel removed takes its settings and bans with it, at the same
       * stamp, on every hub (an older hub's c| del carries no C|/B| dels). */
      if (strcmp(key, "c") == 0 && !hub_global_value_active(combined_value))
        hub_chan_cascade_del(state, value, ts, false);
      return true;
    }
    hub_log_debug("[STORAGE] Global %s=%s: incoming_ts=%ld <= stored_ts=%ld -> REJECTED\n",
            key, value, (long)ts, (long)state->global_entries[i].timestamp);
    return false;
  }

  if (!hub_global_value_active(combined_value) && hub_purge_floor_blocks(state, ts)) {
    hub_log_debug("[STORAGE] Global %s=%s: tombstone ts=%ld older than the last purge: "
                  "not re-created\n", key, value, (long)ts);
    return false;
  }
  if (global_room(state, key)) {
    hub_log_debug("[STORAGE] Global %s=%s: NEW entry ts=%ld\n", key, value, (long)ts);
    config_entry_t *e = &state->global_entries[state->global_entry_count++];
    snprintf(e->key, sizeof(e->key), "%s", key);
    size_t len = strlen(combined_value);
    if (len >= sizeof(e->value))
      len = sizeof(e->value) - 1;
    memcpy(e->value, combined_value, len);
    e->value[len] = 0;
    e->timestamp = ts;
    hub_global_note_new(state, state->global_entry_count - 1);
    return true;
  }
  hub_log_warning("[STORAGE] Global %s=%s: REJECTED (max entries reached)\n", key, value);
  return false;
}

/* nick!user@host, three non-empty parts, printable ASCII, no '*' or '?'. */
static bool hostmask_literal(const char *h) {
  const char *bang = strchr(h, '!'), *at = bang ? strchr(bang + 1, '@') : NULL;
  if (!bang || !at || bang == h || at == bang + 1 || !at[1]) return false;
  if (strchr(at + 1, '!') || strchr(at + 1, '@')) return false;
  for (const char *p = h; *p; p++) {
    unsigned char c = (unsigned char)*p;
    if (c <= 0x20 || c >= 0x7f || c == '*' || c == '?' || c == '|') return false;
  }
  return true;
}

// Core Logic: Add/Update Entry
static bool storage_update_entry(hub_state_t *state, const char *uuid,
                                 const char *key, const char *value,
                                 const char *extra, const char *op, time_t ts);

/* A revoked uuid never comes back: no record is created for it but its
 * tombstone, and one that exists stays deleted.  A bot that becomes deleted
 * with a key on file joins the revoke list (hub_revoke.c). */
bool hub_storage_update_entry(hub_state_t *state, const char *uuid,
                              const char *key, const char *value,
                              const char *extra, const char *op, time_t ts) {
  bool per_bot = strcmp(key, "d") == 0 || strcmp(key, "pub") == 0 ||
                 strcmp(key, "n") == 0 || strcmp(key, "h") == 0 ||
                 strcmp(key, "t") == 0 || strcmp(key, "seen") == 0;
  bot_config_t *b = NULL;
  if (per_bot && hub_revoke_find(state, uuid)) {
    for (int i = 0; i < state->bot_count && !b; i++)
      if (strcmp(state->bots[i].uuid, uuid) == 0) b = &state->bots[i];
    if (!b && strcmp(key, "d") != 0) return false;
  }
  /* A deleted bot purged here is not re-created from a sync built before the
   * purge (a revoked one can only come back through its d entry). */
  if (strcmp(key, "d") == 0 && value && strcmp(value, "1") == 0 &&
      hub_purge_floor_blocks(state, ts)) {
    bool known = false;
    for (int i = 0; i < state->bot_count && !known; i++)
      known = strcmp(state->bots[i].uuid, uuid) == 0;
    if (!known) return false;
  }
  bool ok = storage_update_entry(state, uuid, key, value, extra, op, ts);
  if (!ok || !per_bot) return ok;
  if (!b)
    for (int i = 0; i < state->bot_count && !b; i++)
      if (strcmp(state->bots[i].uuid, uuid) == 0) b = &state->bots[i];
  if (!b) return ok;
  if (hub_revoke_find(state, uuid)) b->is_active = false;
  if (!b->is_active && (strcmp(key, "d") == 0 || strcmp(key, "pub") == 0 ||
                        strcmp(key, "n") == 0))
    hub_revoke_from_bot(state, b);
  return ok;
}

static bool storage_update_entry(hub_state_t *state, const char *uuid,
                                 const char *key, const char *value,
                                 const char *extra, const char *op, time_t ts) {

  /* Keys no writer may store as plain entries, whichever path (delta,
   * push, sync, load) offers them. */
  if (strcmp(key, "p") == 0 || strcmp(key, "a") == 0) {
    hub_log_warning("[STORAGE] REJECTED unknown key '%s'\n", key);
    return false;
  }

  /* C|, D|, B| are global records with their own writers and checks; a
   * per-bot delta or sync line under those keys is never one of them. */
  if (key_is_modes(key)) {
    hub_log_warning("[STORAGE] REJECTED key '%s' on the per-bot path\n", key);
    return false;
  }

  // [MODIFIED] Global keys intercept
  if (strcmp(key, "c") == 0 || strcmp(key, "m") == 0 || strcmp(key, "o") == 0) {
    return hub_storage_update_global_entry(state, key, value, extra, op, ts);
  }

  // CRITICAL: Reject invalid bot-specific keys being used as UUIDs
  // "n", "h", "seen", "pub", "d", "t" should never be UUIDs
  if (strcmp(uuid, "n") == 0 || strcmp(uuid, "h") == 0 ||
      strcmp(uuid, "seen") == 0 || strcmp(uuid, "pub") == 0 ||
      strcmp(uuid, "d") == 0 || strcmp(uuid, "t") == 0) {
    hub_log_warning("[STORAGE] REJECTED: Invalid UUID '%s' (bot-specific key used as UUID)\n", uuid);
    return false;
  }

  bot_config_t *b = get_or_create_bot(state, uuid);
  if (!b)
    return false;

  /* Change 3b — zero-trust per-bot ingest bound (single enforcement point for
   * the delta path, config-push, peer-sync, and config load).  Global keys
   * (c/m/o/a/p) were already intercepted above.  A bot's per-bot state is
   * exactly {t, n, h, pub, seen, d}; reject any other key so a hostile bot or
   * peer cannot create arbitrarily-named entries and unbound the sync payload.
   * This is what makes BOT_SYNC_FIELDS a hard bound (see hub.h). Value length
   * is capped per key so a per-bot line can never approach value[1024]. */
  if (strcmp(key, "t") != 0 && strcmp(key, "n") != 0 &&
      strcmp(key, "h") != 0 && strcmp(key, "pub") != 0 &&
      strcmp(key, "seen") != 0 && strcmp(key, "d") != 0 &&
      strcmp(key, "hl") != 0) {
    hub_log_warning("[STORAGE] REJECTED per-bot key '%s' for %s (not in whitelist)\n",
            key, uuid);
    return false;
  }
  {
    size_t vlen = value ? strlen(value) : 0;
    size_t cap = 0;
    if      (strcmp(key, "h") == 0)   cap = MAX_MASK_LEN - 1;
    else if (strcmp(key, "n") == 0)   cap = MAX_NICK - 1;
    else if (strcmp(key, "pub") == 0) cap = COMBINED_KEY_B64;
    else if (strcmp(key, "hl") == 0)  cap = HL_VALUE_MAX;
    else                              cap = 31; /* seen/d/t: short numerics */
    if (vlen > cap) {
      hub_log_warning("[STORAGE] REJECTED per-bot '%s' for %s: value too long "
              "(%zu > %zu)\n", key, uuid, vlen, cap);
      return false;
    }
    if (strcmp(key, "hl") == 0 && !hub_hublist_valid(value)) {
      hub_log_warning("[STORAGE] REJECTED per-bot 'hl' for %s: not a hub list\n", uuid);
      return false;
    }
  }

  /* A reported hostmask is a literal nick!user@host, never a pattern: the ban
   * protection matches bans against it, so a '*' here would shield everyone. */
  if (strcmp(key, "h") == 0 && value && value[0] && !hostmask_literal(value)) {
    hub_log_warning("[STORAGE] REJECTED per-bot 'h' for %s: not a literal "
            "nick!user@host\n", uuid);
    return false;
  }

  // Special Metadata: Sync Timestamp
  if (strcmp(key, "t") == 0) {
    if (ts > b->last_sync_time) {
      b->last_sync_time = ts;
      return true;
    }
    return false;
  }

  // Build combined value for storage
  // Format depends on type:
  // c| → "chan_name|key|add" or "chan_name||del"
  // m| → "mask|add" or "mask|del"
  // o| → "mask|password|add" or "mask|password|del"
  // a|, p|, h| → just the value (no op)

  char combined_value[1024];

  // Sanitize op parameter - strip leading and trailing pipes from malformed input
  char clean_op[16] = "";
  if (op) {
    snprintf(clean_op, sizeof(clean_op), "%s", op);
    // Strip leading pipes
    char *op_start = clean_op;
    while (*op_start == '|') {
      op_start++;
    }
    // Strip trailing pipes
    char *op_end = op_start + strlen(op_start);
    while (op_end > op_start && *(op_end - 1) == '|') {
      *(--op_end) = '\0';
    }
    // Move cleaned string to beginning if needed
    if (op_start != clean_op && *op_start) {
      memmove(clean_op, op_start, strlen(op_start) + 1);
    } else if (!*op_start) {
      clean_op[0] = '\0';
    }
  }
  const char *safe_op = clean_op[0] ? clean_op : "add";

  if (strcmp(key, "c") == 0) {
    // Channel: value|extra|op
    if (extra && extra[0]) {
      snprintf(combined_value, sizeof(combined_value), "%s|%s|%s", value, extra,
               safe_op);
    } else {
      snprintf(combined_value, sizeof(combined_value), "%s||%s", value,
               safe_op);
    }
  } else if (strcmp(key, "m") == 0) {
    // Mask: value|op
    snprintf(combined_value, sizeof(combined_value), "%s|%s", value,
             safe_op);
  } else if (strcmp(key, "o") == 0) {
    // Oper: value|extra|op
    snprintf(combined_value, sizeof(combined_value), "%s|%s|%s", value,
             extra ? extra : "", safe_op);
  } else {
    // Simple value (a, p, h)
    snprintf(combined_value, sizeof(combined_value), "%s", value);
  }

  // Determine Type: Singleton or List
  bool is_singleton = (strcmp(key, "n") == 0 || strcmp(key, "a") == 0 ||
                       strcmp(key, "p") == 0 || strcmp(key, "h") == 0 ||
                       strcmp(key, "d") == 0 || strcmp(key, "pub") == 0 ||
                       strcmp(key, "seen") == 0);

  /* is_active follows the 'd' entry alone.  An 'n' or 's' entry used to set
   * it back to true ("auto-undelete on check-in"): a peer still holding a
   * deleted bot's nick, or a config reload that read 'n' after 'd|1',
   * re-registered the bot.  A deleted bot cannot check in (auth needs
   * is_active), so nothing legitimate depended on it. */

  // Check for existing entry
  for (int i = 0; i < b->entry_count; i++) {
    bool match = false;

    if (is_singleton) {
      if (strcmp(b->entries[i].key, key) == 0) {
        match = true;
      }
    } else {
      // For lists (c, m, o, s), key AND value must match
      // Extract just the first part (before first |) for matching
      char stored_first[256];
      const char *pipe = strchr(b->entries[i].value, '|');
      if (pipe) {
        size_t len = (size_t)(pipe - b->entries[i].value);
        if (len >= sizeof(stored_first))
          len = sizeof(stored_first) - 1;
        memcpy(stored_first, b->entries[i].value, len);
        stored_first[len] = 0;
      } else {
        snprintf(stored_first, sizeof(stored_first), "%.*s",
                 (int)(sizeof(stored_first) - 1), b->entries[i].value);
      }

      if (strcmp(b->entries[i].key, key) == 0 &&
          strcmp(stored_first, value) == 0) {
        match = true;
      }
    }

    if (match) {
      // Timestamp comparison
      if (ts < b->entries[i].timestamp)
        return false;

      if (ts > b->entries[i].timestamp) {
        size_t len = strlen(combined_value);
        if (len >= sizeof(b->entries[i].value))
          len = sizeof(b->entries[i].value) - 1;
        memcpy(b->entries[i].value, combined_value, len);
        b->entries[i].value[len] = 0;
        b->entries[i].timestamp = ts;

        if (strcmp(key, "d") == 0) {
          b->is_active = (strcmp(value, "1") != 0);
        }
        return true;
      }

      /* Same stamp, different value: the byte-wise greater value wins on
       * every node.  "Last arrival wins" swapped two nodes' copies with each
       * other and kept them apart; for 'd' this makes "1" (deleted) beat "0",
       * the same delete-over-add rule as hub_lww_accepts. */
      if (ts == b->entries[i].timestamp) {
        if (strcmp(combined_value, b->entries[i].value) > 0) {
          size_t len = strlen(combined_value);
          if (len >= sizeof(b->entries[i].value))
            len = sizeof(b->entries[i].value) - 1;
          memcpy(b->entries[i].value, combined_value, len);
          b->entries[i].value[len] = 0;

          if (strcmp(key, "d") == 0) {
            b->is_active = (strcmp(value, "1") != 0);
          }
          return true;
        }
      }
      return false;
    }
  }

  // New Entry
  if (b->entry_count < MAX_BOT_ENTRIES) {
    config_entry_t *e = &b->entries[b->entry_count++];
    snprintf(e->key, sizeof(e->key), "%s", key);
    size_t len = strlen(combined_value);
    if (len >= sizeof(e->value))
      len = sizeof(e->value) - 1;
    memcpy(e->value, combined_value, len);
    e->value[len] = 0;
    e->timestamp = ts;

    if (strcmp(key, "d") == 0) {
      b->is_active = (strcmp(value, "1") != 0);
    }

    return true;
  }

  hub_log_warning("[STORAGE] Bot %s has reached MAX_BOT_ENTRIES\n", uuid);
  return false;
}

bool hub_storage_delete(hub_state_t *state, const char *uuid, time_t *ts_out) {
  /* A delete is a d|1 tombstone, the same record every peer stores from the
   * sync line, and the purge removes it later.  It used to remove the bot
   * outright here: this hub then held nothing that outranks a peer still
   * carrying the bot live (a peer that had not yet seen the delete), and
   * that peer's next full sync registered the bot again. */
  bot_config_t *b = NULL;
  for (int i = 0; i < state->bot_count; i++) {
    if (strcmp(state->bots[i].uuid, uuid) == 0) {
      b = &state->bots[i];
      break;
    }
  }
  if (!b || !b->is_active)
    return false;

  time_t prev = 0;
  for (int j = 0; j < b->entry_count; j++) {
    if (strcmp(b->entries[j].key, "d") == 0) {
      prev = b->entries[j].timestamp;
      break;
    }
  }
  time_t ts = hub_lww_next_ts(prev);
  if (!hub_storage_update_entry(state, uuid, "d", "1", "", "", ts) ||
      b->is_active)
    return false;
  if (ts_out)
    *ts_out = ts;
  state->config_dirty = true;
  hub_config_write(state);
  return true;
}


// Generate payload for a specific bot (Global + Bot-specific)
// Does NOT include "b|uuid|" prefix for global items, preserving protocol
// compatibility
void hub_generate_bot_payload(hub_state_t *state, const char *uuid,
                              char *buffer, int max_len) {
  int offset = 0;
  int written;
  buffer[0] = 0;

  // 1. Add Global Entries (channels; skip h/n/a/m/o — now in typed arrays —
  //    and the retired bot password p)
  for (int i = 0; i < state->global_entry_count; i++) {
    config_entry_t *e = &state->global_entries[i];
    if (strcmp(e->key, "h") == 0 || strcmp(e->key, "n") == 0 ||
        strcmp(e->key, "a") == 0 || strcmp(e->key, "m") == 0 ||
        strcmp(e->key, "o") == 0 || strcmp(e->key, "p") == 0) {
      continue;
    }
    written = snprintf(buffer + offset, (size_t)(max_len - offset), "%s|%s|%ld\n", e->key,
                       e->value, (long)e->timestamp);
    if (written < 0 || written >= (max_len - offset))
      break;
    offset += written;
  }
  // K|: what the bots saw on IRC, after the c| lines it hangs off.
  hub_learned_append(state, buffer, max_len, &offset);

  // 1a. Named admin/oper records: uuid|name|pubkey|act|seen|ts|
  for (int i = 0; i < state->user_record_count; i++) {
    hub_user_record_t *u = &state->user_records[i];
    written = hub_format_user_record(u, buffer + offset, (size_t)(max_len - offset));
    if (written < 0 || written >= (max_len - offset)) break;
    offset += written;
  }

  // 1b. Add usermask records (new format: m| lines)
  for (int i = 0; i < state->mask_record_count; i++) {
    hub_mask_record_t *m = &state->mask_records[i];
    written = snprintf(buffer + offset, (size_t)(max_len - offset),
                       "m|%s|%s|%s|%ld|%ld\n",
                       m->uuid, m->mask,
                       m->is_active ? "add" : "del",
                       (long)m->last_used, (long)m->timestamp);
    if (written < 0 || written >= (max_len - offset)) break;
    offset += written;
  }

  // 1b. Admin flags and oper channel bindings, after the users they name.
  hub_access_append(state, buffer, max_len, &offset, NULL, NULL);

  // 1b. Add purge_days setting (allows bots to validate purge policies)
  // Format: pd|<days>|<timestamp>
  time_t now = time(NULL);
  written = snprintf(buffer + offset, (size_t)(max_len - offset), "pd|%d|%ld\n",
                     state->purge_days_setting, (long)now);
  if (written > 0 && written < (max_len - offset)) {
    offset += written;
  }

  // 1c. Push network opt flag string, even when empty, so bots observe a
  // clear.  Capital 'O' for bot wire format.  Only with a real timestamp: a
  // hub that has none (fresh, never synced) must not stamp "no flags" with
  // `now` — bots would take that as newest, drop 'h' and then refuse the
  // network's actual (older) value.
  if (state->opt_flags_ts > 0) {
    written = snprintf(buffer + offset, (size_t)(max_len - offset), "O|%s|%lld\n",
                       state->opt_flags, (long long)state->opt_flags_ts);
    if (written > 0 && written < (max_len - offset)) {
      offset += written;
    }
  }

  // 2. Add Bot-Specific Entries
  // Skip: h, n (hub-only metadata), c, m, o, a, p (now global entries)
  for (int i = 0; i < state->bot_count; i++) {
    if (strcmp(state->bots[i].uuid, uuid) == 0) {
      bot_config_t *b = &state->bots[i];
      for (int j = 0; j < b->entry_count; j++) {
        config_entry_t *e = &b->entries[j];
        // Skip hub-only metadata and global entries
        if (strcmp(e->key, "h") == 0 || strcmp(e->key, "n") == 0 ||
            strcmp(e->key, "c") == 0 || strcmp(e->key, "m") == 0 ||
            strcmp(e->key, "o") == 0 || strcmp(e->key, "a") == 0 ||
            strcmp(e->key, "p") == 0) {
          continue;
        }
        written = snprintf(buffer + offset, (size_t)(max_len - offset), "%s|%s|%ld\n",
                           e->key, e->value, (long)e->timestamp);
        if (written < 0 || written >= (max_len - offset))
          break;
        offset += written;
      }
      break;
    }
  }

  // 3. Add OTHER bots as trusted-bot lines (for offline peer operation):
  //    b|<hostmask>|<uuid>|<pubkey>|<ts>   (pubkey seals ~B2 traffic)
  //    ts = max(hostmask ts, pubkey ts) so a rekey alone is seen as newer.
  //    The list ends with T|<count>: the lines above are the whole trusted
  //    set, so the bot drops every trusted bot they do not name (a deleted or
  //    purged bot).  Without it a revoked bot kept ~B2 and op grants forever.
  int trusted_lines = 0;
  for (int i = 0; i < state->bot_count; i++) {
    if (strcmp(state->bots[i].uuid, uuid) == 0)
      continue; // Skip self
    if (!state->bots[i].is_active)
      continue; // Skip inactive bots

    bot_config_t *b = &state->bots[i];
    const config_entry_t *h = NULL, *pub = NULL;
    for (int j = 0; j < b->entry_count; j++) {
      if (strcmp(b->entries[j].key, "h") == 0) h = &b->entries[j];
      else if (strcmp(b->entries[j].key, "pub") == 0) pub = &b->entries[j];
    }
    if (!h) continue;
    long ts = (long)h->timestamp;
    unsigned char raw[COMBINED_KEY_LEN];
    bool key_ok = pub && hub_crypto_pubkey_b64_decode(pub->value, raw);
    if (key_ok && (long)pub->timestamp > ts) ts = (long)pub->timestamp;
    written = snprintf(buffer + offset, (size_t)(max_len - offset), "b|%s|%s|%s|%ld\n",
                       h->value, b->uuid, key_ok ? pub->value : "", ts);
    if (written < 0 || written >= (max_len - offset))
      break;
    offset += written;
    trusted_lines++;
  }
  written = snprintf(buffer + offset, (size_t)(max_len - offset), "T|%d\n",
                     trusted_lines);
  if (written > 0 && written < (max_len - offset))
    offset += written;
}

/* ==========================================================================
 * C| / D| / B| records (docs/modes.md §2) -- the single ingest point.
 * Stored in global_entries[] as key + value + stamp; the value is the line
 * between the tag and the stamp:
 *   C   chan|modes|settings|op
 *   D   modes|settings                      (no op, never deleted)
 *   B   chan|mask|expires|flags|setter|reason|op
 * Every writer -- console, bot push, peer sync, config load -- ends up in
 * hub_storage_put_record, so the field caps and charsets are enforced once.
 * ========================================================================== */

#define REC_MAX_FIELDS 8

/* Split `value` into exactly `want` '|' separated fields inside buf (cap
 * bytes).  False when it is too long or has another field count. */
static bool rec_split(const char *value, int want, char *buf, size_t cap,
                      char *f[]) {
  size_t n = strlen(value);
  if (n >= cap || want > REC_MAX_FIELDS) return false;
  memcpy(buf, value, n + 1);
  int cnt = 0;
  f[cnt++] = buf;
  for (char *p = buf; *p; p++) {
    if (*p != '|') continue;
    if (cnt >= want) return false;
    *p = '\0';
    f[cnt++] = p + 1;
  }
  return cnt == want;
}

/* A channel name the bots can JOIN (# or &, no blank/comma/control), or "*". */
static bool rec_chan_ok(const char *s, bool star_ok) {
  if (star_ok && s[0] == '*' && !s[1]) return true;
  size_t n = strlen(s);
  if (n < 2 || n >= MAX_CHAN || (s[0] != '#' && s[0] != '&')) return false;
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c <= 0x20 || c == ',' || c == 0x7f || c == '|') return false;
  }
  return true;
}

/* Free text: no control characters (UTF-8 bytes pass), <= max.  A ban
 * reason may hold '|': op and stamp are taken from the END of the line. */
static bool rec_text_ok(const char *s, size_t max) {
  size_t n = strlen(s);
  if (n > max) return false;
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c < 0x20 || c == 0x7f) return false;
  }
  return true;
}

/* A hostmask pattern: printable ASCII, no blank, comma or '|'. */
static bool rec_mask_ok(const char *s) {
  size_t n = strlen(s);
  if (n == 0 || n > BAN_MASK_MAX) return false;
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c <= 0x20 || c >= 0x7f || c == ',' || c == '|') return false;
  }
  return true;
}

static bool rec_modes_ok(const char *s) {
  size_t n = strlen(s);
  if (n > C_MODES_MAX) return false;
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '+' || c == '-' || c == ' '))
      return false;
  }
  return true;
}

/* "name=value,name=value": printable ASCII, no '|', every token has a name
 * and an '='.  Names and values themselves are checked by the console's
 * setting table; unknown ones are kept for forward compatibility. */
static bool rec_settings_ok(const char *s, size_t max) {
  size_t n = strlen(s);
  if (n > max) return false;
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c < 0x20 || c >= 0x7f || c == '|') return false;
  }
  const char *p = s;
  while (*p) {
    const char *end = strchr(p, ',');
    size_t tl = end ? (size_t)(end - p) : strlen(p);
    const char *eq = memchr(p, '=', tl);
    if (tl == 0 || !eq || eq == p) return false;
    p += tl;
    if (*p == ',') p++;
  }
  return true;
}

static bool rec_num_ok(const char *s) {
  size_t n = strlen(s);
  if (n == 0 || n > 11) return false;
  for (size_t i = 0; i < n; i++)
    if (s[i] < '0' || s[i] > '9') return false;
  return true;
}

static bool rec_op_ok(const char *s) {
  return strcmp(s, "add") == 0 || strcmp(s, "del") == 0;
}

bool hub_record_valid(const char *key, const char *value) {
  if (!key || !value) return false;
  char buf[1100];
  char *f[REC_MAX_FIELDS];
  if (strcmp(key, "C") == 0) {
    return rec_split(value, 4, buf, sizeof(buf), f) && rec_chan_ok(f[0], false) &&
           rec_modes_ok(f[1]) && rec_settings_ok(f[2], C_SETTINGS_MAX) &&
           rec_op_ok(f[3]);
  }
  if (strcmp(key, "D") == 0) {
    return rec_split(value, 2, buf, sizeof(buf), f) && rec_modes_ok(f[0]) &&
           rec_settings_ok(f[1], D_SETTINGS_MAX);
  }
  if (strcmp(key, "B") == 0) {
    /* chan|mask|expires|flags|setter|reason|op: the reason is everything
     * between the 5th '|' and the LAST '|' and may contain '|'. */
    const char *last = strrchr(value, '|');
    size_t n = strlen(value);
    if (n >= sizeof(buf) || !last) return false;
    int bars = 0;
    const char *sixth = NULL;
    for (const char *p = value; *p; p++)
      if (*p == '|' && ++bars == 5) { sixth = p; break; }
    if (!sixth || last <= sixth) return false;
    if (!rec_op_ok(last + 1)) return false;
    char head[sizeof(buf)];
    memcpy(head, value, (size_t)(sixth - value));
    head[sixth - value] = '\0';
    if (!rec_split(head, 5, buf, sizeof(buf), f)) return false;
    if (!rec_chan_ok(f[0], true) || !rec_mask_ok(f[1]) || !rec_num_ok(f[2]))
      return false;
    for (const char *p = f[3]; *p; p++)  /* flags: "s" or nothing */
      if (*p != 's' || p - f[3] >= 4) return false;
    size_t sl = strlen(f[4]);
    if (sl >= BAN_SETTER_MAX) return false;
    for (size_t i = 0; i < sl; i++) {
      unsigned char c = (unsigned char)f[4][i];
      if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'))
        return false;
    }
    char reason[BAN_REASON_MAX + 2];
    size_t rl = (size_t)(last - sixth - 1);
    if (rl > BAN_REASON_MAX) return false;
    memcpy(reason, sixth + 1, rl);
    reason[rl] = '\0';
    return rec_text_ok(reason, BAN_REASON_MAX);
  }
  return false;
}

/* LWW for these records: newer stamp wins; on a tie a delete beats an add,
 * and between two of the same kind the byte-wise greater value wins, so every
 * hub picks the same side (docs/modes.md D2; same shape as the opt rule). */
static bool rec_accepts(time_t in_ts, const char *in_val, bool in_active,
                        time_t cur_ts, const char *cur_val, bool cur_active) {
  if (in_ts != cur_ts) return in_ts > cur_ts;
  if (cur_active != in_active) return cur_active && !in_active;
  return strcmp(in_val, cur_val) > 0;
}

/* First field of a stored value equals `chan`, ASCII case-insensitively. */
static bool entry_chan_eq(const config_entry_t *e, const char *chan) {
  size_t n = strcspn(e->value, "|");
  if (strlen(chan) != n) return false;
  for (size_t i = 0; i < n; i++)
    if (afold((unsigned char)e->value[i]) != afold((unsigned char)chan[i]))
      return false;
  return true;
}

static bool entry_active(const config_entry_t *e) {
  return e->key[0] == 'D' ? true : hub_global_value_active(e->value);
}

/* Live (not deleted) bans stored for `chan` ("*" = the global ones). */
static int bans_live_in(const hub_state_t *state, const char *chan) {
  return state->global_ban_chan[gban_pos(state, chan)].live;
}

/* The live-ban ceiling for `chan` ("*" = the global list). */
static int ban_ceiling(const char *chan) {
  if (chan[0] == '*') return MAX_GLOBAL_BANS;
  return MAX_BANS_PER_CHAN;
}

/* Drop the oldest tombstone of class `key` to make room.  One younger than
 * the purge horizon (7 days when purge is off) is never dropped: it may still
 * be the only thing that stops an old add coming back.  False if none. */
static bool evict_oldest_tombstone(hub_state_t *state, const char *key) {
  long keep = state->purge_days_setting > 0 ? (long)state->purge_days_setting * 86400L
                                            : TOMB_MIN_AGE_OFF;
  time_t newest_ok = time(NULL) - keep;
  int best = -1;
  for (int i = 0; i < state->global_entry_count; i++) {
    const config_entry_t *e = &state->global_entries[i];
    if (strcmp(e->key, key) != 0 || entry_active(e) || e->timestamp > newest_ok) continue;
    if (best < 0 || e->timestamp < state->global_entries[best].timestamp) best = i;
  }
  if (best < 0) return false;
  state->global_entries[best] = state->global_entries[--state->global_entry_count];
  hub_global_reindex(state);
  return true;
}

bool hub_storage_put_record(hub_state_t *state, const char *key, const char *value,
                            time_t ts) {
  if (!state || !key || !value || !key_is_modes(key) || ts <= 0) return false;
  if (!hub_record_valid(key, value)) {
    hub_log_warning("[STORAGE] REJECTED malformed %s| record\n", key);
    return false;
  }
  bool in_active = key[0] == 'D' ? true : hub_global_value_active(value);
  int i = hub_global_find(state, key, value);

  if (i >= 0) {
    config_entry_t *e = &state->global_entries[i];
    char norm[sizeof(e->value)];
    if (key[0] == 'D') {
      snprintf(norm, sizeof(norm), "%s", value);
    } else {
      /* The stored channel / mask spelling stays: the first writer's. */
      size_t il = ident_len(key, e->value), vl = ident_len(key, value);
      if (il + strlen(value + vl) >= sizeof(norm)) return false;
      memcpy(norm, e->value, il);
      strcpy(norm + il, value + vl);
    }
    if (!rec_accepts(ts, norm, in_active, e->timestamp, e->value, entry_active(e)))
      return false;
    if (key[0] == 'B' && in_active && !entry_active(e)) {
      /* A deleted ban coming back counts against the ceilings again. */
      char chan[MAX_CHAN];
      size_t cl = strcspn(norm, "|");
      if (cl >= sizeof(chan)) return false;
      memcpy(chan, norm, cl);
      chan[cl] = '\0';
      if (bans_live_in(state, chan) >= ban_ceiling(chan))
        return false;
    }
    bool was_active = entry_active(e);
    memcpy(e->value, norm, strlen(norm) + 1);
    e->timestamp = ts;
    if (key[0] == 'B' && was_active != in_active) gban_adjust(state, i, in_active ? 1 : -1);
    return true;
  }

  if (!in_active && hub_purge_floor_blocks(state, ts)) {
    hub_log_debug("[STORAGE] %s| tombstone ts=%ld older than the last purge: not re-created\n",
                  key, (long)ts);
    return false;
  }
  if (key[0] == 'B' && in_active) {
    char chan[MAX_CHAN];
    size_t cl = strcspn(value, "|");
    if (cl >= sizeof(chan)) return false;
    memcpy(chan, value, cl);
    chan[cl] = '\0';
    if (bans_live_in(state, chan) >= ban_ceiling(chan)) {
      hub_log_warning("[STORAGE] B| for %s REJECTED (ban ceiling)\n", chan);
      return false;
    }
  }
  if (!global_room(state, key) && !(evict_oldest_tombstone(state, key) &&
                                    global_room(state, key))) {
    hub_log_warning("[STORAGE] %s| record REJECTED (max entries reached)\n", key);
    return false;
  }
  config_entry_t *e = &state->global_entries[state->global_entry_count++];
  snprintf(e->key, sizeof(e->key), "%s", key);
  snprintf(e->value, sizeof(e->value), "%s", value);
  e->timestamp = ts;
  e->last_used = 0;
  hub_global_note_new(state, state->global_entry_count - 1);
  return true;
}

bool hub_chan_live(const hub_state_t *state, const char *chan, char *name,
                   size_t cap) {
  int i = chan ? hub_global_find(state, "c", chan) : -1;
  if (i < 0 || !hub_global_value_active(state->global_entries[i].value))
    return false;
  if (name && cap) {
    size_t n = strcspn(state->global_entries[i].value, "|");
    if (n >= cap) n = cap - 1;
    memcpy(name, state->global_entries[i].value, n);
    name[n] = '\0';
  }
  return true;
}

time_t hub_chan_del_stamp(const hub_state_t *state, const char *chan) {
  time_t newest = 0;
  for (int i = 0; i < state->global_entry_count; i++) {
    const config_entry_t *e = &state->global_entries[i];
    bool ours = (strcmp(e->key, "c") == 0 || strcmp(e->key, "C") == 0 ||
                 strcmp(e->key, "B") == 0) && entry_chan_eq(e, chan);
    if (ours && e->timestamp > newest) newest = e->timestamp;
  }
  return hub_lww_next_ts(newest);
}

int hub_chan_cascade_del(hub_state_t *state, const char *chan, time_t ts,
                         bool announce) {
  int changed = 0;
  char out[8192];
  size_t off = 0;
  /* What the bots saw goes with the channel: K| has no tombstone, and every
   * hub drops it on the same c| del. */
  hub_learned_drop(state, chan);
  for (int i = 0; i < state->global_entry_count; i++) {
    config_entry_t *e = &state->global_entries[i];
    char nv[sizeof(e->value)];
    bool is_c = strcmp(e->key, "C") == 0, is_b = strcmp(e->key, "B") == 0;
    if ((!is_c && !is_b) || !entry_active(e) || !entry_chan_eq(e, chan)) continue;
    /* Canonical tombstones: every hub writes the same text for the same stamp. */
    int w = snprintf(nv, sizeof(nv), is_c ? "%.*s|||del" : "%.*s|0||||del",
                     (int)ident_len(e->key, e->value), e->value);
    if (w <= 0 || w >= (int)sizeof(nv)) continue;
    char tag[2] = {e->key[0], 0};
    if (!hub_storage_put_record(state, tag, nv, ts)) continue;
    changed++;
    if (!announce) continue;
    int n = snprintf(out + off, sizeof(out) - off, "%s|%s|%ld\n", tag, nv, (long)ts);
    if (n > 0 && (size_t)n < sizeof(out) - off) {
      off += (size_t)n;
    } else {
      out[off] = '\0'; /* drop the cut-off line: send complete lines only */
      if (off) hub_broadcast_sync_to_peers(state, out, -1);
      off = 0;
      n = snprintf(out, sizeof(out), "%s|%s|%ld\n", tag, nv, (long)ts);
      if (n > 0) off = (size_t)n;
    }
  }
  /* Oper bindings to the channel go too (user_flags plan U6), same stamp:
   * every hub and bot applies the same cascade to the same c| del.  "*" is
   * not a channel and stays. */
  for (int i = 0; i < state->uchan_record_count; i++) {
    hub_uchan_record_t *r = &state->uchan_records[i];
    if (!r->is_active || strcmp(r->chan, "*") == 0 || strcasecmp(r->chan, chan) != 0) continue;
    if (!hub_uchan_put(state, r->uuid, r->chan, false, ts)) continue;
    changed++;
    if (!announce) continue;
    char l[UC_LINE_MAX];
    int n = hub_format_uchan(r, l, sizeof(l));
    if (n <= 0 || n >= (int)sizeof(l)) continue;
    if ((size_t)n >= sizeof(out) - off) {
      out[off] = '\0';
      if (off) hub_broadcast_sync_to_peers(state, out, -1);
      off = 0;
    }
    memcpy(out + off, l, (size_t)n + 1);
    off += (size_t)n;
  }
  if (off) hub_broadcast_sync_to_peers(state, out, -1);
  if (changed) {
    state->config_dirty = true;
    if (announce) state->bot_config_pending = true;
  }
  return changed;
}

/* ---- K|: learned channel state (docs/plans/2026-10-20_learned_state_purge_plan.md)
 * One slot per live channel.  Existence is c|'s alone: a slot is written only
 * while the channel is live and dropped with it, so a bot report that lands
 * after a delete cannot bring the channel back. */
static int learned_index(const hub_state_t *state, const char *chan) {
  for (int i = 0; i < state->chan_learned_count; i++)
    if (strcasecmp(state->chan_learned[i].chan, chan) == 0) return i;
  return -1;
}

const hub_chan_learned_t *hub_learned_find(const hub_state_t *state, const char *chan) {
  int i = chan ? learned_index(state, chan) : -1;
  return i >= 0 ? &state->chan_learned[i] : NULL;
}

static bool learned_key_ok(const char *k) {
  size_t n = strlen(k);
  if (n >= MAX_KEY) return false;
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)k[i];
    if (c <= 0x20 || c == ',' || c == '|' || c >= 0x7f) return false;
  }
  return true;
}

bool hub_learned_put(hub_state_t *state, const char *chan, const char *key, int modes,
                     time_t ts) {
  if (!chan || !key || ts <= 0 || !rec_chan_ok(chan, false) || !learned_key_ok(key) ||
      modes < 0 || (modes & ~K_MODES_MASK))
    return false;
  char name[MAX_CHAN];
  if (!hub_chan_live(state, chan, name, sizeof(name))) return false;
  int i = learned_index(state, name);
  if (i >= 0) {
    hub_chan_learned_t *l = &state->chan_learned[i];
    if (ts < l->ts) return false;
    if (ts == l->ts) {
      char in[MAX_KEY + 16], cur[MAX_KEY + 16];
      snprintf(in, sizeof(in), "%s|%d", key, modes);
      snprintf(cur, sizeof(cur), "%s|%d", l->key, l->modes);
      if (strcmp(in, cur) <= 0) return false;
    }
    snprintf(l->key, sizeof(l->key), "%s", key);
    l->modes = modes;
    l->ts = ts;
    return true;
  }
  if (state->chan_learned_count >= MAX_CHANNELS) return false;
  hub_chan_learned_t *l = &state->chan_learned[state->chan_learned_count++];
  snprintf(l->chan, sizeof(l->chan), "%s", name);
  snprintf(l->key, sizeof(l->key), "%s", key);
  l->modes = modes;
  l->ts = ts;
  return true;
}

bool hub_learned_ingest(hub_state_t *state, const char *body) {
  char buf[K_LINE_MAX];
  if (!body || strlen(body) >= sizeof(buf)) return false;
  snprintf(buf, sizeof(buf), "%s", body);
  char *f[4];
  char *p = buf;
  for (int n = 0; n < 4; n++) {
    f[n] = p;
    char *bar = strchr(p, '|');
    if (n < 3) {
      if (!bar) return false;
      *bar = '\0';
      p = bar + 1;
    } else if (bar) {
      return false;
    }
  }
  if (!rec_num_ok(f[2]) || strlen(f[2]) > 3 || !rec_num_ok(f[3])) return false;
  return hub_learned_put(state, f[0], f[1], atoi(f[2]), (time_t)atoll(f[3]));
}

void hub_learned_drop(hub_state_t *state, const char *chan) {
  int i = chan ? learned_index(state, chan) : -1;
  if (i < 0) return;
  secure_wipe(state->chan_learned[i].key, sizeof(state->chan_learned[i].key));
  state->chan_learned[i] = state->chan_learned[--state->chan_learned_count];
}

int hub_learned_format(const hub_chan_learned_t *l, char *buf, size_t cap) {
  int w = snprintf(buf, cap, "K|%s|%s|%d|%ld\n", l->chan, l->key, l->modes, (long)l->ts);
  return (w < 0 || (size_t)w >= cap) ? -1 : w;
}

bool hub_learned_append(const hub_state_t *state, char *buf, int cap, int *off) {
  for (int i = 0; i < state->chan_learned_count; i++) {
    int w = hub_learned_format(&state->chan_learned[i], buf + *off, (size_t)(cap - *off));
    if (w < 0) return false;
    *off += w;
  }
  return true;
}

/* ---- Orphans and the purge floor ------------------------------------------ */
int hub_purge_chan_orphans(hub_state_t *state,
                           void (*note)(void *, const char *kind, const char *name,
                                        time_t ts), void *arg) {
  int gone = 0, n = state->global_entry_count;
  /* Decide first (the index still matches the array), then compact. */
  bool *drop = n > 0 ? calloc((size_t)n, sizeof(bool)) : NULL;
  if (n > 0 && !drop) {
    hub_log_error("[PURGE] calloc failed: orphan sweep skipped\n");
    return 0;
  }
  for (int i = 0; i < n; i++) {
    const config_entry_t *e = &state->global_entries[i];
    bool is_c = e->key[0] == 'C' && !e->key[1], is_b = e->key[0] == 'B' && !e->key[1];
    /* Live ones only: a tombstone is the purge's own business (its cutoff),
     * and while it is young it is what stops an old add coming back. */
    if (!(is_c || is_b) || !entry_active(e)) continue;
    char chan[MAX_CHAN];
    size_t cl = strcspn(e->value, "|");
    if (cl >= sizeof(chan)) continue;
    memcpy(chan, e->value, cl);
    chan[cl] = '\0';
    if ((is_b && strcmp(chan, "*") == 0) || hub_chan_live(state, chan, NULL, 0)) continue;
    if (note) note(arg, is_c ? "chanset" : "ban", chan, e->timestamp);
    drop[i] = true;
    gone++;
  }
  if (gone) {
    int o = 0;
    for (int i = 0; i < n; i++) {
      if (drop[i]) continue;
      if (o != i) state->global_entries[o] = state->global_entries[i];
      o++;
    }
    state->global_entry_count = o;
    hub_global_reindex(state);
  }
  free(drop);
  for (int i = 0; i < state->chan_learned_count; i++) {
    if (hub_chan_live(state, state->chan_learned[i].chan, NULL, 0)) continue;
    if (note) note(arg, "learned", state->chan_learned[i].chan, state->chan_learned[i].ts);
    hub_learned_drop(state, state->chan_learned[i].chan);
    gone++;
    i--;
  }
  if (gone) state->config_dirty = true;
  return gone;
}

bool hub_purge_floor_blocks(const hub_state_t *state, time_t ts) {
  return state->purge_floor_until > time(NULL) && ts < state->purge_floor;
}

void hub_purge_floor_set(hub_state_t *state, time_t cutoff) {
  time_t now = time(NULL);
  time_t floor = cutoff > 0 ? cutoff : now;
  if (state->purge_floor_until <= now || floor > state->purge_floor)
    state->purge_floor = floor;
  state->purge_floor_until = now + PURGE_FLOOR_HOLD;
}
