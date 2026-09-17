#include "hub.h"

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

/* Index of the stored global entry that `value` under `key` addresses: a|/p|
 * are singletons, every other key matches on its first field.  -1 if none. */
static int global_entry_find(const hub_state_t *state, const char *key,
                             const char *value) {
  bool is_singleton = (strcmp(key, "a") == 0 || strcmp(key, "p") == 0);

  for (int i = 0; i < state->global_entry_count; i++) {
    if (strcmp(state->global_entries[i].key, key) != 0)
      continue;
    if (is_singleton)
      return i;
    // List match logic (similar to per-bot)
    char stored_first[256];
    const char *pipe = strchr(state->global_entries[i].value, '|');
    if (pipe) {
      size_t len = pipe - state->global_entries[i].value;
      if (len >= sizeof(stored_first))
        len = sizeof(stored_first) - 1;
      memcpy(stored_first, state->global_entries[i].value, len);
      stored_first[len] = 0;
    } else {
      snprintf(stored_first, sizeof(stored_first), "%.*s",
               (int)(sizeof(stored_first) - 1), state->global_entries[i].value);
    }
    if (strcmp(stored_first, value) == 0)
      return i;
  }
  return -1;
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
     * peer or an old hub_admin must not be kept, synced or listed. */
    (void)extra;
    snprintf(combined_value, sizeof(combined_value), "%s||%s", value, safe_op);
  } else {
    snprintf(combined_value, sizeof(combined_value), "%s", value);
  }

  int i = global_entry_find(state, key, value);
  if (i >= 0) {
    if (hub_lww_accepts(ts, hub_global_value_active(combined_value),
                        state->global_entries[i].timestamp,
                        hub_global_value_active(state->global_entries[i].value))) {
      hub_log("[STORAGE] Global %s=%s: incoming_ts=%ld %s stored_ts=%ld -> UPDATED\n",
              key, value, (long)ts,
              ts > state->global_entries[i].timestamp ? ">" : "== (del beats add)",
              (long)state->global_entries[i].timestamp);
      size_t len = strlen(combined_value);
      if (len >= sizeof(state->global_entries[i].value))
        len = sizeof(state->global_entries[i].value) - 1;
      memcpy(state->global_entries[i].value, combined_value, len);
      state->global_entries[i].value[len] = 0;
      state->global_entries[i].timestamp = ts;
      return true;
    }
    hub_log("[STORAGE] Global %s=%s: incoming_ts=%ld <= stored_ts=%ld -> REJECTED\n",
            key, value, (long)ts, (long)state->global_entries[i].timestamp);
    return false;
  }

  if (state->global_entry_count < MAX_BOT_ENTRIES) {
    hub_log("[STORAGE] Global %s=%s: NEW entry ts=%ld\n", key, value, (long)ts);
    config_entry_t *e = &state->global_entries[state->global_entry_count++];
    snprintf(e->key, sizeof(e->key), "%s", key);
    size_t len = strlen(combined_value);
    if (len >= sizeof(e->value))
      len = sizeof(e->value) - 1;
    memcpy(e->value, combined_value, len);
    e->value[len] = 0;
    e->timestamp = ts;
    return true;
  }
  hub_log("[STORAGE] Global %s=%s: REJECTED (max entries reached)\n", key, value);
  return false;
}

// Core Logic: Add/Update Entry
bool hub_storage_update_entry(hub_state_t *state, const char *uuid,
                              const char *key, const char *value,
                              const char *extra, const char *op, time_t ts) {

  /* Retired password-era keys (docs/passwordless.md §3.3): the shared bot
   * password 'p' and the legacy global admin password 'a' are never stored
   * again, whichever path (delta, push, sync, load) offers them. */
  if (strcmp(key, "p") == 0 || strcmp(key, "a") == 0) {
    hub_log("[STORAGE] REJECTED retired key '%s' (passwordless)\n", key);
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
    hub_log("[STORAGE] REJECTED: Invalid UUID '%s' (bot-specific key used as UUID)\n", uuid);
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
      strcmp(key, "seen") != 0 && strcmp(key, "d") != 0) {
    hub_log("[STORAGE] REJECTED per-bot key '%s' for %s (not in whitelist)\n",
            key, uuid);
    return false;
  }
  {
    size_t vlen = value ? strlen(value) : 0;
    size_t cap = 0;
    if      (strcmp(key, "h") == 0)   cap = MAX_MASK_LEN - 1;
    else if (strcmp(key, "n") == 0)   cap = MAX_NICK - 1;
    else if (strcmp(key, "pub") == 0) cap = COMBINED_KEY_B64;
    else                              cap = 31; /* seen/d/t: short numerics */
    if (vlen > cap) {
      hub_log("[STORAGE] REJECTED per-bot '%s' for %s: value too long "
              "(%zu > %zu)\n", key, uuid, vlen, cap);
      return false;
    }
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
        size_t len = pipe - b->entries[i].value;
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

  hub_log("Warning: Bot %s has reached MAX_BOT_ENTRIES\n", uuid);
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

int hub_storage_get_full_list(hub_state_t *state, char *buffer, int max_len) {
  int offset = 0;
  int written;

  int active_count = 0;
  for (int i = 0; i < state->bot_count; i++) {
    if (state->bots[i].is_active) {
      active_count++;
    }
  }

  written = snprintf(buffer + offset, max_len - offset,
                     "--- Registered Bots (%d) ---\n", active_count);
  if (written >= max_len - offset)
    return max_len;
  offset += written;

  for (int i = 0; i < state->bot_count; i++) {
    bot_config_t *b = &state->bots[i];

    if (!b->is_active)
      continue;

    char time_buf[64];
    if (b->last_sync_time == 0) {
      snprintf(time_buf, sizeof(time_buf), "Never");
    } else {
      struct tm *t = localtime(&b->last_sync_time);
      strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", t);
    }

    char nick[32] = "Unknown";
    for (int k = 0; k < b->entry_count; k++) {
      if (strcmp(b->entries[k].key, "n") == 0) {
        snprintf(nick, sizeof(nick), "%.*s",
                 (int)(sizeof(nick) - 1), b->entries[k].value);
        break;
      }
    }

    written = snprintf(buffer + offset, max_len - offset,
                       "[%s] %s | Last Sync: %s\n", b->uuid, nick, time_buf);

    if (written >= max_len - offset)
      break;
    offset += written;

    if (offset >= max_len - 100)
      break;
  }

  return offset;
}

int hub_storage_get_summary_list(hub_state_t *state, char *buffer,
                                 int max_len) {
  int offset = 0;
  int written;

  written = snprintf(buffer + offset, max_len - offset, "--- Bot List ---\n");
  if (written >= max_len - offset)
    return max_len;
  offset += written;

  for (int i = 0; i < state->bot_count; i++) {
    if (!state->bots[i].is_active)
      continue;

    if (offset >= max_len - 128)
      break;

    /* Show friendly name alongside UUID for usability */
    char nick[32] = "";
    for (int k = 0; k < state->bots[i].entry_count; k++) {
      if (strcmp(state->bots[i].entries[k].key, "n") == 0) {
        snprintf(nick, sizeof(nick), "%.*s",
                 (int)(sizeof(nick) - 1), state->bots[i].entries[k].value);
        break;
      }
    }

    if (nick[0]) {
      written = snprintf(buffer + offset, max_len - offset,
                         "%-16s  [%s]\n", nick, state->bots[i].uuid);
    } else {
      written = snprintf(buffer + offset, max_len - offset, "%s\n",
                         state->bots[i].uuid);
    }

    if (written >= max_len - offset)
      break;
    offset += written;
  }

  return offset;
}

// Generate payload for a specific bot (Global + Bot-specific)
// Does NOT include "b|uuid|" prefix for global items, preserving protocol
// compatibility
void hub_generate_bot_payload(hub_state_t *state, const char *uuid,
                              bool proto_v2, char *buffer, int max_len) {
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
    written = snprintf(buffer + offset, max_len - offset, "%s|%s|%ld\n", e->key,
                       e->value, (long)e->timestamp);
    if (written < 0 || written >= (max_len - offset))
      break;
    offset += written;
  }

  // 1a. Named admin/oper records.  A v2 (passwordless) bot gets
  //     uuid|name|pubkey|act|seen|ts|; any other connection gets the legacy
  //     shape with an EMPTY password slot, so an old bot refuses every admin
  //     command instead of reading the public key as a password.
  for (int i = 0; i < state->user_record_count; i++) {
    hub_user_record_t *u = &state->user_records[i];
    written = hub_format_user_record(u, !proto_v2, buffer + offset,
                                     (size_t)(max_len - offset));
    if (written < 0 || written >= (max_len - offset)) break;
    offset += written;
  }

  // 1b. Add usermask records (new format: m| lines)
  for (int i = 0; i < state->mask_record_count; i++) {
    hub_mask_record_t *m = &state->mask_records[i];
    written = snprintf(buffer + offset, max_len - offset,
                       "m|%s|%s|%s|%ld|%ld\n",
                       m->uuid, m->mask,
                       m->is_active ? "add" : "del",
                       (long)m->last_used, (long)m->timestamp);
    if (written < 0 || written >= (max_len - offset)) break;
    offset += written;
  }

  // 1b. Add purge_days setting (allows bots to validate purge policies)
  // Format: pd|<days>|<timestamp>
  time_t now = time(NULL);
  written = snprintf(buffer + offset, max_len - offset, "pd|%d|%ld\n",
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
    written = snprintf(buffer + offset, max_len - offset, "O|%s|%lld\n",
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
        written = snprintf(buffer + offset, max_len - offset, "%s|%s|%ld\n",
                           e->key, e->value, (long)e->timestamp);
        if (written < 0 || written >= (max_len - offset))
          break;
        offset += written;
      }
      break;
    }
  }

  // 3. Add OTHER bots as trusted-bot lines (for offline peer operation):
  //    v2:     b|<hostmask>|<uuid>|<pubkey>|<ts>   (pubkey seals ~B2 traffic)
  //    legacy: b|<hostmask>|<uuid>|<ts>
  //    ts = max(hostmask ts, pubkey ts) so a rekey alone is seen as newer.
  //    v2 payloads end the list with T|<count>: the lines above are the whole
  //    trusted set, so the bot drops every trusted bot they do not name (a
  //    deleted or purged bot).  Without it a bot only ever added or updated
  //    trust and a revoked bot kept ~B2 and op grants forever.  Bots that
  //    predate the marker ignore the unknown line.
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
    if (proto_v2) {
      unsigned char raw[COMBINED_KEY_LEN];
      bool key_ok = pub && hub_crypto_pubkey_b64_decode(pub->value, raw);
      if (key_ok && (long)pub->timestamp > ts) ts = (long)pub->timestamp;
      written = snprintf(buffer + offset, max_len - offset, "b|%s|%s|%s|%ld\n",
                         h->value, b->uuid, key_ok ? pub->value : "", ts);
    } else {
      written = snprintf(buffer + offset, max_len - offset, "b|%s|%s|%ld\n",
                         h->value, b->uuid, ts);
    }
    if (written < 0 || written >= (max_len - offset))
      break;
    offset += written;
    trusted_lines++;
  }
  if (proto_v2) {
    written = snprintf(buffer + offset, max_len - offset, "T|%d\n",
                       trusted_lines);
    if (written > 0 && written < (max_len - offset))
      offset += written;
  }
}
