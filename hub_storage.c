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
    strncpy(b->uuid, uuid, sizeof(b->uuid) - 1);
    b->uuid[sizeof(b->uuid) - 1] = 0;
    b->is_active = true;
    return b;
  }

  return NULL;
}

// Global Storage Update
// Global Storage Update
bool hub_storage_update_global_entry(hub_state_t *state, const char *key,
                                     const char *value, const char *extra,
                                     const char *op, time_t ts) {
  char combined_value[1024];

  // Sanitize op parameter - strip leading and trailing pipes from malformed input
  char clean_op[16] = "";
  if (op) {
    strncpy(clean_op, op, sizeof(clean_op) - 1);
    clean_op[sizeof(clean_op) - 1] = '\0';
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
    snprintf(combined_value, sizeof(combined_value), "%s|%s|%s", value,
             extra ? extra : "", safe_op);
  } else {
    strncpy(combined_value, value, sizeof(combined_value) - 1);
    combined_value[sizeof(combined_value) - 1] = 0;
  }

  bool is_singleton = (strcmp(key, "a") == 0 || strcmp(key, "p") == 0);

  for (int i = 0; i < state->global_entry_count; i++) {
    bool match = false;
    if (is_singleton) {
      if (strcmp(state->global_entries[i].key, key) == 0)
        match = true;
    } else {
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
        strncpy(stored_first, state->global_entries[i].value,
                sizeof(stored_first) - 1);
        stored_first[sizeof(stored_first) - 1] = 0;
      }
      if (strcmp(state->global_entries[i].key, key) == 0 &&
          strcmp(stored_first, value) == 0) {
        match = true;
      }
    }

    if (match) {
      if (ts > state->global_entries[i].timestamp) {
        hub_log("[STORAGE] Global %s=%s: incoming_ts=%ld > stored_ts=%ld -> UPDATED\n",
                key, value, (long)ts, (long)state->global_entries[i].timestamp);
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
  }

  if (state->global_entry_count < MAX_BOT_ENTRIES) {
    hub_log("[STORAGE] Global %s=%s: NEW entry ts=%ld\n", key, value, (long)ts);
    config_entry_t *e = &state->global_entries[state->global_entry_count++];
    strncpy(e->key, key, sizeof(e->key) - 1);
    e->key[sizeof(e->key) - 1] = 0;
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

  // [MODIFIED] Global keys intercept
  if (strcmp(key, "c") == 0 || strcmp(key, "m") == 0 || strcmp(key, "o") == 0 ||
      strcmp(key, "a") == 0 || strcmp(key, "p") == 0) {
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
    strncpy(clean_op, op, sizeof(clean_op) - 1);
    clean_op[sizeof(clean_op) - 1] = '\0';
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
    strncpy(combined_value, value, sizeof(combined_value) - 1);
    combined_value[sizeof(combined_value) - 1] = 0;
  }

  // Determine Type: Singleton or List
  bool is_singleton = (strcmp(key, "n") == 0 || strcmp(key, "a") == 0 ||
                       strcmp(key, "p") == 0 || strcmp(key, "h") == 0 ||
                       strcmp(key, "d") == 0 || strcmp(key, "pub") == 0 ||
                       strcmp(key, "seen") == 0);

  // Auto-Undelete on check-in
  if (strcmp(key, "n") == 0 || strcmp(key, "s") == 0) {
    b->is_active = true;
  }

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
        strncpy(stored_first, b->entries[i].value, sizeof(stored_first) - 1);
        stored_first[sizeof(stored_first) - 1] = 0;
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

      if (ts == b->entries[i].timestamp) {
        if (strcmp(b->entries[i].value, combined_value) != 0) {
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
    strncpy(e->key, key, sizeof(e->key) - 1);
    e->key[sizeof(e->key) - 1] = 0;
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

  fprintf(stderr, "Warning: Bot %s has reached MAX_BOT_ENTRIES\n", uuid);
  return false;
}

bool hub_storage_delete(hub_state_t *state, const char *uuid) {
  bool found = false;

  for (int i = 0; i < state->bot_count; i++) {
    if (strcmp(state->bots[i].uuid, uuid) == 0) {
      found = true;
      break;
    }
  }

  if (!found) {
    return false;
  }

  // Apply Soft Delete
  hub_storage_update_entry(state, uuid, "d", "1", "", "", time(NULL));
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
        strncpy(nick, b->entries[k].value, sizeof(nick) - 1);
        nick[sizeof(nick) - 1] = 0;
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

    written = snprintf(buffer + offset, max_len - offset, "%s\n",
                       state->bots[i].uuid);

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
                              char *buffer, int max_len) {
  int offset = 0;
  int written;
  buffer[0] = 0;

  // 1. Add Global Entries (c, m, o, a, p only - skip h and n which are hub-only)
  for (int i = 0; i < state->global_entry_count; i++) {
    config_entry_t *e = &state->global_entries[i];
    // Skip h and n - these are hub-only metadata, not meant for bots
    if (strcmp(e->key, "h") == 0 || strcmp(e->key, "n") == 0) {
      continue;
    }
    written = snprintf(buffer + offset, max_len - offset, "%s|%s|%ld\n", e->key,
                       e->value, (long)e->timestamp);
    if (written < 0 || written >= (max_len - offset))
      break;
    offset += written;
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

  // 3. Add OTHER bots' hostmasks (for offline peer operation)
  // This allows bots to operate independently when hub is unavailable
  for (int i = 0; i < state->bot_count; i++) {
    if (strcmp(state->bots[i].uuid, uuid) == 0)
      continue; // Skip self
    if (!state->bots[i].is_active)
      continue; // Skip inactive bots

    bot_config_t *b = &state->bots[i];
    for (int j = 0; j < b->entry_count; j++) {
      if (strcmp(b->entries[j].key, "h") == 0) {
        // Format: b|hostmask|uuid|timestamp
        // Cleaner format for storage and matching
        written = snprintf(buffer + offset, max_len - offset, "b|%s|%s|%ld\n",
                           b->entries[j].value, b->uuid,
                           (long)b->entries[j].timestamp);
        if (written < 0 || written >= (max_len - offset))
          break;
        offset += written;
      }
    }
  }
}
