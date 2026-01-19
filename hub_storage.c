#include "hub.h"

void hub_storage_init(void) { }

static bot_config_t *get_or_create_bot(hub_state_t *state, const char *uuid) {
    for (int i = 0; i < state->bot_count; i++) {
        if (strcmp(state->bots[i].uuid, uuid) == 0) return &state->bots[i];
    }
    if (state->bot_count < MAX_BOTS) {
        bot_config_t *b = &state->bots[state->bot_count++];
        memset(b, 0, sizeof(bot_config_t));
        snprintf(b->uuid, sizeof(b->uuid), "%.63s", uuid);
        b->is_active = true;
        return b;
    }
    return NULL;
}

// Core Logic: Add/Update Entry
bool hub_storage_update_entry(hub_state_t *state, const char *uuid, const char *key, const char *value, time_t ts) {
    bot_config_t *b = get_or_create_bot(state, uuid);
    if (!b) return false;

    // Special Metadata: Sync Timestamp
    if (strcmp(key, "t") == 0) {
        // [FIX] Strict check: Only update if strictly newer
        if (ts > b->last_sync_time) {
            b->last_sync_time = ts;
            return true;
        }
        return false;
    }

    // Determine Type: Singleton (n, b, d, pub) or List (c, s, m)
    // Added "pub" to singletons logic
    bool is_singleton = (strcmp(key, "n") == 0 || strcmp(key, "b") == 0 || strcmp(key, "d") == 0 || strcmp(key, "pub") == 0 || strcmp(key, "seen") == 0);

    // Auto-Undelete on check-in
    if (strcmp(key, "n") == 0 || strcmp(key, "s") == 0) {
        b->is_active = true;
    }

    for (int i = 0; i < b->entry_count; i++) {
        bool match = false;
        if (is_singleton) {
            if (strcmp(b->entries[i].key, key) == 0) match = true;
        } else {
            // For lists, key AND value must match to be the "same entry"
            if (strcmp(b->entries[i].key, key) == 0 && strcmp(b->entries[i].value, value) == 0) match = true;
        }

        if (match) {
            // [FIX] LOOP KILLER LOGIC

            // 1. If incoming is older, ignore it.
            if (ts < b->entries[i].timestamp) return false;

            // 2. If incoming is newer, update.
            if (ts > b->entries[i].timestamp) {
                // [FIX] Removed %.127s limiter. Uses full buffer size now.
                snprintf(b->entries[i].value, sizeof(b->entries[i].value), "%s", value);
                b->entries[i].timestamp = ts;

                // Handle deletion side-effect if this is the winning 'd' entry
                if (strcmp(key, "d") == 0) b->is_active = (strcmp(value, "1") != 0);

                return true;
            }

            // 3. If timestamps are EQUAL, only update if Value is DIFFERENT.
            // (Only applies to singletons, as lists matched on value already)
            if (ts == b->entries[i].timestamp) {
                if (strcmp(b->entries[i].value, value) != 0) {
                     // [FIX] Removed %.127s limiter
                     snprintf(b->entries[i].value, sizeof(b->entries[i].value), "%s", value);

                     if (strcmp(key, "d") == 0) b->is_active = (strcmp(value, "1") != 0);
                     return true;
                }
            }

            // If we get here: Time is same (or newer) AND value is same.
            // DO NOT return true. This kills the echo.
            return false;
        }
    }

    // New Entry (Always true if we have space)
    if (b->entry_count < MAX_BOT_ENTRIES) {
        config_entry_t *e = &b->entries[b->entry_count++];
        snprintf(e->key, sizeof(e->key), "%.31s", key);
        // [FIX] Removed %.127s limiter
        snprintf(e->value, sizeof(e->value), "%s", value);
        e->timestamp = ts;

        if (strcmp(key, "d") == 0) b->is_active = (strcmp(value, "1") != 0);
        return true;
    }

    return false; // Full
}

bool hub_storage_delete(hub_state_t *state, const char *uuid) {
    bool found = false;
    for (int i = 0; i < state->bot_count; i++) {
        if (strcmp(state->bots[i].uuid, uuid) == 0) {
            found = true;
            break;
        }
    }
    if (!found) return false;

    // Apply Soft Delete
    // This will trigger update_entry, which handles the logic
    hub_storage_update_entry(state, uuid, "d", "1", time(NULL));
    hub_config_write(state);
    return true;
}

int hub_storage_get_full_list(hub_state_t *state, char *buffer, int max_len) {
    int offset = 0;

    int active_count = 0;
    for(int i=0; i<state->bot_count; i++) {
        if (state->bots[i].is_active) active_count++;
    }

    offset += snprintf(buffer + offset, max_len - offset, "--- Registered Bots (%d) ---\n", active_count);

    for (int i = 0; i < state->bot_count; i++) {
        bot_config_t *b = &state->bots[i];

        if (!b->is_active) continue;

        char time_buf[64];
        if (b->last_sync_time == 0) {
            snprintf(time_buf, sizeof(time_buf), "Never");
        } else {
            struct tm *t = localtime(&b->last_sync_time);
            strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", t);
        }

        char nick[32] = "Unknown";
        for(int k=0; k<b->entry_count; k++) {
            if(strcmp(b->entries[k].key, "n")==0) {
                strncpy(nick, b->entries[k].value, 31);
                nick[31] = 0;
                break;
            }
        }

        offset += snprintf(buffer + offset, max_len - offset, 
                           "[%s] %s | Last Sync: %s\n", 
                           b->uuid, nick, time_buf);

        if (offset >= max_len - 100) break;
    }
    return offset;
}

int hub_storage_get_summary_list(hub_state_t *state, char *buffer, int max_len) {
    int offset = 0;
    offset += snprintf(buffer + offset, max_len - offset, "--- Bot List ---\n");
    for (int i = 0; i < state->bot_count; i++) {
        if (!state->bots[i].is_active) continue;

        if (offset >= max_len - 128) break;
        offset += snprintf(buffer + offset, max_len - offset, "%s\n", state->bots[i].uuid);
    }
    return offset;
}
