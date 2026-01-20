#include "hub.h"

void hub_storage_init(void) { }

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

// Core Logic: Add/Update Entry
bool hub_storage_update_entry(hub_state_t *state, const char *uuid, 
                               const char *key, const char *value, time_t ts) {
    bot_config_t *b = get_or_create_bot(state, uuid);
    if (!b) return false;

    // Special Metadata: Sync Timestamp
    if (strcmp(key, "t") == 0) {
        if (ts > b->last_sync_time) {
            b->last_sync_time = ts;
            return true;
        }
        return false;
    }

    // Determine Type: Singleton (n, b, d, pub, seen) or List (c, s, m)
    bool is_singleton = (strcmp(key, "n") == 0 || 
                        strcmp(key, "b") == 0 || 
                        strcmp(key, "d") == 0 || 
                        strcmp(key, "pub") == 0 || 
                        strcmp(key, "seen") == 0);

    // Auto-Undelete on check-in
    if (strcmp(key, "n") == 0 || strcmp(key, "s") == 0) {
        b->is_active = true;
    }

    for (int i = 0; i < b->entry_count; i++) {
        bool match = false;
        
        if (is_singleton) {
            if (strcmp(b->entries[i].key, key) == 0) {
                match = true;
            }
        } else {
            // For lists, key AND value must match
            if (strcmp(b->entries[i].key, key) == 0 && 
                strcmp(b->entries[i].value, value) == 0) {
                match = true;
            }
        }

        if (match) {
            // Loop Prevention Logic:
            
            // 1. If incoming is older, ignore it
            if (ts < b->entries[i].timestamp) {
                return false;
            }

            // 2. If incoming is newer, update
            if (ts > b->entries[i].timestamp) {
                strncpy(b->entries[i].value, value, sizeof(b->entries[i].value) - 1);
                b->entries[i].value[sizeof(b->entries[i].value) - 1] = 0;
                b->entries[i].timestamp = ts;

                // Handle deletion side-effect
                if (strcmp(key, "d") == 0) {
                    b->is_active = (strcmp(value, "1") != 0);
                }

                return true;
            }

            // 3. If timestamps are EQUAL, only update if value is DIFFERENT
            if (ts == b->entries[i].timestamp) {
                if (strcmp(b->entries[i].value, value) != 0) {
                    strncpy(b->entries[i].value, value, sizeof(b->entries[i].value) - 1);
                    b->entries[i].value[sizeof(b->entries[i].value) - 1] = 0;

                    if (strcmp(key, "d") == 0) {
                        b->is_active = (strcmp(value, "1") != 0);
                    }
                    return true;
                }
            }

            // Same timestamp AND same value - DO NOT propagate (kills echo)
            return false;
        }
    }

    // New Entry
    if (b->entry_count < MAX_BOT_ENTRIES) {
        config_entry_t *e = &b->entries[b->entry_count++];
        strncpy(e->key, key, sizeof(e->key) - 1);
        e->key[sizeof(e->key) - 1] = 0;
        strncpy(e->value, value, sizeof(e->value) - 1);
        e->value[sizeof(e->value) - 1] = 0;
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
    hub_storage_update_entry(state, uuid, "d", "1", time(NULL));
    hub_config_write(state);
    return true;
}

int hub_storage_get_full_list(hub_state_t *state, char *buffer, int max_len) {
    int offset = 0;
    int written;

    int active_count = 0;
    for(int i = 0; i < state->bot_count; i++) {
        if (state->bots[i].is_active) {
            active_count++;
        }
    }

    written = snprintf(buffer + offset, max_len - offset, 
                      "--- Registered Bots (%d) ---\n", active_count);
    if (written >= max_len - offset) return max_len;
    offset += written;

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
        for(int k = 0; k < b->entry_count; k++) {
            if(strcmp(b->entries[k].key, "n") == 0) {
                strncpy(nick, b->entries[k].value, sizeof(nick) - 1);
                nick[sizeof(nick) - 1] = 0;
                break;
            }
        }

        written = snprintf(buffer + offset, max_len - offset, 
                          "[%s] %s | Last Sync: %s\n", 
                          b->uuid, nick, time_buf);
        
        if (written >= max_len - offset) break;
        offset += written;

        if (offset >= max_len - 100) break;
    }
    
    return offset;
}

int hub_storage_get_summary_list(hub_state_t *state, char *buffer, int max_len) {
    int offset = 0;
    int written;
    
    written = snprintf(buffer + offset, max_len - offset, "--- Bot List ---\n");
    if (written >= max_len - offset) return max_len;
    offset += written;
    
    for (int i = 0; i < state->bot_count; i++) {
        if (!state->bots[i].is_active) continue;

        if (offset >= max_len - 128) break;
        
        written = snprintf(buffer + offset, max_len - offset, 
                          "%s\n", state->bots[i].uuid);
        
        if (written >= max_len - offset) break;
        offset += written;
    }
    
    return offset;
}
