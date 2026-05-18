#include "hub.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

// FIXED: Replaced EVP_BytesToKey with PKCS5_PBKDF2_HMAC
void hub_config_write(hub_state_t *state) {
  int estimated_size = 8192 + (state->bot_count * MAX_BOT_ENTRIES * 1100);
  char *buffer = malloc(estimated_size);
  if (!buffer)
    return;

  int offset = 0, written = 0;

#define SAFE_WRITE(...)                                                        \
  do {                                                                         \
    if (offset < estimated_size) {                                             \
      written =                                                                \
          snprintf(buffer + offset, estimated_size - offset, __VA_ARGS__);     \
      if (written < 0 || written >= (estimated_size - offset)) {               \
        hub_log("Buffer overflow in config write\n");                          \
        offset = estimated_size;                                               \
      } else {                                                                 \
        offset += written;                                                     \
      }                                                                        \
    }                                                                          \
  } while (0)

  SAFE_WRITE("port|%d\n", state->port);
  SAFE_WRITE("bind_ip|%s\n", state->bind_ip[0] ? state->bind_ip : "127.0.0.1");
  SAFE_WRITE("uuid|%s\n", state->hub_uuid[0] ? state->hub_uuid : "");
  SAFE_WRITE("hub_name|%s\n", state->hub_friendly_name[0] ? state->hub_friendly_name : "");
  SAFE_WRITE("admin|%s\n", state->admin_password);
  /* Persist Lamport seq so it survives restart and stays monotonic. */
  SAFE_WRITE("lamport_seq|%llu\n", (unsigned long long)state->next_lamport_seq);

  // Write purge_days setting (only if enabled)
  if (state->purge_days_setting > 0) {
    SAFE_WRITE("purge_days|%d\n", state->purge_days_setting);
  }

  for (int i = 0; i < state->peer_count; i++) {
    SAFE_WRITE("peer|%s|%d|%s|%s\n", state->peers[i].ip, state->peers[i].port,
               state->peers[i].uuid[0] ? state->peers[i].uuid : "",
               state->peers[i].friendly_name[0] ? state->peers[i].friendly_name : "");
  }

  if (state->hub_keys_loaded) {
    unsigned char priv64[64], pub64[64];
    memcpy(priv64,      state->hub_ed25519_priv, 32);
    memcpy(priv64 + 32, state->hub_x25519_priv,  32);
    memcpy(pub64,       state->hub_ed25519_pub,  32);
    memcpy(pub64 + 32,  state->hub_x25519_pub,   32);

    char *priv_b64 = base64_encode(priv64, 64);
    char *pub_b64  = base64_encode(pub64,  64);
    if (priv_b64) {
      SAFE_WRITE("key|%s\n", priv_b64);
      secure_wipe(priv_b64, strlen(priv_b64));
      free(priv_b64);
    }
    if (pub_b64) {
      SAFE_WRITE("pub|%s\n", pub_b64);
      free(pub_b64);
    }
    secure_wipe(priv64, 64);
  }

  // Write Global Entries (skip h/n metadata and a/m/o which use typed arrays)
  for (int i = 0; i < state->global_entry_count; i++) {
    const char *gk = state->global_entries[i].key;
    if (strcmp(gk, "h") == 0 || strcmp(gk, "n") == 0 ||
        strcmp(gk, "a") == 0 || strcmp(gk, "m") == 0 ||
        strcmp(gk, "o") == 0) {
      continue;
    }
    SAFE_WRITE("%s|%s|%ld\n", gk,
               state->global_entries[i].value,
               (long)state->global_entries[i].timestamp);
  }

  // Write named admin/oper records (a| and o| lines) — skip duplicates by type+name
  char wr_seen_names[MAX_HUB_USER_RECORDS][64];
  char wr_seen_types[MAX_HUB_USER_RECORDS];
  int  wr_seen_count = 0;
  for (int i = 0; i < state->user_record_count; i++) {
    hub_user_record_t *u = &state->user_records[i];
    bool dup = false;
    for (int j = 0; j < wr_seen_count; j++) {
      if (wr_seen_types[j] == u->type && strcasecmp(wr_seen_names[j], u->name) == 0) {
        dup = true;
        break;
      }
    }
    if (dup) continue;
    snprintf(wr_seen_names[wr_seen_count], sizeof(wr_seen_names[0]), "%s", u->name);
    wr_seen_types[wr_seen_count] = u->type;
    wr_seen_count++;
    SAFE_WRITE("%c|%s|%s|%s|%s|%ld|%ld\n",
               u->type, u->uuid, u->name, u->password,
               u->is_active ? "add" : "del",
               (long)u->last_seen, (long)u->timestamp);
  }

  // Write usermask records (m| lines) — skip masks with no surviving owner
  for (int i = 0; i < state->mask_record_count; i++) {
    hub_mask_record_t *m = &state->mask_records[i];
    bool owned = false;
    for (int j = 0; j < state->user_record_count; j++) {
      if (strcmp(state->user_records[j].uuid, m->uuid) == 0) {
        owned = true;
        break;
      }
    }
    if (!owned) continue;
    SAFE_WRITE("m|%s|%s|%s|%ld|%ld\n",
               m->uuid, m->mask,
               m->is_active ? "add" : "del",
               (long)m->last_used, (long)m->timestamp);
  }

  for (int i = 0; i < state->bot_count; i++) {
    bot_config_t *b = &state->bots[i];
    if (b->uuid[0] == 0)
      continue;

    SAFE_WRITE("b|%s|t|%ld\n", b->uuid, (long)b->last_sync_time);

    for (int j = 0; j < b->entry_count; j++) {
      // Special handling for "seen" and "t" - omit value field
      if (strcmp(b->entries[j].key, "seen") == 0 || strcmp(b->entries[j].key, "t") == 0) {
        SAFE_WRITE("b|%s|%s|%ld\n", b->uuid, b->entries[j].key,
                   (long)b->entries[j].timestamp);
      } else {
        SAFE_WRITE("b|%s|%s|%s|%ld\n", b->uuid, b->entries[j].key,
                   b->entries[j].value, (long)b->entries[j].timestamp);
      }
    }

    if (offset >= estimated_size)
      break;
  }

  // FIXED: Use PBKDF2 instead of EVP_BytesToKey
  unsigned char salt[SALT_SIZE], key[32], iv[GCM_IV_LEN], tag[GCM_TAG_LEN];
  RAND_bytes(salt, sizeof(salt));
  RAND_bytes(iv, sizeof(iv));

  // FIXED: Proper PBKDF2 with 100,000 iterations
  if (PKCS5_PBKDF2_HMAC(state->config_pass, strlen(state->config_pass), salt,
                        SALT_SIZE, PBKDF2_ITERATIONS, EVP_sha256(), 32,
                        key) != 1) {
    hub_log("PBKDF2 failed\n");
    secure_wipe(buffer, offset);
    free(buffer);
    return;
  }

  unsigned char *ciphertext = malloc(offset + 16);
  if (!ciphertext) {
    secure_wipe(buffer, offset);
    free(buffer);
    return;
  }

  int len, cipher_len;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    free(ciphertext);
    secure_wipe(buffer, offset);
    free(buffer);
    return;
  }

  EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
  EVP_EncryptUpdate(ctx, ciphertext, &cipher_len, (unsigned char *)buffer,
                    offset);
  EVP_EncryptFinal_ex(ctx, ciphertext + cipher_len, &len);
  cipher_len += len;
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag);
  EVP_CIPHER_CTX_free(ctx);

  // Write to temp file then rename (atomic operation)
  char tmp[64];
  snprintf(tmp, sizeof(tmp), "%s.tmp", HUB_CONFIG_FILE);
  FILE *fp = fopen(tmp, "wb");
  if (fp) {
    fwrite(salt, 1, SALT_SIZE, fp);
    fwrite(iv, 1, GCM_IV_LEN, fp);
    fwrite(tag, 1, GCM_TAG_LEN, fp);
    fwrite(ciphertext, 1, cipher_len, fp);
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);
    rename(tmp, HUB_CONFIG_FILE);
  }

  // ADDED: Secure cleanup
  secure_wipe(key, sizeof(key));
  secure_wipe(ciphertext, cipher_len);
  free(ciphertext);
  secure_wipe(buffer, offset);
  free(buffer);

#undef SAFE_WRITE
}

// FIXED: Use PBKDF2 and improved error handling
bool hub_config_load(hub_state_t *state, const char *password) {
  FILE *fp = fopen(HUB_CONFIG_FILE, "rb");
  if (!fp) {
    hub_log("Config file not found\n");
    return false;
  }

  unsigned char salt[SALT_SIZE], iv[GCM_IV_LEN], tag[GCM_TAG_LEN];

  if (fread(salt, 1, SALT_SIZE, fp) != SALT_SIZE) {
    hub_log("Failed to read salt\n");
    fclose(fp);
    return false;
  }
  if (fread(iv, 1, GCM_IV_LEN, fp) != GCM_IV_LEN) {
    hub_log("Failed to read IV\n");
    fclose(fp);
    return false;
  }
  if (fread(tag, 1, GCM_TAG_LEN, fp) != GCM_TAG_LEN) {
    hub_log("Failed to read tag\n");
    fclose(fp);
    return false;
  }

  fseek(fp, 0, SEEK_END);
  long fsize = ftell(fp);
  long cipher_len = fsize - SALT_SIZE - GCM_IV_LEN - GCM_TAG_LEN;

  if (cipher_len <= 0) {
    hub_log("Invalid config file size\n");
    fclose(fp);
    return false;
  }

  fseek(fp, SALT_SIZE + GCM_IV_LEN + GCM_TAG_LEN, SEEK_SET);
  unsigned char *ciphertext = malloc(cipher_len);
  if (!ciphertext) {
    fclose(fp);
    return false;
  }

  if (fread(ciphertext, 1, cipher_len, fp) != (size_t)cipher_len) {
    hub_log("Failed to read ciphertext\n");
    free(ciphertext);
    fclose(fp);
    return false;
  }
  fclose(fp);

  // FIXED: Use PBKDF2 instead of EVP_BytesToKey
  unsigned char key[32];
  if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE,
                        PBKDF2_ITERATIONS, EVP_sha256(), 32, key) != 1) {
    hub_log("PBKDF2 failed\n");
    free(ciphertext);
    return false;
  }

  unsigned char *plaintext = malloc(cipher_len + 1);
  if (!plaintext) {
    secure_wipe(key, sizeof(key));
    free(ciphertext);
    return false;
  }

  int len, plain_len;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    secure_wipe(key, sizeof(key));
    free(ciphertext);
    free(plaintext);
    return false;
  }

  EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
  EVP_DecryptUpdate(ctx, plaintext, &plain_len, ciphertext, cipher_len);
  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag);

  if (EVP_DecryptFinal_ex(ctx, plaintext + plain_len, &len) <= 0) {
    hub_log("Config decryption failed (wrong password or corrupted file)\n");
    EVP_CIPHER_CTX_free(ctx);
    secure_wipe(key, sizeof(key));
    free(ciphertext);
    free(plaintext);
    return false;
  }

  plain_len += len;
  plaintext[plain_len] = 0;
  EVP_CIPHER_CTX_free(ctx);

  // Cleanup sensitive data
  secure_wipe(key, sizeof(key));
  free(ciphertext);

  // Parse configuration
  state->bot_count = 0;
  state->peer_count = 0;

  char *saveptr;
  char *line = strtok_r((char *)plaintext, "\n", &saveptr);

  while (line) {
    char *sep = strchr(line, '|');
    if (!sep)
      sep = strchr(line, ':');

    if (sep) {
      *sep = 0;
      char *k = line;
      char *v = sep + 1;

      if (strcmp(k, "port") == 0) {
        state->port = atoi(v);
      } else if (strcmp(k, "bind_ip") == 0) {
        snprintf(state->bind_ip, sizeof(state->bind_ip), "%s", v);
      } else if (strcmp(k, "uuid") == 0) {
        snprintf(state->hub_uuid, sizeof(state->hub_uuid), "%s", v);
      } else if (strcmp(k, "hub_name") == 0) {
        // Only update if value is non-empty to prevent blanking out existing name
        if (v && v[0]) {
          snprintf(state->hub_friendly_name, sizeof(state->hub_friendly_name), "%s", v);
        }
      } else if (strcmp(k, "admin") == 0) {
        snprintf(state->admin_password, sizeof(state->admin_password), "%s", v);
      } else if (strcmp(k, "purge_days") == 0) {
        state->purge_days_setting = atoi(v);
        if (state->purge_days_setting < 0) state->purge_days_setting = 0;
      } else if (strcmp(k, "lamport_seq") == 0) {
        unsigned long long loaded_seq = 0;
        sscanf(v, "%llu", &loaded_seq);
        /* Bump past max(saved_seq, time_based_floor) so seq stays monotonic
         * even if the clock or the saved value lagged. Shift left 10 bits
         * gives ~1024 seqs/second headroom before any real tick fires. */
        uint64_t time_floor = ((uint64_t)time(NULL)) << 10;
        state->next_lamport_seq = (loaded_seq > time_floor) ? loaded_seq : time_floor;
      } else if (strcmp(k, "key") == 0) {
        int out;
        unsigned char *d = base64_decode(v, &out);
        if (d && out == 64) {
          memcpy(state->hub_ed25519_priv, d,      32);
          memcpy(state->hub_x25519_priv,  d + 32, 32);
          state->hub_keys_loaded = true;
        } else if (d) {
          hub_log("[HUB] Hub private key in config is not 64 bytes "
                  "(legacy RSA?). Re-run -setup with a Curve25519 key.\n");
        }
        if (d) { secure_wipe(d, out); free(d); }
      } else if (strcmp(k, "pub") == 0) {
        int out;
        unsigned char *d = base64_decode(v, &out);
        if (d && out == 64) {
          memcpy(state->hub_ed25519_pub, d,      32);
          memcpy(state->hub_x25519_pub,  d + 32, 32);
        }
        if (d) free(d);
      } else if (strcmp(k, "peer") == 0) {
        // Parse: peer|ip|port|uuid|friendly_name
        char *ip = v;
        char *port_str = strchr(ip, '|');
        if (!port_str) port_str = strchr(ip, ':');

        if (port_str && state->peer_count < MAX_PEERS) {
          *port_str = 0;
          port_str++;

          char *uuid_str = strchr(port_str, '|');
          if (uuid_str) {
            *uuid_str = 0;
            uuid_str++;

            char *name_str = strchr(uuid_str, '|');
            if (name_str) {
              *name_str = 0;
              name_str++;
            }

            // Store peer data
            snprintf(state->peers[state->peer_count].ip,
                     sizeof(state->peers[state->peer_count].ip), "%s", ip);

            state->peers[state->peer_count].port = atoi(port_str);

            snprintf(state->peers[state->peer_count].uuid,
                     sizeof(state->peers[state->peer_count].uuid), "%s", uuid_str);

            // Only copy friendly_name if it's non-empty
            if (name_str && name_str[0]) {
              snprintf(state->peers[state->peer_count].friendly_name,
                       sizeof(state->peers[state->peer_count].friendly_name),
                       "%s", name_str);
            }

            state->peers[state->peer_count].fd = -1;
            state->peer_count++;
          } else {
            // Old format: peer|ip|port (for backward compatibility)
            snprintf(state->peers[state->peer_count].ip,
                     sizeof(state->peers[state->peer_count].ip), "%s", ip);
            state->peers[state->peer_count].port = atoi(port_str);
            state->peers[state->peer_count].fd = -1;
            state->peer_count++;
          }
        }
      } else if (strcmp(k, "b") == 0) {
        char *s2 = strchr(v, '|');
        if (s2) {
          *s2 = 0;
          char *uuid = v;
          char *rest = s2 + 1;
          char *s3 = strchr(rest, '|');
          if (s3) {
            *s3 = 0;
            char *bk = rest;
            char *bv = s3 + 1;

            if (strcmp(bk, "t") == 0 || strcmp(bk, "seen") == 0) {
              // Metadata fields without value: b|uuid|t|timestamp or b|uuid|seen|timestamp
              hub_storage_update_entry(state, uuid, bk, "", "", "", atol(bv));
            } else {
              // Config entry: b|uuid|key|value|timestamp
              char *s4 = strrchr(bv, '|');
              if (s4) {
                *s4 = 0;
                long ts = atol(s4 + 1);

                char *pipe1 = strchr(bv, '|');
                if (pipe1) {
                  *pipe1 = 0;
                  char *rest2 = pipe1 + 1;
                  char *pipe2 = strchr(rest2, '|');

                  if (pipe2) {
                    // Three parts: value|extra|op (channel or oper)
                    *pipe2 = 0;
                    char *value = bv;
                    char *extra = rest2;
                    char *op = pipe2 + 1;
                    hub_storage_update_entry(state, uuid, bk, value, extra, op,
                                             ts);
                  } else {
                    // Two parts: value|op (mask)
                    char *value = bv;
                    char *op = rest2;
                    hub_storage_update_entry(state, uuid, bk, value, "", op,
                                             ts);
                  }
                } else {
                  // One part: simple value
                  hub_storage_update_entry(state, uuid, bk, bv, "", "", ts);
                }
              }
            }
          }
        }
      }
      // NEW: Handle Global Entries (g|key|value|timestamp)
      else if (strcmp(k, "g") == 0) {
        char *s2 = strchr(v, '|');
        if (s2) {
          *s2 = 0;
          char *gk = v;      // key (c, m, o, a, p)
          char *gv = s2 + 1; // value...|ts

          char *s_ts = strrchr(gv, '|');
          if (s_ts) {
            *s_ts = 0;
            long ts = atol(s_ts + 1);

            // Parse complex values based on key
            // c -> value|extra|op
            // m -> value|op
            // o -> value|extra|op
            // a, p -> value

            if (strcmp(gk, "c") == 0 || strcmp(gk, "o") == 0) {
              /* Format: chan|key[|modes]|op — use first pipe for chan,
               * last pipe for op, middle portion = extra (key or key|modes) */
              char *pipe1 = strchr(gv, '|');
              if (pipe1) {
                *pipe1 = 0;
                char *rest = pipe1 + 1;
                char *last = strrchr(rest, '|');
                if (last) {
                  *last = 0;
                  char *op = last + 1;
                  hub_storage_update_global_entry(state, gk, gv, rest, op, ts);
                }
              }
            } else if (strcmp(gk, "m") == 0) {
              char *pipe1 = strchr(gv, '|');
              if (pipe1) {
                *pipe1 = 0;
                char *op = pipe1 + 1;
                // Strip any trailing pipes from op (malformed config entries)
                char *op_end = op + strlen(op);
                while (op_end > op && *(op_end - 1) == '|') {
                  *(--op_end) = '\0';
                }
                hub_storage_update_global_entry(state, gk, gv, "", op, ts);
              }
            } else {
              hub_storage_update_global_entry(state, gk, gv, "", "", ts);
            }
          }
        }
      }
      // Handle a| o| m| lines (new typed arrays) and legacy c|/p| global entries
      else if (strcmp(k, "a") == 0 || strcmp(k, "o") == 0) {
        /* New format: uuid|name|password|add/del|last_seen|timestamp
         * Old format: password|timestamp  (a only — no opers had this shape)
         * Detect by checking if first field looks like a UUID. */
        char first[40] = {0};
        char *pipe1 = strchr(v, '|');
        if (pipe1) {
          size_t flen = (size_t)(pipe1 - v);
          if (flen < sizeof(first)) { memcpy(first, v, flen); first[flen] = 0; }
        }
        bool is_new = (strlen(first) == 36 && first[8] == '-' &&
                       first[13] == '-' && first[18] == '-' && first[23] == '-');

        if (is_new && state->user_record_count < MAX_HUB_USER_RECORDS) {
          /* New format: uuid|name|password|action|last_seen|timestamp */
          hub_user_record_t *u = &state->user_records[state->user_record_count];
          memset(u, 0, sizeof(*u));
          char *p1 = strchr(v, '|');           /* after uuid */
          char *p2 = p1 ? strchr(p1+1, '|') : NULL; /* after name */
          char *p3 = p2 ? strchr(p2+1, '|') : NULL; /* after pass */
          char *p4 = p3 ? strchr(p3+1, '|') : NULL; /* after action */
          char *p5 = p4 ? strchr(p4+1, '|') : NULL; /* after last_seen */
          if (p1 && p2 && p3 && p4 && p5) {
            snprintf(u->uuid,     sizeof(u->uuid),     "%.*s", (int)(p1-v),    v);
            snprintf(u->name,     sizeof(u->name),     "%.*s", (int)(p2-p1-1), p1+1);
            snprintf(u->password, sizeof(u->password), "%.*s", (int)(p3-p2-1), p2+1);
            u->type      = k[0];
            u->is_active = (strncmp(p3+1, "add", 3) == 0);
            u->last_seen = (time_t)atol(p4+1);
            u->timestamp = (time_t)atol(p5+1);
            state->user_record_count++;
          }
        }
      } else if (strcmp(k, "m") == 0) {
        /* New format: uuid|mask|add/del|last_used|timestamp
         * Old format: mask|add/del|timestamp
         * Detect by UUID in first field. */
        char first[40] = {0};
        char *pipe1 = strchr(v, '|');
        if (pipe1) {
          size_t flen = (size_t)(pipe1 - v);
          if (flen < sizeof(first)) { memcpy(first, v, flen); first[flen] = 0; }
        }
        bool is_new = (strlen(first) == 36 && first[8] == '-' &&
                       first[13] == '-' && first[18] == '-' && first[23] == '-');

        if (is_new && state->mask_record_count < MAX_HUB_USER_MASKS) {
          hub_mask_record_t *m = &state->mask_records[state->mask_record_count];
          memset(m, 0, sizeof(*m));
          char *p1 = strchr(v, '|');           /* after uuid */
          char *p2 = p1 ? strchr(p1+1, '|') : NULL; /* after mask */
          char *p3 = p2 ? strchr(p2+1, '|') : NULL; /* after action */
          char *p4 = p3 ? strchr(p3+1, '|') : NULL; /* after last_used */
          if (p1 && p2 && p3 && p4) {
            snprintf(m->uuid,     sizeof(m->uuid),     "%.*s", (int)(p1-v),    v);
            snprintf(m->mask,     sizeof(m->mask),     "%.*s", (int)(p2-p1-1), p1+1);
            m->is_active = (strncmp(p2+1, "add", 3) == 0);
            m->last_used = (time_t)atol(p3+1);
            m->timestamp = (time_t)atol(p4+1);
            state->mask_record_count++;
          }
        }
      } else if (strcmp(k, "c") == 0) {
        /* Channel entries: chan|key[|modes]|op|timestamp */
        char *s_ts = strrchr(v, '|');
        if (s_ts) {
          *s_ts = 0;
          long ts = atol(s_ts + 1);
          char *pipe1 = strchr(v, '|');
          if (pipe1) {
            *pipe1 = 0;
            char *rest = pipe1 + 1;
            char *last = strrchr(rest, '|');
            if (last) {
              *last = 0;
              hub_storage_update_global_entry(state, k, v, rest, last + 1, ts);
            }
          }
        }
      } else if (strcmp(k, "p") == 0) {
        /* Bot pass: value|timestamp */
        char *s_ts = strrchr(v, '|');
        if (s_ts) {
          *s_ts = 0;
          hub_storage_update_global_entry(state, k, v, "", "", atol(s_ts + 1));
        }
      }
    }
    line = strtok_r(NULL, "\n", &saveptr);
  }

  /* Deduplicate user records by name: for each name, keep the record with the
   * highest last_seen (ties: highest timestamp; further ties: first loaded).
   * Remap orphaned mask records to the surviving UUID and drop duplicates.
   * This handles the case where multiple hubs independently migrated the same
   * admin/oper name and synced their records here. */
  {
    hub_user_record_t dedup_users[MAX_HUB_USER_RECORDS];
    hub_mask_record_t dedup_masks[MAX_HUB_USER_MASKS];
    int dedup_user_count = 0, dedup_mask_count = 0;
    char uuid_remap[MAX_HUB_USER_RECORDS][2][37]; /* [i][0]=old, [1]=new */
    int remap_count = 0;

    for (int i = 0; i < state->user_record_count; i++) {
      hub_user_record_t *u = &state->user_records[i];
      /* Check if a record with the same type+name already exists in dedup_users */
      int existing = -1;
      for (int j = 0; j < dedup_user_count; j++) {
        if (dedup_users[j].type == u->type &&
            strcasecmp(dedup_users[j].name, u->name) == 0) {
          existing = j;
          break;
        }
      }
      if (existing < 0) {
        /* First time we see this name: add to dedup set */
        dedup_users[dedup_user_count++] = *u;
      } else {
        /* Duplicate name: keep the better record */
        hub_user_record_t *winner = &dedup_users[existing];
        hub_user_record_t *loser  = u;
        bool incoming_wins = (u->last_seen > winner->last_seen) ||
                             (u->last_seen == winner->last_seen &&
                              u->timestamp > winner->timestamp) ||
                             (u->last_seen == winner->last_seen &&
                              u->timestamp == winner->timestamp &&
                              strcmp(u->uuid, winner->uuid) < 0);
        if (incoming_wins) {
          /* Remap old winner's UUID → incoming's UUID */
          if (remap_count < MAX_HUB_USER_RECORDS) {
            snprintf(uuid_remap[remap_count][0], 37, "%s", winner->uuid);
            snprintf(uuid_remap[remap_count][1], 37, "%s", u->uuid);
            remap_count++;
          }
          *winner = *u;
          loser = &state->user_records[i]; /* already u, but for clarity */
        } else {
          /* Remap incoming's UUID → winner's UUID */
          if (remap_count < MAX_HUB_USER_RECORDS) {
            snprintf(uuid_remap[remap_count][0], 37, "%s", u->uuid);
            snprintf(uuid_remap[remap_count][1], 37, "%s", winner->uuid);
            remap_count++;
          }
        }
        (void)loser;
        if (remap_count > 0) {
          hub_log("[HUB] Dedup: merged duplicate '%s' %c record\n", u->name, u->type);
        }
      }
    }

    /* Remap, dedup, and drop orphaned masks */
    for (int i = 0; i < state->mask_record_count; i++) {
      hub_mask_record_t *m = &state->mask_records[i];
      /* Apply UUID remapping (known loser → winner) */
      for (int r = 0; r < remap_count; r++) {
        if (strcmp(m->uuid, uuid_remap[r][0]) == 0) {
          snprintf(m->uuid, sizeof(m->uuid), "%s", uuid_remap[r][1]);
          break;
        }
      }
      /* Drop masks whose UUID has no surviving owner */
      bool has_owner = false;
      for (int j = 0; j < dedup_user_count; j++) {
        if (strcmp(dedup_users[j].uuid, m->uuid) == 0) {
          has_owner = true;
          break;
        }
      }
      if (!has_owner) {
        hub_log("[HUB] Dedup: dropped orphaned mask '%s' (UUID %s)\n",
                m->mask, m->uuid);
        continue;
      }
      /* Check for duplicate (same uuid+mask already in dedup_masks) */
      bool dup = false;
      for (int j = 0; j < dedup_mask_count; j++) {
        if (strcmp(dedup_masks[j].uuid, m->uuid) == 0 &&
            strcasecmp(dedup_masks[j].mask, m->mask) == 0) {
          if (m->last_used > dedup_masks[j].last_used)
            dedup_masks[j] = *m;
          dup = true;
          break;
        }
      }
      if (!dup && dedup_mask_count < MAX_HUB_USER_MASKS)
        dedup_masks[dedup_mask_count++] = *m;
    }

    if (dedup_user_count != state->user_record_count ||
        dedup_mask_count  != state->mask_record_count) {
      hub_log("[HUB] Config dedup: users %d->%d, masks %d->%d\n",
              state->user_record_count, dedup_user_count,
              state->mask_record_count, dedup_mask_count);
      memcpy(state->user_records, dedup_users,
             sizeof(hub_user_record_t) * (size_t)dedup_user_count);
      state->user_record_count = dedup_user_count;
      memcpy(state->mask_records, dedup_masks,
             sizeof(hub_mask_record_t) * (size_t)dedup_mask_count);
      state->mask_record_count = dedup_mask_count;
      hub_config_write(state);
    }
  }

  secure_wipe(plaintext, plain_len);
  free(plaintext);
  return true;
}
