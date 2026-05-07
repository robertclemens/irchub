#include "hub.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

  // NEW: Write Global Entries (skip h and n which are hub-only metadata)
  for (int i = 0; i < state->global_entry_count; i++) {
    // Skip h and n - these should not be in global entries
    if (strcmp(state->global_entries[i].key, "h") == 0 ||
        strcmp(state->global_entries[i].key, "n") == 0) {
      continue;
    }
    SAFE_WRITE("%s|%s|%ld\n", state->global_entries[i].key,
               state->global_entries[i].value,
               (long)state->global_entries[i].timestamp);
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
      // FIXED: Handle unprefixed global entries (c, m, o, a, p)
      // These are written by hub_config_write() without a prefix
      else if (strcmp(k, "c") == 0 || strcmp(k, "m") == 0 ||
               strcmp(k, "o") == 0 || strcmp(k, "a") == 0 ||
               strcmp(k, "p") == 0) {
        // Parse: key|value|...|timestamp
        char *s_ts = strrchr(v, '|');
        if (s_ts) {
          *s_ts = 0;
          long ts = atol(s_ts + 1);

          if (strcmp(k, "c") == 0 || strcmp(k, "o") == 0) {
            /* Format: chan|key[|modes]|op — use first pipe for chan,
             * last pipe for op, middle portion = extra */
            char *pipe1 = strchr(v, '|');
            if (pipe1) {
              *pipe1 = 0;
              char *rest = pipe1 + 1;
              char *last = strrchr(rest, '|');
              if (last) {
                *last = 0;
                char *op = last + 1;
                hub_storage_update_global_entry(state, k, v, rest, op, ts);
              }
            }
          } else if (strcmp(k, "m") == 0) {
            // Mask: value|op
            char *pipe1 = strchr(v, '|');
            if (pipe1) {
              *pipe1 = 0;
              char *value = v;
              char *op = pipe1 + 1;
              // Strip any trailing pipes from op (malformed config entries)
              char *op_end = op + strlen(op);
              while (op_end > op && *(op_end - 1) == '|') {
                *(--op_end) = '\0';
              }
              hub_storage_update_global_entry(state, k, value, "", op, ts);
            }
          } else {
            // Admin/Bot password: just value
            hub_storage_update_global_entry(state, k, v, "", "", ts);
          }
        }
      }
    }
    line = strtok_r(NULL, "\n", &saveptr);
  }

  secure_wipe(plaintext, plain_len);
  free(plaintext);
  return true;
}
