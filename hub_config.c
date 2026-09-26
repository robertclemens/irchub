#include "hub.h"
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

void hub_set_config_pass(hub_state_t *s, const char *pass) {
  /* Store plaintext and lock the page into RAM so it cannot be swapped.
   * See the threat-model comment on hub_state_t.config_pass in hub.h. */
  size_t n = pass ? strlen(pass) : 0;
  if (n >= sizeof(s->config_pass)) n = sizeof(s->config_pass) - 1;
  memcpy(s->config_pass, pass ? pass : "", n);
  memset(s->config_pass + n, 0, sizeof(s->config_pass) - n);
  mlock(s->config_pass, sizeof(s->config_pass));
}

void hub_get_config_pass(const hub_state_t *s, char *out, size_t len) {
  if (len == 0) return;
  size_t sz = sizeof(s->config_pass);
  if (len < sz) sz = len;
  memcpy(out, s->config_pass, sz);
  if (sz < len) out[sz] = '\0';
  else          out[len - 1] = '\0';
}

/* ---- a|/o| user record codec (docs/passwordless.md §3.1) ----
 *   new     uuid|name|pubkey|add/del|last_seen|ts|<reserved, empty>
 *   legacy  uuid|name|password|add/del|last_seen|ts[|pubkey]
 * Field 3 decides.  A valid key there means the new format; anything else is
 * a legacy password, which is never copied anywhere, and the key (if any) is
 * field 7.  Covers every older shape, including an old hub that stored a
 * pubkey in the password slot. */
static int split_fields(const char *s, const char **f, size_t *fl, int max) {
  int n = 0;
  while (n < max) {
    const char *bar = strchr(s, '|');
    f[n] = s;
    fl[n] = bar ? (size_t)(bar - s) : strlen(s);
    n++;
    if (!bar) break;
    s = bar + 1;
  }
  return n;
}

static bool is_uuid_field(const char *s, size_t len) {
  if (len != 36) return false;
  for (size_t i = 0; i < 36; i++) {
    char c = s[i];
    bool dash = (i == 8 || i == 13 || i == 18 || i == 23);
    if (dash ? c != '-'
             : !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                 (c >= 'A' && c <= 'F')))
      return false;
  }
  return true;
}

static bool field_pubkey(const char *f, size_t fl, char out[COMBINED_KEY_B64 + 1]) {
  unsigned char raw[64];
  out[0] = '\0';
  if (fl != COMBINED_KEY_B64) return false;
  memcpy(out, f, COMBINED_KEY_B64);
  out[COMBINED_KEY_B64] = '\0';
  if (hub_crypto_pubkey_b64_decode(out, raw)) return true;
  out[0] = '\0';
  return false;
}

bool hub_parse_opt_value(const char *v, char flags[MAX_OPT_FLAGS + 1],
                         time_t *ts) {
  flags[0] = '\0';
  *ts = 0;
  if (!v) return false;
  const char *bar = strchr(v, '|');
  if (!bar) return false;
  int w = 0;
  for (const char *c = v; c < bar && w < MAX_OPT_FLAGS; c++)
    if ((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') ||
        (*c >= '0' && *c <= '9'))
      flags[w++] = *c;
  flags[w] = '\0';
  char *end = NULL;
  errno = 0;
  long long t = strtoll(bar + 1, &end, 10);
  if (errno || end == bar + 1 || (*end && *end != '|' && *end != '\r') ||
      t <= 0)
    return false;
  *ts = (time_t)t;
  return true;
}

bool hub_parse_user_record(const char *data, char type, hub_user_record_t *out,
                           bool *legacy) {
  const char *f[8];
  size_t fl[8];
  memset(out, 0, sizeof(*out));
  if (legacy) *legacy = false;
  int nf = split_fields(data, f, fl, 8);
  if (nf < 6 || !is_uuid_field(f[0], fl[0])) return false;
  if (fl[1] == 0 || fl[1] >= sizeof(out->name)) return false;
  memcpy(out->uuid, f[0], 36);
  memcpy(out->name, f[1], fl[1]);
  if (field_pubkey(f[2], fl[2], out->pubkey_b64)) {
    out->has_pubkey = true;
  } else {
    if (legacy) *legacy = true;
    if (nf >= 7 && field_pubkey(f[6], fl[6], out->pubkey_b64))
      out->has_pubkey = true;
  }
  out->type = type;
  out->is_active = (fl[3] == 3 && strncmp(f[3], "add", 3) == 0);
  out->last_seen = (time_t)strtoll(f[4], NULL, 10);
  out->timestamp = (time_t)strtoll(f[5], NULL, 10);
  return true;
}

int hub_format_user_record(const hub_user_record_t *u, bool legacy_v1,
                           char *buf, size_t len) {
  const char *pk = u->has_pubkey ? u->pubkey_b64 : "";
  if (legacy_v1)
    /* Old bots read field 3 as a ~A1 password: leave it EMPTY so they refuse
     * every admin command (fail closed); they still get the key in field 7. */
    return snprintf(buf, len, "%c|%s|%s||%s|%ld|%ld|%s\n", u->type, u->uuid,
                    u->name, u->is_active ? "add" : "del", (long)u->last_seen,
                    (long)u->timestamp, pk);
  return snprintf(buf, len, "%c|%s|%s|%s|%s|%ld|%ld|\n", u->type, u->uuid,
                  u->name, pk, u->is_active ? "add" : "del",
                  (long)u->last_seen, (long)u->timestamp);
}

// FIXED: Replaced EVP_BytesToKey with PKCS5_PBKDF2_HMAC
/* Set by -selftest: a staged build loads and validates the live config but
 * must never rewrite (migrate) it under the build that is still running. */
bool g_hub_config_readonly = false;

void hub_config_write(hub_state_t *state) {
  if (g_hub_config_readonly) return;
  int estimated_size = (int)(HUB_CONFIG_FIXED_MAX +
                             (size_t)state->bot_count * HUB_CONFIG_PER_BOT_MAX);
  char *buffer = malloc(estimated_size);
  if (!buffer)
    return;

  int offset = 0, written = 0;
  bool overflow = false;

#define SAFE_WRITE(...)                                                        \
  do {                                                                         \
    if (!overflow) {                                                           \
      written =                                                                \
          snprintf(buffer + offset, estimated_size - offset, __VA_ARGS__);     \
      if (written < 0 || written >= (estimated_size - offset)) {               \
        overflow = true;                                                       \
      } else {                                                                 \
        offset += written;                                                     \
      }                                                                        \
    }                                                                          \
  } while (0)

  SAFE_WRITE("port|%d\n", state->port);
  SAFE_WRITE("bind_ip|%s\n", state->bind_ip[0] ? state->bind_ip : "127.0.0.1");
  SAFE_WRITE("uuid|%s\n", state->hub_uuid[0] ? state->hub_uuid : "");
  SAFE_WRITE("hub_name|%s\n", state->hub_friendly_name[0] ? state->hub_friendly_name : "");
  /* No 'admin|' line is written: admins authenticate with the public keys in
   * their a| records.  Existing files that carry an admin| line are silently
   * ignored at load time. */
  /* Persist Lamport seq so it survives restart and stays monotonic. */
  SAFE_WRITE("lamport_seq|%llu\n", (unsigned long long)state->next_lamport_seq);

  /* Log settings set over CMD_ADMIN_SET_LOG_LEVEL / _SIZE: written only when
   * they differ from the defaults, so an untouched hub's file is unchanged. */
  if (state->log_level != HUB_DEFAULT_LOG_LEVEL)
    SAFE_WRITE("log_level|%d\n", state->log_level);
  if (state->log_max_size > 0 && state->log_max_size != HUB_LOG_FILE_SIZE)
    SAFE_WRITE("log_size|%d\n", state->log_max_size);

  // Write purge_days setting (only if enabled)
  if (state->purge_days_setting > 0) {
    SAFE_WRITE("purge_days|%d\n", state->purge_days_setting);
  }

  /* D3: persist the loopback-trust flag. Always written so the security
   * posture is explicit in the config file rather than implied by absence. */
  SAFE_WRITE("trust_loopback|%d\n", state->trust_loopback ? 1 : 0);

  /* Network opt flags: opt|<letters>|<timestamp>.  Written whenever the
   * value has a timestamp, including a clear (opt||<ts>): without it a
   * restarted hub has ts 0 and adopts the stale flags back from a peer. */
  if (state->opt_flags_ts > 0) {
    SAFE_WRITE("opt|%s|%lld\n", state->opt_flags,
               (long long)state->opt_flags_ts);
  }

  /* The roll-up plan (upgrade plan, Task 13): hub-local, never replicated.
   * rollup|target|variant|kind|min_from|hub_target|plan_set|base|hub_base —
   * every field was checked free of '|' and line breaks before it was
   * accepted (hub_upgrade_plan_field_ok), and is checked again here, so the
   * line can never split or inject another. */
  {
    const pending_rollup_t *r = &state->rollup;
    if (r->have_plan && hub_upgrade_plan_field_ok(r->target) &&
        hub_upgrade_plan_field_ok(r->variant) &&
        hub_upgrade_plan_field_ok(r->kind) &&
        hub_upgrade_plan_field_ok(r->min_from) &&
        hub_upgrade_plan_field_ok(r->hub_target) &&
        hub_upgrade_plan_field_ok(r->base) &&
        hub_upgrade_plan_field_ok(r->hub_base)) {
      SAFE_WRITE("rollup|%s|%s|%s|%s|%s|%lld|%s|%s\n", r->target, r->variant,
                 r->kind, r->min_from, r->hub_target, (long long)r->plan_set,
                 r->base, r->hub_base);
    }
  }

  for (int i = 0; i < state->peer_count; i++) {
    /* Serialize the per-peer Curve25519 pubkey (88 chars base64 of 64-byte
     * combined Ed25519+X25519) as the 5th field. Empty string means "no
     * pubkey known, peer will be refused at connection time". */
    char peer_pub_b64[COMBINED_KEY_B64 + 1] = "";
    if (state->peers[i].has_pubkey) {
      unsigned char combined[COMBINED_KEY_LEN];
      memcpy(combined,                    state->peers[i].ed_pub,    ED25519_KEY_LEN);
      memcpy(combined + ED25519_KEY_LEN,  state->peers[i].x25519_pub, X25519_KEY_LEN);
      char *b64 = base64_encode(combined, COMBINED_KEY_LEN);
      if (b64) {
        snprintf(peer_pub_b64, sizeof(peer_pub_b64), "%s", b64);
        secure_wipe(b64, strlen(b64));
        free(b64);
      }
      secure_wipe(combined, sizeof(combined));
    }
    SAFE_WRITE("peer|%s|%d|%s|%s|%s\n", state->peers[i].ip, state->peers[i].port,
               state->peers[i].uuid[0] ? state->peers[i].uuid : "",
               state->peers[i].friendly_name[0] ? state->peers[i].friendly_name : "",
               peer_pub_b64);
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

  // Write Global Entries (skip h/n metadata, a/m/o which use typed arrays,
  // and the retired bot password p)
  for (int i = 0; i < state->global_entry_count; i++) {
    const char *gk = state->global_entries[i].key;
    if (strcmp(gk, "h") == 0 || strcmp(gk, "n") == 0 ||
        strcmp(gk, "a") == 0 || strcmp(gk, "m") == 0 ||
        strcmp(gk, "o") == 0 || strcmp(gk, "p") == 0) {
      continue;
    }
    SAFE_WRITE("%s|%s|%ld\n", gk,
               state->global_entries[i].value,
               (long)state->global_entries[i].timestamp);
  }

  // Local IP access lists: w|<pattern>|<added> (allow), x|... (deny)
  for (int i = 0; i < state->ip_allow_count; i++)
    SAFE_WRITE("w|%s|%ld\n", state->ip_allow[i].pattern,
               (long)state->ip_allow[i].added);
  for (int i = 0; i < state->ip_deny_count; i++)
    SAFE_WRITE("x|%s|%ld\n", state->ip_deny[i].pattern,
               (long)state->ip_deny[i].added);

  // Write named admin/oper records (a| and o| lines) — skip duplicates by type+name
  // Format: <a|o>|uuid|name|<pubkey_b64>|add/del|last_seen|timestamp|
  // (pubkey empty when has_pubkey == false; trailing field reserved, empty).
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
    char uline[USER_LINE_MAX];
    int ul = hub_format_user_record(u, false, uline, sizeof(uline));
    if (ul <= 0 || ul >= (int)sizeof(uline)) { overflow = true; break; }
    SAFE_WRITE("%s", uline);
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

    if (overflow)
      break;
  }
#undef SAFE_WRITE

  if (overflow) {
    hub_log_error("[CONFIG] config exceeds its %d-byte bound; NOT written "
            "(previous file kept)\n", estimated_size);
    secure_wipe(buffer, (size_t)estimated_size);
    free(buffer);
    return;
  }

  // FIXED: Use PBKDF2 instead of EVP_BytesToKey
  unsigned char salt[SALT_SIZE], key[32], iv[GCM_IV_LEN], tag[GCM_TAG_LEN];
  /* CRITICAL: GCM nonce reuse is catastrophic. Bail out instead of writing
   * with a predictable IV/salt if the RNG is unavailable. */
  if (RAND_bytes(salt, sizeof(salt)) != 1 ||
      RAND_bytes(iv,   sizeof(iv))   != 1) {
    hub_log_error("[HUB] RAND_bytes failed; aborting config write\n");
    secure_wipe(buffer, offset);
    free(buffer);
    return;
  }

  /* Decode XOR-obfuscated config password before use */
  char plain_pass[MAX_PASS];
  hub_get_config_pass(state, plain_pass, sizeof(plain_pass));
  // FIXED: Proper PBKDF2 with 100,000 iterations
  int pbkdf2_ok = PKCS5_PBKDF2_HMAC(plain_pass, (int)strlen(plain_pass), salt,
                                      SALT_SIZE, PBKDF2_ITERATIONS, EVP_sha256(),
                                      32, key);
  secure_wipe(plain_pass, sizeof(plain_pass));
  if (!pbkdf2_ok) {
    hub_log_error("[HUB] PBKDF2 failed\n");
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

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1 ||
      EVP_EncryptUpdate(ctx, ciphertext, &cipher_len, (unsigned char *)buffer,
                        offset) != 1 ||
      EVP_EncryptFinal_ex(ctx, ciphertext + cipher_len, &len) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1) {
    hub_log_error("[HUB] EVP encryption failed; aborting config write\n");
    EVP_CIPHER_CTX_free(ctx);
    secure_wipe(key, sizeof(key));
    secure_wipe(ciphertext, (size_t)offset + 16);
    free(ciphertext);
    secure_wipe(buffer, offset);
    free(buffer);
    return;
  }
  cipher_len += len;
  EVP_CIPHER_CTX_free(ctx);

  // Write to temp file then rename (atomic operation)
  char tmp[64];
  snprintf(tmp, sizeof(tmp), "%s.tmp", HUB_CONFIG_FILE);
  int tmp_fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  FILE *fp = (tmp_fd >= 0) ? fdopen(tmp_fd, "wb") : NULL;
  if (!fp && tmp_fd >= 0) close(tmp_fd);
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
}

/* Body of a w|/x| line, "<pattern>|<ts>", into the local IP list ('w' allow,
 * 'x' deny).  A pattern that does not parse is dropped and logged rather than
 * guessed at (the old matcher read "10.0.0.0/" as /0, i.e. every address).
 * False when the line should not stay in the file as written: dropped, a
 * duplicate, or not in canonical form. */
static bool load_ip_acl_line(hub_state_t *state, char list, char *v) {
  const char *name = list == 'w' ? "allowlist" : "denylist";
  char *s_ts = strrchr(v, '|');
  if (!s_ts) {
    hub_log_warning("[CONFIG] Dropping %s line without a timestamp\n", name);
    return false;
  }
  *s_ts = 0;
  char *op = strchr(v, '|');  /* never written; tolerate "<pattern>|add" */
  if (op) {
    *op++ = 0;
    if (strcmp(op, "add") != 0) {
      hub_log_warning("[CONFIG] Dropping %s entry '%.40s' (op '%.8s')\n", name, v, op);
      return false;
    }
  }
  hub_ip_acl_t e;
  if (!hub_ip_acl_parse(v, &e)) {
    hub_log_warning("[CONFIG] Dropping invalid %s entry '%.40s' (not an IPv4 address "
            "or CIDR)\n", name, v);
    return false;
  }
  e.added = (time_t)atoll(s_ts + 1);
  ip_acl_add_t r = hub_ip_acl_add(state, list, &e);
  if (r == IP_ACL_FULL)
    hub_log_warning("[CONFIG] %s full (%d); dropping %s\n", name, MAX_IP_ACL_ENTRIES,
            e.pattern);
  return r == IP_ACL_ADDED && !op && strcmp(v, e.pattern) == 0;
}

// FIXED: Use PBKDF2 and improved error handling
bool hub_config_load(hub_state_t *state, const char *password) {
  int cfg_legacy_users = 0;  /* password-era a|/o| lines or a p| line seen */
  int cfg_acl_fixed = 0;     /* w|/x| lines dropped, merged or canonicalised */
  struct stat cfg_st;
  if (stat(HUB_CONFIG_FILE, &cfg_st) == 0) {
    if ((cfg_st.st_mode & 0177) != 0)
      hub_log_warning("[HUB] %s has insecure permissions %04o — should be 0600\n",
              HUB_CONFIG_FILE, (unsigned)(cfg_st.st_mode & 0777));
  }
  FILE *fp = fopen(HUB_CONFIG_FILE, "rb");
  if (!fp) {
    hub_log_error("[HUB] Config file not found\n");
    return false;
  }

  unsigned char salt[SALT_SIZE], iv[GCM_IV_LEN], tag[GCM_TAG_LEN];

  if (fread(salt, 1, SALT_SIZE, fp) != SALT_SIZE) {
    hub_log_error("[HUB] Failed to read salt\n");
    fclose(fp);
    return false;
  }
  if (fread(iv, 1, GCM_IV_LEN, fp) != GCM_IV_LEN) {
    hub_log_error("[HUB] Failed to read IV\n");
    fclose(fp);
    return false;
  }
  if (fread(tag, 1, GCM_TAG_LEN, fp) != GCM_TAG_LEN) {
    hub_log_error("[HUB] Failed to read tag\n");
    fclose(fp);
    return false;
  }

  fseek(fp, 0, SEEK_END);
  long fsize = ftell(fp);
  long cipher_len = fsize - SALT_SIZE - GCM_IV_LEN - GCM_TAG_LEN;

  if (cipher_len <= 0) {
    hub_log_error("[HUB] Invalid config file size\n");
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
    hub_log_error("[HUB] Failed to read ciphertext\n");
    free(ciphertext);
    fclose(fp);
    return false;
  }
  fclose(fp);

  // FIXED: Use PBKDF2 instead of EVP_BytesToKey
  unsigned char key[32];
  if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE,
                        PBKDF2_ITERATIONS, EVP_sha256(), 32, key) != 1) {
    hub_log_error("[HUB] PBKDF2 failed\n");
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

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1 ||
      EVP_DecryptUpdate(ctx, plaintext, &plain_len, ciphertext, cipher_len) != 1 ||
      EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag) != 1 ||
      EVP_DecryptFinal_ex(ctx, plaintext + plain_len, &len) <= 0) {
    hub_log_error("[HUB] Config decryption failed (wrong password or corrupted file)\n");
    EVP_CIPHER_CTX_free(ctx);
    secure_wipe(key, sizeof(key));
    /* Partial plaintext may have been written by EVP_DecryptUpdate before the
     * GCM tag check failed. Wipe before freeing so unverified data doesn't
     * outlive its scope. */
    secure_wipe(plaintext, (size_t)cipher_len + 1);
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
        /* Legacy 'admin|' line ignored (global admin password dropped in
         * favour of per-admin records). Old configs simply lose this field
         * on the next save; admins must already exist as a| records. */
        (void)v;
      } else if (strcmp(k, "log_level") == 0) {
        long lv = strtol(v, NULL, 10);
        state->log_level = (int)(lv < LOG_NONE ? LOG_NONE
                                 : lv > LOG_DEBUG ? LOG_DEBUG : lv);
      } else if (strcmp(k, "log_size") == 0) {
        long sz = strtol(v, NULL, 10);
        state->log_max_size = (int)(sz < HUB_LOG_SIZE_MIN ? HUB_LOG_SIZE_MIN
                                    : sz > HUB_LOG_SIZE_MAX ? HUB_LOG_SIZE_MAX
                                                            : sz);
      } else if (strcmp(k, "purge_days") == 0) {
        state->purge_days_setting = atoi(v);
        if (state->purge_days_setting < 0) state->purge_days_setting = 0;
      } else if (strcmp(k, "trust_loopback") == 0) {
        /* D3: exempt 127.0.0.1/::1 from rate limiting only when explicitly set.
         * Absent key -> false (secure default; state is zeroed before load). */
        state->trust_loopback = (v && (v[0] == '1' ||
                                       strcasecmp(v, "true") == 0 ||
                                       strcasecmp(v, "yes")  == 0));
      } else if (strcmp(k, "opt") == 0) {
        /* opt|<letters>|<timestamp>, or opt||<timestamp> after a clear */
        char flags[MAX_OPT_FLAGS + 1];
        time_t ts;
        if (hub_parse_opt_value(v, flags, &ts)) {
          memcpy(state->opt_flags, flags, sizeof(flags));
          state->opt_flags_ts = ts;
        }
      } else if (strcmp(k, "rollup") == 0) {
        /* rollup|target|variant|kind|min_from|hub_target|plan_set|base|hub_base
         * — see hub_config_write.  A line that does not parse cleanly is
         * dropped whole: no plan is better than half of one. */
        const char *f[9];
        size_t fl[9];
        int n = split_fields(v, f, fl, 9);
        pending_rollup_t *r = &state->rollup;
        struct { char *dst; size_t cap; } out[8] = {
            {r->target, sizeof(r->target)},     {r->variant, sizeof(r->variant)},
            {r->kind, sizeof(r->kind)},         {r->min_from, sizeof(r->min_from)},
            {r->hub_target, sizeof(r->hub_target)}, {NULL, 0},
            {r->base, sizeof(r->base)},         {r->hub_base, sizeof(r->hub_base)}};
        bool ok = (n == 8 && fl[0] > 0);
        for (int i = 0; ok && i < 8; i++) {
          if (!out[i].dst) continue;
          if (fl[i] >= out[i].cap) ok = false;
          else {
            memcpy(out[i].dst, f[i], fl[i]);
            out[i].dst[fl[i]] = '\0';
            ok = hub_upgrade_plan_field_ok(out[i].dst);
          }
        }
        long long ts = ok ? strtoll(f[5], NULL, 10) : 0;
        if (ok && ts > 0) {
          r->plan_set = (time_t)ts;
          r->have_plan = true;
        } else {
          memset(r, 0, sizeof(*r));
          hub_log_warning("[CONFIG] Ignoring a malformed rollup| line\n");
        }
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
          hub_log_error("[HUB] Hub private key in config is not 64 bytes "
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
        /* Formats accepted:
         *   peer|ip|port                                 (oldest)
         *   peer|ip|port|uuid|friendly_name              (v1)
         *   peer|ip|port|uuid|friendly_name|pubkey_b64   (v2; pubkey may be empty)
         */
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
            char *pubkey_str = NULL;
            if (name_str) {
              *name_str = 0;
              name_str++;
              pubkey_str = strchr(name_str, '|');
              if (pubkey_str) { *pubkey_str = 0; pubkey_str++; }
            }

            hub_peer_config_t *p = &state->peers[state->peer_count];
            snprintf(p->ip, sizeof(p->ip), "%s", ip);
            p->port = atoi(port_str);
            snprintf(p->uuid, sizeof(p->uuid), "%s", uuid_str);

            if (name_str && name_str[0])
              snprintf(p->friendly_name, sizeof(p->friendly_name), "%s", name_str);

            p->has_pubkey = false;
            if (pubkey_str && pubkey_str[0]) {
              int dec_len = 0;
              unsigned char *dec = base64_decode(pubkey_str, &dec_len);
              if (dec && dec_len == COMBINED_KEY_LEN) {
                memcpy(p->ed_pub,     dec,                   ED25519_KEY_LEN);
                memcpy(p->x25519_pub, dec + ED25519_KEY_LEN, X25519_KEY_LEN);
                p->has_pubkey = true;
              } else {
                hub_log_warning("[PEER] peer %s pubkey wrong length (%d, need %d) — "
                        "ignoring; v2 auth disabled for this peer\n",
                        p->uuid, dec_len, COMBINED_KEY_LEN);
              }
              if (dec) { secure_wipe(dec, (size_t)(dec_len > 0 ? dec_len : 0)); free(dec); }
            }

            p->fd = -1;
            state->peer_count++;
          } else {
            // Old format: peer|ip|port (for backward compatibility)
            hub_peer_config_t *p = &state->peers[state->peer_count];
            snprintf(p->ip, sizeof(p->ip), "%s", ip);
            p->port = atoi(port_str);
            p->fd = -1;
            p->has_pubkey = false;
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
              hub_storage_update_entry(state, uuid, bk, "", "", "", atoll(bv));
            } else {
              // Config entry: b|uuid|key|value|timestamp
              char *s4 = strrchr(bv, '|');
              if (s4) {
                *s4 = 0;
                long long ts = atoll(s4 + 1);

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
      // Older layout of the local IP lists: g|<w|x>|<pattern>|<ts>
      else if (strcmp(k, "g") == 0 &&
               (strncmp(v, "w|", 2) == 0 || strncmp(v, "x|", 2) == 0)) {
        load_ip_acl_line(state, v[0], v + 2);
        cfg_acl_fixed++;  /* rewrite as w|/x| */
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
            long long ts = atoll(s_ts + 1);

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
        /* hub_parse_user_record: new uuid|name|pubkey|act|seen|ts| or the
         * legacy password shape (password dropped).  The pre-UUID global
         * admin-password shape a|<password>|<ts> is ignored outright. */
        if (state->user_record_count < MAX_HUB_USER_RECORDS) {
          hub_user_record_t *u = &state->user_records[state->user_record_count];
          bool legacy = false;
          if (hub_parse_user_record(v, k[0], u, &legacy)) {
            state->user_record_count++;
            if (legacy) cfg_legacy_users++;
          } else {
            memset(u, 0, sizeof(*u));
            cfg_legacy_users++;  /* rewrite without the unparseable line */
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
            m->last_used = (time_t)atoll(p3+1);
            m->timestamp = (time_t)atoll(p4+1);
            state->mask_record_count++;
          }
        }
      } else if (strcmp(k, "c") == 0) {
        /* Channel entries: chan|key[|modes]|op|timestamp */
        char *s_ts = strrchr(v, '|');
        if (s_ts) {
          *s_ts = 0;
          long long ts = atoll(s_ts + 1);
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
        /* Retired shared bot password: dropped (bots use public keys). */
        cfg_legacy_users++;
      } else if (strcmp(k, "w") == 0 || strcmp(k, "x") == 0) {
        if (!load_ip_acl_line(state, k[0], v))
          cfg_acl_fixed++;
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
          hub_log_debug("[HUB] Dedup: merged duplicate '%s' %c record\n", u->name, u->type);
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
        hub_log_debug("[HUB] Dedup: dropped orphaned mask '%s' (UUID %s)\n",
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
      hub_log_info("[HUB] Config dedup: users %d->%d, masks %d->%d\n",
              state->user_record_count, dedup_user_count,
              state->mask_record_count, dedup_mask_count);
      memcpy(state->user_records, dedup_users,
             sizeof(hub_user_record_t) * (size_t)dedup_user_count);
      state->user_record_count = dedup_user_count;
      memcpy(state->mask_records, dedup_masks,
             sizeof(hub_mask_record_t) * (size_t)dedup_mask_count);
      state->mask_record_count = dedup_mask_count;
      hub_config_write(state);
    } else if (cfg_legacy_users > 0 || cfg_acl_fixed > 0) {
      /* Rewrite once so the passwords / p| line, and IP-list lines that were
       * dropped or canonicalised, leave the file for good. */
      hub_config_write(state);
    }
  }
  if (cfg_legacy_users > 0)
    hub_log_info("[HUB] Config migrated to passwordless records (%d legacy "
            "line(s)); passwords dropped\n", cfg_legacy_users);
  for (int i = 0; i < state->user_record_count; i++) {
    const hub_user_record_t *u = &state->user_records[i];
    if (u->is_active && !u->has_pubkey)
      hub_log_warning("[HUB] %s '%s' has no public key and cannot authenticate until "
              "given one (hub_admin: Change user public key)\n",
              u->type == 'a' ? "Admin" : "Oper", u->name);
  }

  secure_wipe(plaintext, plain_len);
  free(plaintext);
  return true;
}
