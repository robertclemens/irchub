#include "hub.h"
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#ifndef CMD_ADMIN_CREATE_BOT
#define CMD_ADMIN_CREATE_BOT 50
#endif

void hub_log(const char *format, ...);
static void send_config_to_bot(hub_state_t *state, hub_client_t *client);
static void hub_broadcast_config_to_bots(hub_state_t *state, const char *config_line);

// --- Forward Declarations ---
static bool send_response(hub_state_t *state, hub_client_t *client,
                          const char *msg);
static bool send_pong(hub_state_t *state, hub_client_t *c);
void hub_broadcast_mesh_state(hub_state_t *state);
static void add_pending_bot(hub_state_t *state, const char *uuid,
                            const char *ip);
static void remove_pending_bot(hub_state_t *state, const char *uuid);
static void broadcast_new_key(hub_state_t *state, const char *new_priv_key, const char *new_pub_key);
static void process_mesh_state(hub_state_t *state, hub_client_t *c,
                               char *payload);
static void process_peer_sync(hub_state_t *state, char *payload, int origin_fd);
int hub_execute_purge(hub_state_t *state, const char *days_str,
                      bool immediate, char *log_out, int log_max_len);
static bool handle_admin_command(hub_state_t *state, hub_client_t *client,
                                 int cmd, char *payload);
static void process_bot_command(hub_state_t *state, hub_client_t *client,
                                int cmd, char *payload);

// OP Request Forwarding Forward Decls
static void generate_request_id(char *out_id, size_t len);
static int add_pending_op_request(hub_state_t *state, const char *request_id,
                                   const char *requester_uuid,
                                   const char *target_uuid,
                                   const char *channel, int origin_fd);
static pending_op_request_t *find_pending_op_request(hub_state_t *state,
                                                      const char *request_id);
static void remove_pending_op_request(hub_state_t *state,
                                       const char *request_id);
static void forward_op_request_to_peers(hub_state_t *state,
                                         const char *request_id,
                                         const char *requester_uuid,
                                         const char *target_uuid,
                                         const char *channel, int exclude_fd);
static void process_forward_op_request(hub_state_t *state,
                                        hub_client_t *client, char *payload);
static void process_forward_op_grant(hub_state_t *state, hub_client_t *client,
                                      char *payload);
static void process_forward_op_failed(hub_state_t *state, hub_client_t *client,
                                       char *payload);

// Crypto/Config Forward Decls
bool hub_crypto_generate_bot_creds(char **out_uuid, char **out_priv_b64,
                                   char **out_pub_b64);

// --- Helper Functions ---

// ============ RATE LIMITING FUNCTIONS ============

static ip_rate_limit_t* find_or_create_ip_limit(hub_state_t *state, const char *ip) {
    // Find existing entry
    for (int i = 0; i < state->ip_limits_count; i++) {
        if (strcmp(state->ip_limits[i].ip, ip) == 0) {
            return &state->ip_limits[i];
        }
    }

    // Create new entry if space available
    if (state->ip_limits_count < MAX_IP_RATE_LIMITS) {
        ip_rate_limit_t *entry = &state->ip_limits[state->ip_limits_count++];
        strncpy(entry->ip, ip, sizeof(entry->ip) - 1);
        entry->ip[sizeof(entry->ip) - 1] = '\0';
        entry->active_connections = 0;
        entry->failed_auth_count = 0;
        entry->last_failed_auth = 0;
        entry->blocked_until = 0;
        entry->first_seen = time(NULL);
        return entry;
    }

    return NULL;  // No space (shouldn't happen with large limit)
}

bool is_ip_allowed(hub_state_t *state, const char *ip) {
    ip_rate_limit_t *entry = find_or_create_ip_limit(state, ip);
    if (!entry) return true;  // If can't track, allow (fail open)

    time_t now = time(NULL);

    // Check if temporarily blocked
    if (entry->blocked_until > 0 && now < entry->blocked_until) {
        hub_log("[RATE_LIMIT] IP %s is blocked until %ld (failed auth)\n",
                ip, (long)entry->blocked_until);
        return false;
    }

    // Reset block if expired
    if (entry->blocked_until > 0 && now >= entry->blocked_until) {
        entry->blocked_until = 0;
        entry->failed_auth_count = 0;
    }

    // Check connection limit
    if (entry->active_connections >= MAX_CONNECTIONS_PER_IP) {
        hub_log("[RATE_LIMIT] IP %s exceeded connection limit (%d/%d)\n",
                ip, entry->active_connections, MAX_CONNECTIONS_PER_IP);
        return false;
    }

    return true;
}

void increment_active_connections(hub_state_t *state, const char *ip) {
    ip_rate_limit_t *entry = find_or_create_ip_limit(state, ip);
    if (entry) {
        entry->active_connections++;
    }
}

void decrement_active_connections(hub_state_t *state, const char *ip) {
    for (int i = 0; i < state->ip_limits_count; i++) {
        if (strcmp(state->ip_limits[i].ip, ip) == 0) {
            if (state->ip_limits[i].active_connections > 0) {
                state->ip_limits[i].active_connections--;
            }
            break;
        }
    }
}

static void record_failed_auth(hub_state_t *state, const char *ip) {
    ip_rate_limit_t *entry = find_or_create_ip_limit(state, ip);
    if (!entry) return;

    time_t now = time(NULL);

    // Reset counter if last failure was over FAILED_AUTH_RESET_TIME ago
    if (now - entry->last_failed_auth > FAILED_AUTH_RESET_TIME) {
        entry->failed_auth_count = 0;
    }

    entry->failed_auth_count++;
    entry->last_failed_auth = now;

    hub_log("[AUTH_FAIL] IP %s failed auth (attempt %d/%d)\n",
            ip, entry->failed_auth_count, MAX_FAILED_AUTH_ATTEMPTS);

    // Block if exceeded max attempts
    if (entry->failed_auth_count >= MAX_FAILED_AUTH_ATTEMPTS) {
        entry->blocked_until = now + FAILED_AUTH_BLOCK_DURATION;
        hub_log("[AUTH_BLOCK] IP %s blocked for %d seconds (too many failed attempts)\n",
                ip, FAILED_AUTH_BLOCK_DURATION);
    }
}

void cleanup_old_ip_limits(hub_state_t *state) {
    time_t now = time(NULL);
    int i = 0;

    while (i < state->ip_limits_count) {
        ip_rate_limit_t *entry = &state->ip_limits[i];

        // Remove if no active connections and not blocked and old (1 hour+)
        if (entry->active_connections == 0 &&
            entry->blocked_until == 0 &&
            now - entry->first_seen > 3600) {

            // Swap with last and decrement count
            state->ip_limits[i] = state->ip_limits[--state->ip_limits_count];
            continue;  // Don't increment i, check swapped entry
        }
        i++;
    }
}

// ============ IP ACCESS CONTROL FUNCTIONS ============

// Simple CIDR matching (supports /24, /16, /8 and exact match)
static bool ip_matches_pattern(const char *ip, const char *pattern) {
    // Check for CIDR notation
    char pattern_copy[128];
    strncpy(pattern_copy, pattern, sizeof(pattern_copy) - 1);
    pattern_copy[sizeof(pattern_copy) - 1] = '\0';

    char *slash = strchr(pattern_copy, '/');
    if (slash) {
        *slash = '\0';
        int prefix_len = atoi(slash + 1);

        // Convert IPs to binary
        struct in_addr ip_addr, pattern_addr;
        if (inet_pton(AF_INET, ip, &ip_addr) != 1 ||
            inet_pton(AF_INET, pattern_copy, &pattern_addr) != 1) {
            return false;
        }

        // Create netmask
        uint32_t mask = 0;
        if (prefix_len > 0 && prefix_len <= 32) {
            mask = htonl(~((1u << (32 - prefix_len)) - 1));
        }

        // Compare network portions
        return (ip_addr.s_addr & mask) == (pattern_addr.s_addr & mask);
    }

    // Exact match
    return strcmp(ip, pattern) == 0;
}

static bool is_ip_in_list(hub_state_t *state, const char *ip, const char *list_key) {
    for (int i = 0; i < state->global_entry_count; i++) {
        if (strcmp(state->global_entries[i].key, list_key) == 0) {
            // Check if this is a tombstone (deleted)
            if (strstr(state->global_entries[i].value, "|del") != NULL) {
                continue;
            }

            // Extract IP pattern (before first |)
            char pattern[256];
            const char *pipe = strchr(state->global_entries[i].value, '|');
            if (pipe) {
                size_t len = pipe - state->global_entries[i].value;
                if (len >= sizeof(pattern)) len = sizeof(pattern) - 1;
                memcpy(pattern, state->global_entries[i].value, len);
                pattern[len] = '\0';
            } else {
                strncpy(pattern, state->global_entries[i].value, sizeof(pattern) - 1);
                pattern[sizeof(pattern) - 1] = '\0';
            }

            if (ip_matches_pattern(ip, pattern)) {
                return true;
            }
        }
    }
    return false;
}

bool check_ip_access_lists(hub_state_t *state, const char *ip) {
    // Check denylist first
    if (is_ip_in_list(state, ip, "x")) {
        hub_log("[ACCESS_CONTROL] IP %s denied (denylist)\n", ip);
        return false;
    }

    // Check if allowlist exists (count entries with key "w")
    bool allowlist_exists = false;
    for (int i = 0; i < state->global_entry_count; i++) {
        if (strcmp(state->global_entries[i].key, "w") == 0) {
            if (strstr(state->global_entries[i].value, "|del") == NULL) {
                allowlist_exists = true;
                break;
            }
        }
    }

    // If allowlist exists, IP must be in it
    if (allowlist_exists) {
        if (!is_ip_in_list(state, ip, "w")) {
            hub_log("[ACCESS_CONTROL] IP %s denied (not in allowlist)\n", ip);
            return false;
        }
    }

    return true;
}

// ============ ADD THESE THREE FUNCTIONS HERE ============

// Load bot's public key from hub config
static EVP_PKEY *load_bot_public_key(hub_state_t *state, const char *uuid) {
  for (int i = 0; i < state->bot_count; i++) {
    if (strcmp(state->bots[i].uuid, uuid) == 0) {
      for (int j = 0; j < state->bots[i].entry_count; j++) {
        if (strcmp(state->bots[i].entries[j].key, "pub") == 0) {
          int pem_len = 0;
          unsigned char *pem_data =
              base64_decode(state->bots[i].entries[j].value, &pem_len);
          if (!pem_data)
            return NULL;

          BIO *bio = BIO_new_mem_buf(pem_data, pem_len);
          EVP_PKEY *pub_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
          BIO_free(bio);
          free(pem_data);
          return pub_key;
        }
      }
    }
  }
  return NULL;
}

static int rsa_encrypt_with_bot_pubkey(EVP_PKEY *pub_key,
                                       const unsigned char *plain,
                                       int plain_len, unsigned char *enc_out) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub_key, NULL);
  int result = -1;

  if (ctx && EVP_PKEY_encrypt_init(ctx) > 0) {
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0) {
      size_t out_len;
      if (EVP_PKEY_encrypt(ctx, NULL, &out_len, plain, plain_len) > 0) {
        if (EVP_PKEY_encrypt(ctx, enc_out, &out_len, plain, plain_len) > 0) {
          result = (int)out_len;
        }
      }
    }
  }

  if (ctx)
    EVP_PKEY_CTX_free(ctx);
  return result;
}

static bool verify_signature_with_bot_pubkey(EVP_PKEY *pub_key,
                                             const unsigned char *data,
                                             int data_len,
                                             const unsigned char *sig,
                                             size_t sig_len) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  bool valid = false;

  if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pub_key) > 0) {
    if (EVP_DigestVerifyUpdate(ctx, data, data_len) > 0) {
      if (EVP_DigestVerifyFinal(ctx, sig, sig_len) == 1) {
        valid = true;
      }
    }
  }

  EVP_MD_CTX_free(ctx);
  return valid;
}

// ============ END OF NEW HELPER FUNCTIONS ============
// REPLACEMENT for bot authentication section in hub_handle_client_data()
// Insert this where it currently handles "ADMIN", "HUB", or bot UUID
// authentication

bool handle_bot_authentication(hub_state_t *state, hub_client_t *client,
                               unsigned char *data, int packet_len) {

  // PHASE 1: Receive UUID (plaintext)
  if (!client->authenticated && client->bot_auth_state == BOT_AUTH_IDLE) {
    // Packet contains plaintext UUID
    char uuid[64];
    int copy_len = (packet_len < 63) ? packet_len : 63;
    memcpy(uuid, data, copy_len);
    uuid[copy_len] = '\0';

    hub_log("[HUB] Bot auth attempt from %s with UUID: %s\n", client->ip, uuid);

    // Check if bot exists and is authorized
    bool authorized = false;
    for (int i = 0; i < state->bot_count; i++) {
      if (strcmp(state->bots[i].uuid, uuid) == 0) {
        authorized = true;
        break;
      }
    }

    if (!authorized) {
      hub_log("[HUB] Unauthorized bot UUID: %s from %s\n", uuid, client->ip);
      add_pending_bot(state, uuid, client->ip);
      record_failed_auth(state, client->ip);
      return false; // Disconnect
    }

    // Load bot's public key
    EVP_PKEY *pub_key = load_bot_public_key(state, uuid);
    if (!pub_key) {
      hub_log("[HUB][ERROR] No public key found for bot %s\n", uuid);
      return false;
    }

    // Generate random challenge
    if (RAND_bytes(client->challenge, 32) != 1) {
      EVP_PKEY_free(pub_key);
      hub_log("[HUB][ERROR] Failed to generate challenge\n");
      return false;
    }

    // Encrypt challenge with bot's public key
    unsigned char enc_challenge[512];
    int enc_len = rsa_encrypt_with_bot_pubkey(pub_key, client->challenge, 32,
                                              enc_challenge);
    EVP_PKEY_free(pub_key);

    if (enc_len <= 0) {
      hub_log("[HUB][ERROR] Failed to encrypt challenge for %s\n", uuid);
      return false;
    }

    // Send encrypted challenge
    uint32_t net_len = htonl(enc_len);
    if (write(client->fd, &net_len, 4) != 4 ||
        write(client->fd, enc_challenge, enc_len) != enc_len) {
      hub_log("[HUB][ERROR] Failed to send challenge to %s\n", uuid);
      return false;
    }

    // Store UUID and update state
    strncpy(client->id, uuid, sizeof(client->id) - 1);
    client->id[sizeof(client->id) - 1] = '\0';
    client->bot_auth_state = BOT_AUTH_CHALLENGE_SENT;
    client->last_seen = time(NULL);

    hub_log("[HUB] Sent challenge to bot %s\n", uuid);
    return true; // Continue
  }

  // PHASE 2: Receive signature
  else if (!client->authenticated &&
           client->bot_auth_state == BOT_AUTH_CHALLENGE_SENT) {
    // Packet contains signature
    hub_log("[HUB] Received signature from bot %s (%d bytes)\n", client->id,
            packet_len);

    // Load bot's public key
    EVP_PKEY *pub_key = load_bot_public_key(state, client->id);
    if (!pub_key) {
      hub_log("[HUB][ERROR] No public key found for bot %s\n", client->id);
      return false;
    }

    // Verify signature
    bool valid = verify_signature_with_bot_pubkey(pub_key, client->challenge,
                                                  32, data, packet_len);

    if (!valid) {
      EVP_PKEY_free(pub_key);
      hub_log("[HUB][ERROR] Invalid signature from bot %s\n", client->id);
      record_failed_auth(state, client->ip);
      return false;
    }

    hub_log("[HUB] Signature verified for bot %s\n", client->id);

    // Generate session key
    if (RAND_bytes(client->session_key, 32) != 1) {
      EVP_PKEY_free(pub_key);
      hub_log("[HUB][ERROR] Failed to generate session key\n");
      return false;
    }

    // Encrypt session key with bot's public key
    unsigned char enc_session_key[512];
    int enc_len = rsa_encrypt_with_bot_pubkey(pub_key, client->session_key, 32,
                                              enc_session_key);
    EVP_PKEY_free(pub_key);

    if (enc_len <= 0) {
      hub_log("[HUB][ERROR] Failed to encrypt session key for %s\n",
              client->id);
      return false;
    }

    // Send encrypted session key
    uint32_t net_len = htonl(enc_len);
    if (write(client->fd, &net_len, 4) != 4 ||
        write(client->fd, enc_session_key, enc_len) != enc_len) {
      hub_log("[HUB][ERROR] Failed to send session key to %s\n", client->id);
      return false;
    }

    // Mark as authenticated
    client->type = CLIENT_BOT;
    client->authenticated = true;
    client->bot_auth_state = BOT_AUTH_COMPLETE;
    client->last_seen = time(NULL);

    // Update "seen" timestamp on successful authentication
    hub_storage_update_entry(state, client->id, "seen", "", "", "", client->last_seen);

    hub_log("[HUB] Bot %s authenticated successfully\n", client->id);
    return true; // Continue
  }

  return false; // Invalid state
}

static void add_pending_bot(hub_state_t *state, const char *uuid,
                            const char *ip) {
  for (int i = 0; i < state->pending_count; i++) {
    if (strcmp(state->pending[i].uuid, uuid) == 0) {
      state->pending[i].last_attempt = time(NULL);
      size_t ip_len = strlen(ip);
      size_t copy_len = (ip_len < sizeof(state->pending[i].ip) - 1)
                            ? ip_len
                            : sizeof(state->pending[i].ip) - 1;
      memcpy(state->pending[i].ip, ip, copy_len);
      state->pending[i].ip[copy_len] = '\0';
      return;
    }
  }

  int idx;
  if (state->pending_count < MAX_PENDING_BOTS) {
    idx = state->pending_count++;
  } else {
    idx = state->pending_head;
    state->pending_head = (state->pending_head + 1) % MAX_PENDING_BOTS;
  }

  pending_bot_t *p = &state->pending[idx];
  memset(p, 0, sizeof(pending_bot_t));

  size_t uuid_len = strlen(uuid);
  size_t copy_uuid_len =
      (uuid_len < sizeof(p->uuid) - 1) ? uuid_len : sizeof(p->uuid) - 1;
  memcpy(p->uuid, uuid, copy_uuid_len);
  p->uuid[copy_uuid_len] = '\0';

  size_t ip_len = strlen(ip);
  size_t copy_ip_len =
      (ip_len < sizeof(p->ip) - 1) ? ip_len : sizeof(p->ip) - 1;
  memcpy(p->ip, ip, copy_ip_len);
  p->ip[copy_ip_len] = '\0';

  strncpy(p->nick, "Unknown", sizeof(p->nick) - 1);
  p->nick[sizeof(p->nick) - 1] = '\0';
  p->last_attempt = time(NULL);
}

static void remove_pending_bot(hub_state_t *state, const char *uuid) {
  for (int i = 0; i < state->pending_count; i++) {
    if (strcmp(state->pending[i].uuid, uuid) == 0) {
      for (int j = i; j < state->pending_count - 1; j++) {
        state->pending[j] = state->pending[j + 1];
      }
      state->pending_count--;
      return;
    }
  }
}

static void broadcast_new_key(hub_state_t *state, const char *new_priv_key, const char *new_pub_key) {
  unsigned char buffer[MAX_BUFFER];
  unsigned char tag[GCM_TAG_LEN];
  unsigned char plain[MAX_BUFFER];

  // Combine private and public keys in payload: "PRIVKEY|||PUBKEY"
  // Using ||| as delimiter since PEM keys contain single | in base64
  char combined_payload[MAX_BUFFER];
  int written = snprintf(combined_payload, sizeof(combined_payload), "%s|||%s", new_priv_key, new_pub_key);
  if (written < 0 || written >= (int)sizeof(combined_payload)) {
    hub_log("[HUB] ERROR: Combined key payload too large for buffer\n");
    return;
  }

  plain[0] = CMD_UPDATE_PUBKEY;
  int payload_len = strlen(combined_payload);
  if (payload_len > (MAX_BUFFER - 10))
    return;

  memcpy(&plain[1], &payload_len, 4);
  memcpy(&plain[5], combined_payload, payload_len);
  int total_plain = 1 + 4 + payload_len;

  int hub_count = 0;

  // Send both private and public keys to peer hubs (they share the same keys for hub-to-hub auth)
  // Do NOT send to bots - they have their own individual keypairs
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->authenticated && c->type == CLIENT_HUB) {
      int enc_len =
          aes_gcm_encrypt(plain, total_plain, c->session_key, buffer + 4, tag);
      if (enc_len > 0) {
        memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
        int packet_len = enc_len + GCM_TAG_LEN;
        uint32_t net_len = htonl(packet_len);
        memcpy(buffer, &net_len, 4);

        if (write(c->fd, buffer, 4 + packet_len) == (4 + packet_len)) {
          hub_count++;
        }
      }
    }
  }
  hub_log("[HUB] Broadcasted new private and public keys to %d peer hubs for rekey.\n", hub_count);
}

static void hub_state_add_bot_memory(hub_state_t *state, const char *uuid,
                                     const char *nick, const char *pub_key) {
  for (int i = 0; i < state->bot_count; i++) {
    if (strcmp(state->bots[i].uuid, uuid) == 0)
      return;
  }

  if (state->bot_count < MAX_BOTS) {
    int idx = state->bot_count++;
    bot_config_t *b = &state->bots[idx];
    memset(b, 0, sizeof(bot_config_t));
    strncpy(b->uuid, uuid, sizeof(b->uuid) - 1);
    b->uuid[sizeof(b->uuid) - 1] = 0;
    b->last_sync_time = 0;

    time_t now = time(NULL);
    hub_storage_update_entry(state, uuid, "n", nick, "", "", now);
    hub_storage_update_entry(state, uuid, "pub", pub_key, "", "", now);
    hub_storage_update_entry(state, uuid, "seen", "", "", "", now);
  }
}

// FIXED: Added comprehensive bounds checking for CMD_ADMIN_LIST_PEERS
void hub_broadcast_mesh_state(hub_state_t *state) {
  char payload[MAX_BUFFER];
  memset(payload, 0, sizeof(payload));
  int offset = 0;
  int written;

  // Format: bind_ip:port:uuid:friendly_name|
  written = snprintf(payload + offset, MAX_BUFFER - offset, "%s:%d:%s:%s|",
                     state->bind_ip, state->port,
                     state->hub_uuid[0] ? state->hub_uuid : "-",
                     state->hub_friendly_name[0] ? state->hub_friendly_name : "-");
  if (written < 0 || written >= MAX_BUFFER - offset)
    return;
  offset += written;

  for (int i = 0; i < state->peer_count; i++) {
    int is_up = 0;
    for (int c = 0; c < state->client_count; c++) {
      if (state->clients[c]->type == CLIENT_HUB &&
          state->clients[c]->authenticated) {
        if (state->peers[i].fd == state->clients[c]->fd &&
            state->peers[i].fd > 0) {
          is_up = 1;
          break;
        }
      }
    }

    // Format: ip:port:is_up:uuid:friendly_name,
    written = snprintf(payload + offset, MAX_BUFFER - offset, "%s:%d:%d:%s:%s,",
                       state->peers[i].ip, state->peers[i].port, is_up,
                       state->peers[i].uuid[0] ? state->peers[i].uuid : "-",
                       state->peers[i].friendly_name[0] ? state->peers[i].friendly_name : "-");
    if (written < 0 || written >= MAX_BUFFER - offset)
      break;
    offset += written;
  }

  if (offset < MAX_BUFFER - 1) {
    payload[offset++] = ';';
    payload[offset] = 0;
  }

  // Aggregate gossip from peers
  for (int i = 0; i < state->peer_count; i++) {
    if (state->peers[i].connected && strlen(state->peers[i].last_gossip) > 0) {
      char *body = strchr(state->peers[i].last_gossip, '|');
      if (!body)
        continue;

      char work_buf[MAX_BUFFER];
      snprintf(work_buf, sizeof(work_buf), "%.*s", MAX_BUFFER - 1, body + 1);

      char *saveptr;
      char *block = strtok_r(work_buf, ";", &saveptr);

      while (block) {
        char owner_chk[256];
        if (sscanf(block, "%255[^|]", owner_chk) == 1) {
          char my_sig[128];
          snprintf(my_sig, sizeof(my_sig), "%s:%d", state->bind_ip, state->port);

          if (strcmp(owner_chk, my_sig) != 0) {
            char search_sig[260];
            snprintf(search_sig, sizeof(search_sig), "%s|", owner_chk);

            if (strstr(payload, search_sig) == NULL) {
              int blk_len = strlen(block);
              if (offset + blk_len + 2 < MAX_BUFFER) {
                // SECURITY FIX: Use memcpy instead of strcpy for bounded copy
                memcpy(payload + offset, block, blk_len);
                payload[offset + blk_len] = '\0';
                offset += blk_len;
                payload[offset++] = ';';
                payload[offset] = 0;
              }
            }
          }
        }
        block = strtok_r(NULL, ";", &saveptr);
      }
    }
  }

  int connected_peers = 0;
  for (int i = 0; i < state->peer_count; i++) {
    if (state->peers[i].connected)
      connected_peers++;
  }

  int active_bots = 0;
  char bot_uuid_list[MAX_BUFFER];
  int uuid_offset = 0;
  bot_uuid_list[0] = '\0';

  for (int i = 0; i < state->client_count; i++) {
    if (state->clients[i]->type == CLIENT_BOT &&
        state->clients[i]->authenticated) {
      active_bots++;
      // Add bot UUID to list
      if (uuid_offset > 0 && uuid_offset < MAX_BUFFER - 2) {
        bot_uuid_list[uuid_offset++] = ',';
      }
      int uuid_len = strlen(state->clients[i]->id);
      if (uuid_offset + uuid_len < MAX_BUFFER - 1) {
        memcpy(bot_uuid_list + uuid_offset, state->clients[i]->id, uuid_len);
        uuid_offset += uuid_len;
        bot_uuid_list[uuid_offset] = '\0';
      }
    }
  }

  unsigned char buffer[MAX_BUFFER];
  unsigned char plain[MAX_BUFFER];
  unsigned char tag[GCM_TAG_LEN];

  plain[0] = CMD_MESH_STATE;
  char final_packet[MAX_BUFFER];

  written = snprintf(final_packet, sizeof(final_packet), "%d:%d:%d:%s|%s",
                     connected_peers, state->peer_count, active_bots,
                     bot_uuid_list[0] ? bot_uuid_list : "-", payload);
  if (written < 0 || written >= (int)sizeof(final_packet))
    return;

  int payload_len = strlen(final_packet);
  if (payload_len > MAX_BUFFER - 100) {
    payload_len = MAX_BUFFER - 100;
  }

  memcpy(&plain[1], &payload_len, 4);
  memcpy(&plain[5], final_packet, payload_len);
  int total_plain = 1 + 4 + payload_len;

  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type == CLIENT_HUB && c->authenticated) {
      int enc_len =
          aes_gcm_encrypt(plain, total_plain, c->session_key, buffer + 4, tag);
      if (enc_len > 0) {
        memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
        uint32_t net_len = htonl(enc_len + GCM_TAG_LEN);
        memcpy(buffer, &net_len, 4);
        if (write(c->fd, buffer, 4 + enc_len + GCM_TAG_LEN) <= 0) {
          hub_log("[MESH] Failed to send mesh state to peer\n");
        }
      }
    }
  }
}

static void process_mesh_state(hub_state_t *state, hub_client_t *c,
                               char *payload) {
  int remote_conn = 0, remote_total = 0, remote_bots = 0;

  if (sscanf(payload, "%d:%d:%d", &remote_conn, &remote_total, &remote_bots) >=
      2) {
    for (int i = 0; i < state->peer_count; i++) {
      if (state->peers[i].connected && state->peers[i].fd == c->fd) {
        state->peers[i].last_mesh_report = time(NULL);

        // Safe truncating copy with explicit length calculation
        size_t payload_len = strlen(payload);
        size_t max_len = sizeof(state->peers[i].last_gossip) - 1;
        size_t copy_len = (payload_len < max_len) ? payload_len : max_len;

        memcpy(state->peers[i].last_gossip, payload, copy_len);
        state->peers[i].last_gossip[copy_len] = '\0';

        // Extract remote hub's friendly_name and UUID from gossip and update peer record
        // Gossip format: connected:total:bots:bot_list|ip:port:uuid:friendly_name|...
        char *mesh_start = strchr(payload, '|');
        if (mesh_start) {
          mesh_start++; // Skip the first |
          char remote_ip[256], remote_uuid[64], remote_name[64];
          int remote_port;
          memset(remote_uuid, 0, sizeof(remote_uuid));
          memset(remote_name, 0, sizeof(remote_name));

          // Parse: ip:port:uuid:friendly_name|
          int fields = sscanf(mesh_start, "%255[^:]:%d:%63[^:]:%63[^|]",
                             remote_ip, &remote_port, remote_uuid, remote_name);

          bool config_updated = false;

          // Update friendly_name if it changed
          if (fields >= 4 && remote_name[0] && strcmp(remote_name, "-") != 0) {
            if (strcmp(state->peers[i].friendly_name, remote_name) != 0) {
              snprintf(state->peers[i].friendly_name,
                      sizeof(state->peers[i].friendly_name), "%s", remote_name);
              hub_log("[MESH] Updated peer friendly_name to: %s\n", remote_name);
              config_updated = true;
            }
          }

          // Also update UUID if it changed (in case peer was added without UUID)
          if (fields >= 3 && remote_uuid[0] && strcmp(remote_uuid, "-") != 0) {
            if (!state->peers[i].uuid[0] ||
                strcmp(state->peers[i].uuid, remote_uuid) != 0) {
              snprintf(state->peers[i].uuid,
                      sizeof(state->peers[i].uuid), "%s", remote_uuid);
              hub_log("[MESH] Updated peer UUID to: %s\n", remote_uuid);
              config_updated = true;
            }
          }

          // Write config once if anything changed
          if (config_updated) {
            hub_config_write(state);
          }
        }
        return;
      }
    }
  }
}

void hub_broadcast_sync_to_peers(hub_state_t *state, const char *payload,
                                 int exclude_fd) {
  unsigned char buffer[MAX_BUFFER];
  unsigned char plain[MAX_BUFFER];
  unsigned char tag[GCM_TAG_LEN];

  plain[0] = CMD_PEER_SYNC;
  int payload_len = strlen(payload);
  if (payload_len > (MAX_BUFFER - 10))
    return;

  memcpy(&plain[1], &payload_len, 4);
  memcpy(&plain[5], payload, payload_len);
  int total_plain = 1 + 4 + payload_len;

  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type == CLIENT_HUB && c->authenticated && c->fd != exclude_fd) {
      int cipher_len =
          aes_gcm_encrypt(plain, total_plain, c->session_key, buffer + 4, tag);
      if (cipher_len > 0) {
        memcpy(buffer + 4 + cipher_len, tag, GCM_TAG_LEN);
        int packet_len = cipher_len + GCM_TAG_LEN;
        uint32_t nl = htonl(packet_len);
        memcpy(buffer, &nl, 4);

        if (write(c->fd, buffer, 4 + packet_len) <= 0) {
          hub_log("[MESH] Failed to broadcast to peer %s\n", c->ip);
        }
      }
    }
  }
}

// NEW FUNCTION: Broadcast full config to all connected bots to ensure
// consistency
static void broadcast_full_config_to_all_bots(hub_state_t *state) {
  int sent_count = 0;
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type == CLIENT_BOT && c->authenticated) {
      send_config_to_bot(state, c);
      sent_count++;
    }
  }
  hub_log("[HUB] Broadcasted FULL config to %d bots\n", sent_count);
}

static void process_bot_config_push(hub_state_t *state, hub_client_t *client,
                                    char *payload) {
  if (client->type != CLIENT_BOT || !client->authenticated) {
    hub_log("[HUB] Rejected config push from non-bot client\n");
    return;
  }

  hub_log("[HUB] Processing config push from %s\n", client->id);

  char work_buf[MAX_BUFFER];
  strncpy(work_buf, payload, sizeof(work_buf) - 1);
  work_buf[sizeof(work_buf) - 1] = '\0';

  char *saveptr;
  char *line = strtok_r(work_buf, "\n", &saveptr);
  int updates = 0;
  char sync_buffer[MAX_BUFFER];
  int sync_offset = 0;

  while (line) {
    if (strlen(line) < 2 || line[0] == '#') {
      line = strtok_r(NULL, "\n", &saveptr);
      continue;
    }

    // Parse line: type|data
    char type = line[0];
    if (line[1] != '|') {
      line = strtok_r(NULL, "\n", &saveptr);
      continue;
    }

    char *data = line + 2;

    // Special handling for different types
    if (type == 'c') {
      // Channel: c|#chan|key|add|timestamp
      char chan[MAX_CHAN], key[MAX_KEY], op[8];
      long ts;
      int parsed =
          sscanf(data, "%64[^|]|%30[^|]|%7[^|]|%ld", chan, key, op, &ts);
      if (parsed < 3) {
        parsed = sscanf(data, "%64[^|]||%7[^|]|%ld", chan, op, &ts);
        key[0] = '\0';
      }

      if (parsed >= 3) {
        bool accepted = hub_storage_update_entry(state, client->id, "c", chan, key, op, ts);
        hub_log("[HUB-DEBUG] Channel %s: ts=%ld op=%s -> %s\n", chan, ts, op, accepted ? "ACCEPTED" : "REJECTED");
        if (accepted) {
          updates++;
          // Add to sync buffer for peer broadcast
          int w = snprintf(
              sync_buffer + sync_offset, sizeof(sync_buffer) - sync_offset,
              "b|%s|c|%s|%s|%s|%ld\n", client->id, chan, key, op, ts);
          if (w > 0)
            sync_offset += w;
        }
      }
    } else if (type == 'm') {
      // Mask: m|mask|add|timestamp
      char mask[MAX_MASK_LEN], op[8];
      long ts;
      if (sscanf(data, "%127[^|]|%7[^|]|%ld", mask, op, &ts) == 3) {
        bool accepted = hub_storage_update_entry(state, client->id, "m", mask, "", op, ts);
        hub_log("[HUB-DEBUG] Mask %s: ts=%ld op=%s -> %s\n", mask, ts, op, accepted ? "ACCEPTED" : "REJECTED");
        if (accepted) {
          updates++;
          int w = snprintf(sync_buffer + sync_offset,
                           sizeof(sync_buffer) - sync_offset,
                           "b|%s|m|%s|%s|%ld\n", client->id, mask, op, ts);
          if (w > 0)
            sync_offset += w;
        }
      }
    } else if (type == 'o') {
      // Oper: o|mask|password|add|timestamp
      char mask[MAX_MASK_LEN], pass[MAX_PASS], op[8];
      long ts;
      if (sscanf(data, "%127[^|]|%127[^|]|%7[^|]|%ld", mask, pass, op, &ts) ==
          4) {
        // Validate password exists
        if (pass[0] != '\0') {
          bool accepted = hub_storage_update_entry(state, client->id, "o", mask, pass, op, ts);
          hub_log("[HUB-DEBUG] Oper %s: ts=%ld op=%s -> %s\n", mask, ts, op, accepted ? "ACCEPTED" : "REJECTED");
          if (accepted) {
            updates++;
            int w = snprintf(
                sync_buffer + sync_offset, sizeof(sync_buffer) - sync_offset,
                "b|%s|o|%s|%s|%s|%ld\n", client->id, mask, pass, op, ts);
            if (w > 0)
              sync_offset += w;
          }
        } else {
          hub_log("[HUB-DEBUG] Oper %s: REJECTED (no password)\n", mask);
        }
      }
    } else if (type == 'a') {
      // Admin password: a|password|timestamp
      char pass[MAX_PASS];
      long ts = 0;
      int parsed = sscanf(data, "%127[^|]|%ld", pass, &ts);
      if (parsed < 1) {
        // Fallback: no delimiter found, treat entire data as password
        strncpy(pass, data, MAX_PASS - 1);
        pass[MAX_PASS - 1] = '\0';
        ts = time(NULL);
      } else if (parsed < 2 || ts <= 0) {
        // Password found but no valid timestamp
        ts = time(NULL);
      }
      bool accepted = hub_storage_update_entry(state, client->id, "a", pass, "", "", ts);
      hub_log("[HUB-DEBUG] AdminPass: ts=%ld -> %s\n", ts, accepted ? "ACCEPTED" : "REJECTED");
      if (accepted) {
        updates++;
        // Broadcast as global admin password update (WITHOUT b| prefix)
        int w =
            snprintf(sync_buffer + sync_offset,
                     sizeof(sync_buffer) - sync_offset, "a|%s|%ld\n", pass, ts);
        if (w > 0)
          sync_offset += w;
      }
    } else if (type == 'p') {
      // Bot password: p|password|timestamp
      char pass[MAX_PASS];
      long ts = 0;
      int parsed = sscanf(data, "%127[^|]|%ld", pass, &ts);
      if (parsed < 1) {
        // Fallback: no delimiter found, treat entire data as password
        strncpy(pass, data, MAX_PASS - 1);
        pass[MAX_PASS - 1] = '\0';
        ts = time(NULL);
      } else if (parsed < 2 || ts <= 0) {
        // Password found but no valid timestamp
        ts = time(NULL);
      }
      bool accepted = hub_storage_update_entry(state, client->id, "p", pass, "", "", ts);
      hub_log("[HUB-DEBUG] BotPass: ts=%ld -> %s\n", ts, accepted ? "ACCEPTED" : "REJECTED");
      if (accepted) {
        updates++;
        // Broadcast as global bot password update (WITHOUT b| prefix)
        int w =
            snprintf(sync_buffer + sync_offset,
                     sizeof(sync_buffer) - sync_offset, "p|%s|%ld\n", pass, ts);
        if (w > 0)
          sync_offset += w;
      }
    } else if (type == 'h') {
      // Hostmask: h|nick!user@host|timestamp
      char hostmask[256];
      long ts;
      if (sscanf(data, "%255[^|]|%ld", hostmask, &ts) == 2) {
        bool accepted = hub_storage_update_entry(state, client->id, "h", hostmask, "", "", ts);
        hub_log("[HUB-DEBUG] Hostmask %s: ts=%ld -> %s\n", hostmask, ts, accepted ? "ACCEPTED" : "REJECTED");
        if (accepted) {
          updates++;
          // Broadcast in bot entry format: b|uuid|h|hostmask|timestamp
          int w = snprintf(sync_buffer + sync_offset,
                           sizeof(sync_buffer) - sync_offset, "b|%s|h|%s|%ld\n",
                           client->id, hostmask, ts);
          if (w > 0)
            sync_offset += w;
        }
      }
    } else if (type == 'n') {
      // Nick: n|nickname|timestamp
      char nick[MAX_NICK];
      long ts;
      if (sscanf(data, "%32[^|]|%ld", nick, &ts) == 2) {
        bool accepted = hub_storage_update_entry(state, client->id, "n", nick, "", "", ts);
        hub_log("[HUB-DEBUG] Nick %s: ts=%ld -> %s\n", nick, ts, accepted ? "ACCEPTED" : "REJECTED");
        if (accepted) {
          updates++;
          // Broadcast in bot entry format: b|uuid|n|nickname|timestamp
          int w = snprintf(sync_buffer + sync_offset,
                           sizeof(sync_buffer) - sync_offset, "b|%s|n|%s|%ld\n",
                           client->id, nick, ts);
          if (w > 0)
            sync_offset += w;
        }
      }
    }

    line = strtok_r(NULL, "\n", &saveptr);
  }

  if (updates > 0) {
    hub_log("[HUB] Applied %d updates from %s\n", updates, client->id);

    // Update "seen" timestamp to track last successful sync
    time_t now = time(NULL);
    hub_storage_update_entry(state, client->id, "seen", "", "", "", now);

    hub_config_write(state);

    // Broadcast to peer hubs
    if (sync_offset > 0) {
      hub_broadcast_sync_to_peers(state, sync_buffer, client->fd);
    }

    // Broadcast to other bots
    // FIXED: Send FULL config to all connected bots to ensure consistency
    // This fixes issues where bots might miss updates if they were temporarily
    // unreachable
    broadcast_full_config_to_all_bots(state);
  }
}

void hub_generate_sync_packet(hub_state_t *state, char *buffer, int max_len) {
  int offset = 0;
  int written;
  buffer[0] = 0;

  // 1. Include global entries (c, m, o, a, p)
  // Note: h/n/w/x in global_entries are hub-only local metadata
  // - h/n: hub name/bind settings (shouldn't exist in global_entries)
  // - w/x: allowlist/denylist (local-only IP access control)
  // Bot-specific h/n (like b|uuid|h|..., b|uuid|n|...) are synced in the bot loop below
  for (int i = 0; i < state->global_entry_count; i++) {
    config_entry_t *e = &state->global_entries[i];
    // Skip local-only configuration: h/n (hub metadata), w/x (allowlist/denylist)
    if (strcmp(e->key, "h") == 0 || strcmp(e->key, "n") == 0 ||
        strcmp(e->key, "w") == 0 || strcmp(e->key, "x") == 0)
      continue;
    if (max_len - offset <= 1)
      break;

    // Format: key|value|timestamp (same as config file format)
    written = snprintf(buffer + offset, max_len - offset, "%s|%s|%ld\n",
                       e->key, e->value, (long)e->timestamp);
    if (written < 0 || written >= (max_len - offset))
      break;
    offset += written;
  }

  // 2. Include bot entries
  for (int i = 0; i < state->bot_count; i++) {
    bot_config_t *b = &state->bots[i];
    if (max_len - offset <= 1)
      break;

    for (int j = 0; j < b->entry_count; j++) {
      if (max_len - offset <= 1)
        break;

      // Special handling for "seen" and "t" - omit value field
      if (strcmp(b->entries[j].key, "seen") == 0 || strcmp(b->entries[j].key, "t") == 0) {
        written = snprintf(buffer + offset, max_len - offset, "b|%s|%s|%ld\n",
                           b->uuid, b->entries[j].key,
                           (long)b->entries[j].timestamp);
      } else {
        written = snprintf(buffer + offset, max_len - offset, "b|%s|%s|%s|%ld\n",
                           b->uuid, b->entries[j].key, b->entries[j].value,
                           (long)b->entries[j].timestamp);
      }
      if (written < 0 || written >= (max_len - offset))
        break;
      offset += written;
    }
  }
}

// Helper: Check if a key is a global config key
static bool is_global_key(const char *key) {
  return (strcmp(key, "c") == 0 || strcmp(key, "m") == 0 ||
          strcmp(key, "o") == 0 || strcmp(key, "a") == 0 ||
          strcmp(key, "p") == 0);
}

// Helper: Store global entry directly without re-formatting (value is already combined)
static bool store_global_entry_raw(hub_state_t *state, const char *key,
                                   const char *value, time_t ts) {
  bool is_singleton = (strcmp(key, "a") == 0 || strcmp(key, "p") == 0);

  for (int i = 0; i < state->global_entry_count; i++) {
    bool match = false;
    if (is_singleton) {
      if (strcmp(state->global_entries[i].key, key) == 0)
        match = true;
    } else {
      // List match: compare key and first part of value (before first |)
      char stored_first[256], incoming_first[256];
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
      const char *incoming_pipe = strchr(value, '|');
      if (incoming_pipe) {
        size_t len = incoming_pipe - value;
        if (len >= sizeof(incoming_first))
          len = sizeof(incoming_first) - 1;
        memcpy(incoming_first, value, len);
        incoming_first[len] = 0;
      } else {
        strncpy(incoming_first, value, sizeof(incoming_first) - 1);
        incoming_first[sizeof(incoming_first) - 1] = 0;
      }
      if (strcmp(state->global_entries[i].key, key) == 0 &&
          strcmp(stored_first, incoming_first) == 0) {
        match = true;
      }
    }

    if (match) {
      if (ts > state->global_entries[i].timestamp) {
        snprintf(state->global_entries[i].value,
                 sizeof(state->global_entries[i].value), "%s", value);
        state->global_entries[i].timestamp = ts;
        return true;
      }
      return false;
    }
  }

  // Add new entry
  if (state->global_entry_count < MAX_BOT_ENTRIES) {
    snprintf(state->global_entries[state->global_entry_count].key,
             sizeof(state->global_entries[state->global_entry_count].key), "%s",
             key);
    snprintf(state->global_entries[state->global_entry_count].value,
             sizeof(state->global_entries[state->global_entry_count].value),
             "%s", value);
    state->global_entries[state->global_entry_count].timestamp = ts;
    state->global_entry_count++;
    return true;
  }
  return false;
}

static void process_peer_sync(hub_state_t *state, char *payload,
                              int origin_fd) {
  char *saveptr;
  char work_buf[MAX_BUFFER];
  snprintf(work_buf, sizeof(work_buf), "%.*s", MAX_BUFFER - 1, payload);

  char *line = strtok_r(work_buf, "\n", &saveptr);
  int updates = 0;
  char forward_buf[MAX_BUFFER];
  int fwd_offset = 0;
  forward_buf[0] = 0;

  while (line) {
    // Check for PURGE command
    if (strncmp(line, "PURGE|", 6) == 0) {
      char *payload = line + 6; // Skip "PURGE|"
      char param[32];
      long ts;
      if (sscanf(payload, "%31[^|]|%ld", param, &ts) == 2) {
        bool immediate = (strcmp(param, "immediate") == 0);
        hub_log("[MESH] Received PURGE from peer: %s\n",
                immediate ? "immediate" : param);

        // Execute the purge locally
        char purge_log[MAX_BUFFER];
        int purged = hub_execute_purge(state, param, immediate,
                                        purge_log, sizeof(purge_log));

        if (purged > 0) {
          hub_log("[MESH] Purged %d entries from peer sync\n", purged);
          updates += purged;

          // Re-forward to other peers (epidemic broadcast)
          if (origin_fd != -1) {
            hub_broadcast_sync_to_peers(state, line, origin_fd);
          }
        }
      }
      line = strtok_r(NULL, "\n", &saveptr);
      continue;
    }

    // Check if this is a global entry (format: key|value|timestamp)
    // Global keys: c, m, o, a, p (NOT starting with b|)
    if (strncmp(line, "b|", 2) != 0) {
      char *p1 = strchr(line, '|');
      if (p1) {
        // Extract key (before first |)
        char key[32];
        size_t key_len = p1 - line;
        if (key_len < sizeof(key)) {
          memcpy(key, line, key_len);
          key[key_len] = 0;

          if (is_global_key(key)) {
            // Parse: key|value|timestamp (value may contain |)
            char *p_last = strrchr(p1 + 1, '|');
            if (p_last && p_last > p1) {
              char val[1024];
              size_t val_len = p_last - (p1 + 1);
              if (val_len < sizeof(val)) {
                memcpy(val, p1 + 1, val_len);
                val[val_len] = 0;
                long ts = atol(p_last + 1);

                if (store_global_entry_raw(state, key, val, ts)) {
                  updates++;
                  // Forward to other peers
                  if (sizeof(forward_buf) - fwd_offset > 1200) {
                    int w = snprintf(forward_buf + fwd_offset,
                                     sizeof(forward_buf) - fwd_offset,
                                     "%s|%s|%ld\n", key, val, ts);
                    if (w > 0 && w < (int)(sizeof(forward_buf) - fwd_offset)) {
                      fwd_offset += w;
                    }
                  }
                }
              }
            }
            line = strtok_r(NULL, "\n", &saveptr);
            continue;
          }
        }
      }
    }

    // Handle bot entries (format: b|uuid|key|value|timestamp)
    char *ptr = line;
    if (strncmp(line, "b|", 2) == 0) {
      ptr = line + 2;
    }

    char uuid[64], key[32], val[1024];
    long ts;

    char *p1 = strchr(ptr, '|');
    if (p1) {
      *p1 = 0;
      char *p2 = strchr(p1 + 1, '|');
      if (p2) {
        *p2 = 0;
        char *p3 = strrchr(p2 + 1, '|');
        if (p3) {
          *p3 = 0;
          strncpy(uuid, ptr, sizeof(uuid) - 1);
          uuid[sizeof(uuid) - 1] = 0;
          strncpy(key, p1 + 1, sizeof(key) - 1);
          key[sizeof(key) - 1] = 0;
          strncpy(val, p2 + 1, sizeof(val) - 1);
          val[sizeof(val) - 1] = 0;
          ts = atol(p3 + 1);

          // For c/m/o keys, parse the combined value format
          char parsed_val[512] = "", parsed_extra[256] = "", parsed_op[16] = "";
          if (strcmp(key, "c") == 0 || strcmp(key, "o") == 0) {
            // Format: value|extra|op or value||op
            char *vp1 = strchr(val, '|');
            if (vp1) {
              *vp1 = 0;
              size_t len = strlen(val);
              if (len >= sizeof(parsed_val)) len = sizeof(parsed_val) - 1;
              memcpy(parsed_val, val, len);
              parsed_val[len] = 0;
              char *vp2 = strchr(vp1 + 1, '|');
              if (vp2) {
                *vp2 = 0;
                len = strlen(vp1 + 1);
                if (len >= sizeof(parsed_extra)) len = sizeof(parsed_extra) - 1;
                memcpy(parsed_extra, vp1 + 1, len);
                parsed_extra[len] = 0;
                len = strlen(vp2 + 1);
                if (len >= sizeof(parsed_op)) len = sizeof(parsed_op) - 1;
                memcpy(parsed_op, vp2 + 1, len);
                parsed_op[len] = 0;
              }
            }
          } else if (strcmp(key, "m") == 0) {
            // Format: value|op
            char *vp1 = strchr(val, '|');
            if (vp1) {
              *vp1 = 0;
              size_t len = strlen(val);
              if (len >= sizeof(parsed_val)) len = sizeof(parsed_val) - 1;
              memcpy(parsed_val, val, len);
              parsed_val[len] = 0;
              len = strlen(vp1 + 1);
              if (len >= sizeof(parsed_op)) len = sizeof(parsed_op) - 1;
              memcpy(parsed_op, vp1 + 1, len);
              parsed_op[len] = 0;
            }
          }
          // For other keys (pub, h, n, etc.): leave parsed_val empty
          // so hub_storage_update_entry will use the original val buffer

          if (hub_storage_update_entry(state, uuid, key,
              parsed_val[0] ? parsed_val : val,
              parsed_extra,
              parsed_op, ts)) {
            updates++;

            if (sizeof(forward_buf) - fwd_offset > 1200) {
              int w = snprintf(forward_buf + fwd_offset,
                               sizeof(forward_buf) - fwd_offset,
                               "b|%s|%s|%s|%ld\n", uuid, key, val, ts);
              if (w > 0 && w < (int)(sizeof(forward_buf) - fwd_offset)) {
                fwd_offset += w;
              }
            }
          }
        }
      }
    }
    line = strtok_r(NULL, "\n", &saveptr);
  }

  if (updates > 0) {
    hub_config_write(state);
    hub_log("[MESH] Synced %d entries from Peer.\n", updates);

    if (fwd_offset > 0) {
      hub_broadcast_sync_to_peers(state, forward_buf, origin_fd);
    }

    // Broadcast full config to all connected bots to ensure they receive peer updates
    broadcast_full_config_to_all_bots(state);
  }
}

static bool send_response(hub_state_t *state, hub_client_t *client,
                          const char *msg) {
  unsigned char buffer[MAX_BUFFER];
  unsigned char tag[GCM_TAG_LEN];
  int len = strlen(msg);

  int enc_len = aes_gcm_encrypt((unsigned char *)msg, len, client->session_key,
                                buffer + 4, tag);
  if (enc_len > 0) {
    memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
    uint32_t net_len = htonl(enc_len + GCM_TAG_LEN);
    memcpy(buffer, &net_len, 4);

    if (write(client->fd, buffer, 4 + enc_len + GCM_TAG_LEN) !=
        (4 + enc_len + GCM_TAG_LEN)) {
      hub_disconnect_client(state, client);
      return false;
    }
  }
  return true;
}

static bool send_pong(hub_state_t *state, hub_client_t *c) {
  unsigned char buffer[MAX_BUFFER];
  unsigned char tag[GCM_TAG_LEN];
  unsigned char plain[16];

  plain[0] = CMD_PING;
  uint32_t zero = 0;
  memcpy(&plain[1], &zero, 4);

  int enc_len = aes_gcm_encrypt(plain, 5, c->session_key, buffer + 4, tag);
  if (enc_len > 0) {
    memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
    uint32_t net_len = htonl(enc_len + GCM_TAG_LEN);
    memcpy(buffer, &net_len, 4);

    if (write(c->fd, buffer, 4 + enc_len + GCM_TAG_LEN) !=
        (4 + enc_len + GCM_TAG_LEN)) {
      hub_disconnect_client(state, c);
      return false;
    }
  }
  return true;
}

// Broadcast config update to all connected bots
static void hub_broadcast_config_to_bots(hub_state_t *state,
                                          const char *config_line) {
  hub_log("[HUB] Broadcasting config update to all bots: %s", config_line);

  for (int i = 0; i < state->client_count; i++) {
    if (state->clients[i]->type == CLIENT_BOT &&
        state->clients[i]->authenticated) {
      send_config_to_bot(state, state->clients[i]);
    }
  }
}

// Execute tombstone purge (can be called manually or by scheduler)
int hub_execute_purge(hub_state_t *state, const char *days_str,
                      bool immediate, char *log_out, int log_max_len) {
  int days = 30;

  if (!immediate && days_str && strlen(days_str) > 0) {
    days = atoi(days_str);
    if (days <= 0) days = 30;
  }

  time_t now = time(NULL);
  time_t cutoff = now - (days * 24 * 60 * 60);
  int purged_count = 0;
  int log_offset = 0;

  if (log_out && log_max_len > 0) {
    log_out[0] = '\0';
  }

  // Create a new global_entries array without tombstoned items
  config_entry_t new_entries[MAX_BOT_ENTRIES];
  int new_count = 0;

  for (int i = 0; i < state->global_entry_count; i++) {
    bool is_tombstone = false;

    // Check if this entry is tombstoned by inspecting the last pipe-delimited
    // field. Using strrchr avoids sscanf's inability to match empty fields,
    // which breaks detection of channel tombstones stored as "name||del".
    if (strcmp(state->global_entries[i].key, "c") == 0 ||
        strcmp(state->global_entries[i].key, "m") == 0 ||
        strcmp(state->global_entries[i].key, "o") == 0) {
      const char *last_pipe = strrchr(state->global_entries[i].value, '|');
      if (last_pipe && strcmp(last_pipe + 1, "del") == 0) {
        is_tombstone = true;
      }
    }

    // Decide whether to purge this entry
    if (is_tombstone && (immediate || state->global_entries[i].timestamp < cutoff)) {
      purged_count++;
      if (log_out && log_max_len > 0) {
        int written = snprintf(log_out + log_offset, log_max_len - log_offset,
                               "  Purged: %s|%s\n",
                               state->global_entries[i].key,
                               state->global_entries[i].value);
        if (written > 0 && written < (log_max_len - log_offset)) {
          log_offset += written;
        }
      }
    } else {
      // Keep this entry
      if (new_count < MAX_BOT_ENTRIES) {
        memcpy(&new_entries[new_count], &state->global_entries[i], sizeof(config_entry_t));
        new_count++;
      }
    }
  }

  // Update state with new global entries
  memcpy(state->global_entries, new_entries, sizeof(config_entry_t) * new_count);
  state->global_entry_count = new_count;

  // Purge tombstoned bots (is_active=false with a d=1 entry).
  // Peer hubs accumulate these when the initiating hub broadcasts a deletion.
  bot_config_t new_bots[MAX_BOTS];
  int new_bot_count = 0;

  for (int i = 0; i < state->bot_count; i++) {
    bot_config_t *b = &state->bots[i];
    if (!b->is_active) {
      // Find the deletion timestamp from the d=1 entry
      time_t del_ts = 0;
      for (int j = 0; j < b->entry_count; j++) {
        if (strcmp(b->entries[j].key, "d") == 0 &&
            strcmp(b->entries[j].value, "1") == 0) {
          del_ts = b->entries[j].timestamp;
          break;
        }
      }

      if (immediate || (del_ts > 0 && del_ts < cutoff)) {
        purged_count++;
        if (log_out && log_max_len > 0) {
          // Find nickname for the log line
          char bot_nick[32] = "";
          for (int j = 0; j < b->entry_count; j++) {
            if (strcmp(b->entries[j].key, "n") == 0) {
              snprintf(bot_nick, sizeof(bot_nick), "%s", b->entries[j].value);
              break;
            }
          }
          int written;
          if (bot_nick[0]) {
            written = snprintf(log_out + log_offset, log_max_len - log_offset,
                               "  Purged bot: %s (%s)\n", b->uuid, bot_nick);
          } else {
            written = snprintf(log_out + log_offset, log_max_len - log_offset,
                               "  Purged bot: %s\n", b->uuid);
          }
          if (written > 0 && written < (log_max_len - log_offset)) {
            log_offset += written;
          }
        }
        continue; // don't copy this bot to new_bots
      }
    }
    if (new_bot_count < MAX_BOTS) {
      memcpy(&new_bots[new_bot_count++], b, sizeof(bot_config_t));
    }
  }

  memcpy(state->bots, new_bots, sizeof(bot_config_t) * new_bot_count);
  state->bot_count = new_bot_count;

  // Write config to disk
  hub_config_write(state);

  // Broadcast purge to bots so they can purge their local copies
  char purge_msg[256];
  snprintf(purge_msg, sizeof(purge_msg), "PURGE|%s|%ld\n",
           immediate ? "immediate" : (days_str ? days_str : "30"), (long)now);
  hub_broadcast_config_to_bots(state, purge_msg);
  hub_broadcast_sync_to_peers(state, purge_msg, -1);

  return purged_count;
}

static bool handle_admin_command(hub_state_t *state, hub_client_t *client,
                                 int cmd, char *payload) {
  char response[MAX_BUFFER];
  int offset;
  int written;

  switch (cmd) {
    // case CMD_ADMIN_LIST_FULL:
    //     hub_storage_get_full_list(state, response, sizeof(response));
    //     return send_response(state, client, response);

  case CMD_ADMIN_LIST_SUMMARY:
    hub_storage_get_summary_list(state, response, sizeof(response));
    return send_response(state, client, response);

  case CMD_ADMIN_GET_PENDING: {
    offset = 0;
    if (state->pending_count == 0) {
      strcpy(response, "No pending bots.");
    } else {
      written = snprintf(response, sizeof(response),
                         "--- Pending Authorization ---\n");
      if (written >= (int)sizeof(response))
        return send_response(state, client, "Buffer overflow");
      offset += written;

      for (int i = 0; i < state->pending_count; i++) {
        struct tm *t = localtime(&state->pending[i].last_attempt);
        char tbuf[64];
        strftime(tbuf, sizeof(tbuf), "%H:%M:%S", t);

        written = snprintf(response + offset, sizeof(response) - offset,
                           "[%d] %s | IP: %s\n", i + 1, state->pending[i].uuid,
                           state->pending[i].ip);
        if (written >= (int)(sizeof(response) - offset))
          break;
        offset += written;
      }
    }
    return send_response(state, client, response);
  }
  case CMD_ADMIN_REKEY_BOT:
    if (payload && strlen(payload) > 0) {
      // Find bot by UUID
      bot_config_t *bot = NULL;
      for (int i = 0; i < state->bot_count; i++) {
        if (strcmp(state->bots[i].uuid, payload) == 0) {
          bot = &state->bots[i];
          break;
        }
      }

      if (!bot) {
        return send_response(state, client, "ERROR|Bot not found");
      }

      // Get bot nickname
      char nick[64] = "Unknown";
      for (int i = 0; i < bot->entry_count; i++) {
        if (strcmp(bot->entries[i].key, "n") == 0) {
          strncpy(nick, bot->entries[i].value, sizeof(nick) - 1);
          nick[sizeof(nick) - 1] = 0;
          break;
        }
      }

      // Generate new keypair (same logic as CREATE_BOT)
      char *new_priv_b64 = NULL, *new_pub_b64 = NULL;

      // Use existing crypto function
      char *uuid_temp = NULL, *priv_temp = NULL, *pub_temp = NULL;
      if (hub_crypto_generate_bot_creds(&uuid_temp, &priv_temp, &pub_temp)) {
        // We only need the keys, not the UUID
        new_priv_b64 = priv_temp;
        new_pub_b64 = pub_temp;

        if (uuid_temp)
          free(uuid_temp);

        // Update bot's public key in storage
        time_t now = time(NULL);
        hub_storage_update_entry(state, payload, "pub", new_pub_b64, "", "",
                                 now);
        hub_config_write(state);

        // Check if bot is currently connected to THIS hub
        hub_client_t *bot_client = NULL;
        for (int i = 0; i < state->client_count; i++) {
          if (state->clients[i]->type == CLIENT_BOT &&
              strcmp(state->clients[i]->id, payload) == 0) {
            bot_client = state->clients[i];
            break;
          }
        }

        // Check if bot is connected to a REMOTE peer by checking gossip
        bool bot_on_remote_peer = false;
        int remote_peer_fd = -1;
        if (!bot_client) {
          for (int p = 0; p < state->peer_count; p++) {
            if (state->peers[p].connected &&
                strlen(state->peers[p].last_gossip) > 0) {
              // Parse gossip format: connected:total:count:uuid_list|...
              char *colon3 = strchr(state->peers[p].last_gossip, ':');
              if (colon3) {
                colon3 = strchr(colon3 + 1, ':');
                if (colon3) {
                  colon3 = strchr(colon3 + 1, ':');
                  if (colon3) {
                    // Found third colon, now extract UUID list
                    char *pipe = strchr(colon3 + 1, '|');
                    if (pipe) {
                      char uuid_list[MAX_BUFFER];
                      int list_len = pipe - (colon3 + 1);
                      if (list_len > 0 && list_len < (int)sizeof(uuid_list)) {
                        memcpy(uuid_list, colon3 + 1, list_len);
                        uuid_list[list_len] = '\0';

                        // Check if this bot's UUID is in the list
                        if (strcmp(uuid_list, "-") != 0) {
                          // Check for exact match or as part of comma-separated list
                          if (strstr(uuid_list, payload) != NULL) {
                            bot_on_remote_peer = true;
                            // Find the actual client connection for this peer
                            for (int c = 0; c < state->client_count; c++) {
                              if (state->clients[c]->type == CLIENT_HUB &&
                                  state->clients[c]->authenticated &&
                                  strcmp(state->clients[c]->ip, state->peers[p].ip) == 0) {
                                remote_peer_fd = state->clients[c]->fd;
                                break;
                              }
                            }
                            break;
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }

        char response[8192];

        if (bot_client && bot_client->authenticated) {
          // Bot is connected - send new key via secure channel
          hub_log("[ADMIN] Bot %s is connected, sending key update in real-time\n", payload);

          // Send CMD_BOT_KEY_UPDATE with new private key
          unsigned char buffer[MAX_BUFFER];
          unsigned char plain[MAX_BUFFER];
          unsigned char tag[GCM_TAG_LEN];

          plain[0] = CMD_BOT_KEY_UPDATE;
          int key_len = strlen(new_priv_b64);
          uint32_t payload_len = htonl(key_len);
          memcpy(&plain[1], &payload_len, 4);
          memcpy(&plain[5], new_priv_b64, key_len);

          int enc_len = aes_gcm_encrypt(plain, 5 + key_len, bot_client->session_key,
                                        buffer + 4, tag);
          if (enc_len > 0) {
            memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
            uint32_t net_len = htonl(enc_len + GCM_TAG_LEN);
            memcpy(buffer, &net_len, 4);

            if (write(bot_client->fd, buffer, 4 + enc_len + GCM_TAG_LEN) > 0) {
              hub_log("[ADMIN] Sent new key to bot %s, disconnecting for reconnect\n", payload);

              // Give bot a moment to process and save the new key
              struct timespec delay = {.tv_sec = 0, .tv_nsec = 100000000}; // 100ms
              nanosleep(&delay, NULL);

              // Now disconnect so bot reconnects with new key
              hub_disconnect_client(state, bot_client);

              // Build response indicating automatic update
              snprintf(response, sizeof(response),
                       "SUCCESS|%s|AUTO-UPDATED (bot was connected)", nick);
            } else {
              hub_log("[ADMIN] Failed to send key to bot %s, falling back to manual\n", payload);
              hub_disconnect_client(state, bot_client);
              snprintf(response, sizeof(response), "SUCCESS|%s|%s", nick, new_priv_b64);
            }
          } else {
            hub_log("[ADMIN] Encryption failed, falling back to manual key update\n");
            hub_disconnect_client(state, bot_client);
            snprintf(response, sizeof(response), "SUCCESS|%s|%s", nick, new_priv_b64);
          }
        } else if (bot_on_remote_peer && remote_peer_fd != -1) {
          // Bot is connected to a remote peer - forward rekey to that peer
          hub_log("[ADMIN] Bot %s is connected to remote peer, forwarding rekey\n", payload);

          // Send CMD_PEER_REKEY_BOT to the peer hub
          // Payload format: bot_uuid|new_priv_b64
          char forward_payload[MAX_BUFFER];
          int forward_len = snprintf(forward_payload, sizeof(forward_payload), "%s|%s", payload, new_priv_b64);
          if (forward_len < 0 || forward_len >= (int)sizeof(forward_payload)) {
            hub_log("[ADMIN] Rekey forward payload too large\n");
            snprintf(response, sizeof(response), "SUCCESS|%s|%s", nick, new_priv_b64);
          } else {
            unsigned char forward_buffer[MAX_BUFFER];
            unsigned char forward_plain[MAX_BUFFER];
            unsigned char forward_tag[GCM_TAG_LEN];

            forward_plain[0] = CMD_PEER_REKEY_BOT;
            uint32_t fwd_payload_len = htonl(forward_len);
            memcpy(&forward_plain[1], &fwd_payload_len, 4);
            memcpy(&forward_plain[5], forward_payload, forward_len);

            // Find the peer hub client to get its session key
            hub_client_t *peer_hub = NULL;
            for (int c = 0; c < state->client_count; c++) {
              if (state->clients[c]->fd == remote_peer_fd) {
                peer_hub = state->clients[c];
                break;
              }
            }

            if (peer_hub) {
              int fwd_enc_len = aes_gcm_encrypt(forward_plain, 5 + forward_len,
                                                peer_hub->session_key,
                                                forward_buffer + 4, forward_tag);
              if (fwd_enc_len > 0) {
                memcpy(forward_buffer + 4 + fwd_enc_len, forward_tag, GCM_TAG_LEN);
                uint32_t fwd_net_len = htonl(fwd_enc_len + GCM_TAG_LEN);
                memcpy(forward_buffer, &fwd_net_len, 4);

                if (write(remote_peer_fd, forward_buffer, 4 + fwd_enc_len + GCM_TAG_LEN) > 0) {
                  hub_log("[ADMIN] Forwarded rekey to peer hub for bot %s\n", payload);
                  snprintf(response, sizeof(response),
                           "SUCCESS|%s|AUTO-UPDATED (bot connected to peer hub)", nick);
                } else {
                  hub_log("[ADMIN] Failed to forward rekey to peer, falling back to manual\n");
                  snprintf(response, sizeof(response), "SUCCESS|%s|%s", nick, new_priv_b64);
                }
              } else {
                hub_log("[ADMIN] Failed to encrypt forward payload\n");
                snprintf(response, sizeof(response), "SUCCESS|%s|%s", nick, new_priv_b64);
              }
            } else {
              hub_log("[ADMIN] Could not find peer hub client\n");
              snprintf(response, sizeof(response), "SUCCESS|%s|%s", nick, new_priv_b64);
            }
          }
        } else {
          // Bot is not connected - return key for manual update
          hub_log("[ADMIN] Bot %s not connected, manual key update required\n", payload);
          snprintf(response, sizeof(response), "SUCCESS|%s|%s", nick, new_priv_b64);
        }

        // Broadcast sync to peers
        char sync_packet[MAX_BUFFER];
        snprintf(sync_packet, sizeof(sync_packet), "b|%s|pub|%s|%ld\n", payload,
                 new_pub_b64, (long)now);
        hub_broadcast_sync_to_peers(state, sync_packet, -1);

        // Cleanup
        if (new_pub_b64)
          free(new_pub_b64);
        bool result = send_response(state, client, response);

        // Wipe private key from memory
        if (new_priv_b64) {
          secure_wipe(new_priv_b64, strlen(new_priv_b64));
          free(new_priv_b64);
        }

        return result;
      } else {
        return send_response(state, client, "ERROR|Keypair generation failed");
      }
    }
    return send_response(state, client, "ERROR|Missing UUID");

  case CMD_ADMIN_DISCONNECT_BOT:
    if (payload && strlen(payload) > 0) {
      // Find and disconnect bot by UUID
      bool found = false;
      for (int i = 0; i < state->client_count; i++) {
        if (state->clients[i]->type == CLIENT_BOT &&
            strcmp(state->clients[i]->id, payload) == 0) {
          hub_log("[ADMIN] Disconnecting bot %s\n", payload);
          hub_disconnect_client(state, state->clients[i]);
          found = true;
          break;
        }
      }

      if (found) {
        return send_response(state, client, "SUCCESS: Bot disconnected");
      } else {
        return send_response(state, client, "ERROR: Bot not connected");
      }
    }
    return send_response(state, client, "ERROR: Missing UUID");

  // ENHANCEMENT: Update existing CMD_ADMIN_DEL to disconnect bot
  case CMD_ADMIN_DEL:
    if (payload && hub_storage_delete(state, payload)) {
      // Disconnect bot if currently connected
      for (int i = 0; i < state->client_count; i++) {
        if (state->clients[i]->type == CLIENT_BOT &&
            strcmp(state->clients[i]->id, payload) == 0) {
          hub_log("[ADMIN] Disconnecting deleted bot %s\n", payload);
          hub_disconnect_client(state, state->clients[i]);
          break;
        }
      }

      time_t now = time(NULL);
      char sync[256];
      snprintf(sync, sizeof(sync), "%s|d|1|%ld\n", payload, now);
      hub_broadcast_sync_to_peers(state, sync, -1);
      return send_response(state, client, "SUCCESS: Deleted & Synced.");
    }
    return send_response(state, client, "ERROR: Not found.");

  // ENHANCEMENT: Update CMD_ADMIN_LIST_FULL to show connection status
  case CMD_ADMIN_LIST_FULL: {
    char response[MAX_BUFFER];
    int offset = 0;
    int written;

    int active_count = 0;
    for (int i = 0; i < state->bot_count; i++) {
      if (state->bots[i].is_active)
        active_count++;
    }

    written = snprintf(response + offset, MAX_BUFFER - offset,
                       "--- Registered Bots (%d) ---\n", active_count);
    if (written >= MAX_BUFFER - offset)
      return send_response(state, client, "ERROR: Buffer overflow");
    offset += written;

    for (int i = 0; i < state->bot_count; i++) {
      bot_config_t *b = &state->bots[i];
      if (!b->is_active)
        continue;

      // Get nickname
      char nick[32] = "Unknown";
      for (int k = 0; k < b->entry_count; k++) {
        if (strcmp(b->entries[k].key, "n") == 0) {
          strncpy(nick, b->entries[k].value, sizeof(nick) - 1);
          nick[sizeof(nick) - 1] = 0;
          break;
        }
      }

      // Check if bot is currently connected
      bool is_connected = false;
      char connected_to[128] = "N/A";
      time_t last_seen = b->last_sync_time;

      for (int c = 0; c < state->client_count; c++) {
        if (state->clients[c]->type == CLIENT_BOT &&
            strcmp(state->clients[c]->id, b->uuid) == 0) {
          is_connected = true;
          snprintf(connected_to, sizeof(connected_to), "LOCAL (%s:%d)",
                   state->bind_ip, state->port);
          last_seen = state->clients[c]->last_seen;
          break;
        }
      }

      // Check if bot is connected to a remote peer by checking gossip
      if (!is_connected) {
        for (int p = 0; p < state->peer_count; p++) {
          if (state->peers[p].connected &&
              strlen(state->peers[p].last_gossip) > 0) {
            // Parse gossip format: connected:total:count:uuid_list|...
            char *colon3 = strchr(state->peers[p].last_gossip, ':');
            if (colon3) {
              colon3 = strchr(colon3 + 1, ':');
              if (colon3) {
                colon3 = strchr(colon3 + 1, ':');
                if (colon3) {
                  // Found third colon, now extract UUID list
                  char *pipe = strchr(colon3 + 1, '|');
                  if (pipe) {
                    char uuid_list[MAX_BUFFER];
                    int list_len = pipe - (colon3 + 1);
                    if (list_len > 0 && list_len < (int)sizeof(uuid_list)) {
                      memcpy(uuid_list, colon3 + 1, list_len);
                      uuid_list[list_len] = '\0';

                      // Check if this bot's UUID is in the list
                      if (strcmp(uuid_list, "-") != 0) {
                        char search_uuid[128];
                        snprintf(search_uuid, sizeof(search_uuid), "%s", b->uuid);

                        // Check for exact match or as part of comma-separated list
                        if (strstr(uuid_list, search_uuid) != NULL) {
                          is_connected = true;
                          snprintf(connected_to, sizeof(connected_to), "PEER (%s:%d)",
                                   state->peers[p].ip, state->peers[p].port);
                          break;
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }

      // Format last seen time
      char time_buf[64];
      if (last_seen == 0) {
        snprintf(time_buf, sizeof(time_buf), "Never");
      } else {
        struct tm *t = localtime(&last_seen);
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", t);
      }

      // Build output line
      written =
          snprintf(response + offset, MAX_BUFFER - offset,
                   "[%s] %-15s | Status: %-10s | Peer: %-20s | Last: %s\n",
                   b->uuid, nick, is_connected ? "CONNECTED" : "OFFLINE",
                   is_connected ? connected_to : "N/A", time_buf);

      if (written >= MAX_BUFFER - offset)
        break;
      offset += written;

      if (offset >= MAX_BUFFER - 100)
        break;
    }

    return send_response(state, client, response);
  }
  case CMD_ADMIN_APPROVE:
    if (payload && strlen(payload) > 0) {
      char target_uuid[64] = {0};

      if (strlen(payload) < 4) {
        int idx = atoi(payload);
        if (idx > 0 && idx <= state->pending_count) {
          strncpy(target_uuid, state->pending[idx - 1].uuid,
                  sizeof(target_uuid) - 1);
          target_uuid[sizeof(target_uuid) - 1] = 0;
        } else {
          return send_response(state, client, "ERROR: Invalid Index.");
        }
      } else {
        strncpy(target_uuid, payload, sizeof(target_uuid) - 1);
        target_uuid[sizeof(target_uuid) - 1] = 0;
      }

      if (target_uuid[0]) {
        time_t now = time(NULL);
        hub_storage_update_entry(state, target_uuid, "t", "", "", "", now);
        hub_config_write(state);
        remove_pending_bot(state, target_uuid);

        char sync[256];
        snprintf(sync, sizeof(sync), "%s|t||%ld\n", target_uuid, now);
        hub_broadcast_sync_to_peers(state, sync, -1);

        return send_response(state, client,
                             "SUCCESS: Bot Authorized & Synced.");
      }
    }
    return send_response(state, client, "ERROR: Missing Index or UUID.");

  case CMD_ADMIN_ADD:
    if (payload && strlen(payload) > 0) {
      time_t now = time(NULL);
      hub_storage_update_entry(state, payload, "t", "", "", "", now);
      hub_config_write(state);

      char sync[256];
      snprintf(sync, sizeof(sync), "%s|t||%ld\n", payload, now);
      hub_broadcast_sync_to_peers(state, sync, -1);

      return send_response(state, client, "SUCCESS: UUID Authorized & Synced.");
    }
    return send_response(state, client, "ERROR: Invalid UUID.");

    //    case CMD_ADMIN_DEL:
    //        if (payload && hub_storage_delete(state, payload)) {
    //            time_t now = time(NULL);
    //             char sync[256];
    //             snprintf(sync, sizeof(sync), "%s|d|1|%ld\n", payload, now);
    //              hub_broadcast_sync_to_peers(state, sync, -1);
    //              return send_response(state, client, "SUCCESS: Deleted &
    //              Synced.");
    //           }
    //           return send_response(state, client, "ERROR: Not found.");

  case CMD_ADMIN_SYNC_MESH: {
    char full_sync[MAX_BUFFER];
    hub_generate_sync_packet(state, full_sync, MAX_BUFFER - 100);
    hub_broadcast_sync_to_peers(state, full_sync, -1);
    return send_response(state, client, "SUCCESS: Full Sync broadcasted.");
  }

  case CMD_ADMIN_CREATE_BOT: {
    char nick[64];
    if (payload && strlen(payload) > 0) {
      strncpy(nick, payload, sizeof(nick) - 1);
      nick[sizeof(nick) - 1] = 0;
    } else {
      strcpy(nick, "UnnamedBot");
    }

    char *uuid = NULL, *priv_key = NULL, *pub_key = NULL;

    if (hub_crypto_generate_bot_creds(&uuid, &priv_key, &pub_key)) {
      hub_state_add_bot_memory(state, uuid, nick, pub_key);
      hub_config_write(state);

      int w =
          snprintf(response, sizeof(response), "SUCCESS|%s|%s", uuid, priv_key);

      if (w >= (int)sizeof(response)) {
        send_response(state, client, "ERROR|Key too large.");
      } else {
        send_response(state, client, response);
      }

      // ADDED: Secure cleanup
      if (priv_key) {
        secure_wipe(priv_key, strlen(priv_key));
        free(priv_key);
      }
      if (pub_key)
        free(pub_key);
      if (uuid)
        free(uuid);
    } else {
      send_response(state, client, "ERROR|Crypto generation failed.");
    }
  }
    return true;

  case CMD_ADMIN_REGEN_KEYS: {
    char *priv = NULL, *pub = NULL;
    if (hub_crypto_generate_keypair(&priv, &pub)) {
      // Send new private and public keys to all peer hubs (they share the same keys)
      broadcast_new_key(state, priv, pub);

      if (state->private_key_pem) {
        secure_wipe(state->private_key_pem, strlen(state->private_key_pem));
        free(state->private_key_pem);
      }
      if (state->public_key_pem)
        free(state->public_key_pem);
      if (state->priv_key)
        EVP_PKEY_free(state->priv_key);

      state->private_key_pem = priv;
      state->public_key_pem = pub;
      state->priv_key = load_private_key_from_memory(priv);
      hub_config_write(state);

      // Disconnect all peer hubs so they reconnect with new keys
      int disconnected = 0;
      for (int i = 0; i < state->client_count; i++) {
        if (state->clients[i]->type == CLIENT_HUB) {
          hub_log("[HUB] Disconnecting peer hub %s for rekey\n", state->clients[i]->ip);
          hub_disconnect_client(state, state->clients[i]);
          disconnected++;
          i--; // Adjust index since client_count decreased
        }
      }
      hub_log("[HUB] Disconnected %d peer hubs for rekey\n", disconnected);

      time_t now = time(NULL);
      struct tm *t = localtime(&now);
      char f[64];
      strftime(f, sizeof(f), "%Y%m%d%H%M_pub.pem", t);
      FILE *fp = fopen(f, "w");
      if (fp) {
        fputs(pub, fp);
        fclose(fp);
      }
      return send_response(state, client, pub);
    }
    return send_response(state, client, "ERROR: Key generation failed.");
  }

  case CMD_ADMIN_GET_PUBKEY: {
    char *pub = state->public_key_pem;
    if (!pub && state->priv_key) {
      BIO *bio = BIO_new(BIO_s_mem());
      if (bio && PEM_write_bio_PUBKEY(bio, state->priv_key)) {
        int len = BIO_pending(bio);
        char *pem = malloc(len + 1);
        if (pem) {
          BIO_read(bio, pem, len);
          pem[len] = 0;
          state->public_key_pem = pem;
          pub = pem;
        }
        BIO_free(bio);
      }
    }
    if (pub)
      return send_response(state, client, pub);
    return send_response(state, client, "ERROR: No Key Available.");
  }

  case CMD_ADMIN_SET_PRIVKEY:
    if (payload && strlen(payload) > 10) {
      EVP_PKEY *new_pkey = load_private_key_from_memory(payload);
      if (new_pkey) {
        if (state->private_key_pem) {
          secure_wipe(state->private_key_pem, strlen(state->private_key_pem));
          free(state->private_key_pem);
        }
        if (state->public_key_pem) {
          free(state->public_key_pem);
          state->public_key_pem = NULL;
        }
        if (state->priv_key)
          EVP_PKEY_free(state->priv_key);

        state->private_key_pem = strdup(payload);
        state->priv_key = new_pkey;
        hub_config_write(state);
        return send_response(state, client,
                             "SUCCESS: Private Key Imported & Saved.");
      }
      return send_response(state, client, "ERROR: Invalid PEM Data.");
    }
    return send_response(state, client, "ERROR: Empty Payload.");

  case CMD_ADMIN_GET_PRIVKEY:
    if (state->private_key_pem) {
      return send_response(state, client, state->private_key_pem);
    }
    return send_response(state, client, "ERROR: No Private Key in Memory.");

  case CMD_ADMIN_SET_PUBKEY:
    if (payload && strlen(payload) > 10) {
      if (state->public_key_pem)
        free(state->public_key_pem);
      state->public_key_pem = strdup(payload);
      hub_config_write(state);
      return send_response(state, client,
                           "SUCCESS: Public Key Imported & Saved.");
    }
    return send_response(state, client, "ERROR: Empty Payload.");

  case CMD_ADMIN_ADD_PEER:
    if (payload && strlen(payload) > 0) {
      char ip[256], uuid[64], name[64];
      int port;
      memset(uuid, 0, sizeof(uuid));
      memset(name, 0, sizeof(name));

      // Parse: IP:PORT:UUID:NAME (UUID and NAME optional for backward compat)
      int args = sscanf(payload, "%255[^:]:%d:%63[^:]:%63s", ip, &port, uuid, name);

      if (args >= 2) {
        if (state->peer_count < MAX_PEERS) {
          // Check for duplicate UUID
          if (uuid[0]) {
            for (int i = 0; i < state->peer_count; i++) {
              if (state->peers[i].uuid[0] &&
                  strcmp(state->peers[i].uuid, uuid) == 0) {
                return send_response(state, client,
                                   "ERROR: Peer with this UUID already exists.");
              }
            }
          }

          // Note: Friendly name is now auto-populated from gossip, so no duplicate check needed

          size_t ip_len = strlen(ip);
          size_t max_len = sizeof(state->peers[state->peer_count].ip) - 1;
          size_t copy_len = (ip_len < max_len) ? ip_len : max_len;

          memcpy(state->peers[state->peer_count].ip, ip, copy_len);
          state->peers[state->peer_count].ip[copy_len] = '\0';
          state->peers[state->peer_count].port = port;

          if (uuid[0]) {
            snprintf(state->peers[state->peer_count].uuid,
                    sizeof(state->peers[state->peer_count].uuid), "%s", uuid);
          }

          if (name[0]) {
            snprintf(state->peers[state->peer_count].friendly_name,
                    sizeof(state->peers[state->peer_count].friendly_name), "%s", name);
          }

          state->peers[state->peer_count].connected = false;
          state->peers[state->peer_count].fd = -1;
          state->peer_count++;
          hub_config_write(state);
          return send_response(state, client, "SUCCESS: Peer Added.");
        }
        return send_response(state, client, "ERROR: Max peers reached.");
      }
    }
    return send_response(state, client, "ERROR: Invalid format. Use IP:PORT:UUID:NAME");

  case CMD_ADMIN_DEL_PEER:
    if (payload && strlen(payload) > 0) {
      int idx = atoi(payload);
      if (idx == 1) {
        return send_response(state, client,
                             "ERROR: Cannot remove local hub (Index 1).");
      }
      if (idx > 1 && idx <= state->peer_count + 1) {
        int target = idx - 2;

        if (state->peers[target].fd != -1) {
          int target_fd = state->peers[target].fd;
          for (int c = 0; c < state->client_count; c++) {
            if (state->clients[c]->fd == target_fd) {
              hub_disconnect_client(state, state->clients[c]);
              break;
            }
          }
        }

        char confirm_msg[256];
        snprintf(confirm_msg, sizeof(confirm_msg),
                 "SUCCESS: Deleted Peer %s:%d.", state->peers[target].ip,
                 state->peers[target].port);

        for (int j = target; j < state->peer_count - 1; j++) {
          state->peers[j] = state->peers[j + 1];
        }
        state->peer_count--;
        hub_config_write(state);
        return send_response(state, client, confirm_msg);
      }
      return send_response(state, client, "ERROR: Invalid Index.");
    }
    {
      offset = 0;
      written = snprintf(response + offset, sizeof(response) - offset,
                         " --- Remove Local Peer ---\n");
      if (written < 0 || written >= (int)(sizeof(response) - offset)) {
        return send_response(state, client, "ERROR: Buffer overflow");
      }
      offset += written;

      for (int i = 0; i < state->peer_count; i++) {
        written = snprintf(response + offset, sizeof(response) - offset,
                           "[%d] %s:%d\n", i + 2, state->peers[i].ip,
                           state->peers[i].port);
        if (written >= (int)(sizeof(response) - offset))
          break;
        offset += written;
      }

      written = snprintf(response + offset, sizeof(response) - offset,
                         "Enter Index to Remove: ");
      if (written >= 0 && written < (int)(sizeof(response) - offset)) {
        offset += written;
      }
      return send_response(state, client, response);
    }

  case CMD_ADMIN_LIST_PEERS: {
    hub_broadcast_mesh_state(state);
    int offset = 0;
    typedef struct {
      char ip[256];
      int port;
      char uuid[64];
      char friendly_name[64];
      bool is_me;
    } matrix_peer_t;
    matrix_peer_t all_peers[64];
    int count = 0;

    // Add local hub - show friendly name instead of bind_ip
    snprintf(all_peers[count].ip, 256, "Local");
    all_peers[count].port = state->port;
    snprintf(all_peers[count].uuid, sizeof(all_peers[count].uuid), "%s", state->hub_uuid);
    snprintf(all_peers[count].friendly_name, sizeof(all_peers[count].friendly_name), "%s", state->hub_friendly_name);
    all_peers[count].is_me = true;
    count++;

    for (int i = 0; i < state->peer_count; i++) {
      // Use remote_ip (actual connection IP) if available, else configured IP
      const char *display_ip = state->peers[i].remote_ip[0] ?
                               state->peers[i].remote_ip : state->peers[i].ip;
      snprintf(all_peers[count].ip, 256, "%s", display_ip);
      all_peers[count].port = state->peers[i].port;
      snprintf(all_peers[count].uuid, sizeof(all_peers[count].uuid), "%s", state->peers[i].uuid);
      snprintf(all_peers[count].friendly_name, sizeof(all_peers[count].friendly_name), "%s", state->peers[i].friendly_name);
      all_peers[count].is_me = false;
      count++;
    }

    for (int i = 0; i < state->peer_count; i++) {
      if (state->peers[i].connected &&
          strlen(state->peers[i].last_gossip) > 0) {
        char *body = strchr(state->peers[i].last_gossip, '|');
        if (!body)
          continue;
        char work_buf[MAX_BUFFER];
        snprintf(work_buf, sizeof(work_buf), "%.*s", MAX_BUFFER - 1, body + 1);
        char *saveptr, *block = strtok_r(work_buf, ";", &saveptr);
        while (block) {
          char owner[256], owner_uuid[64], owner_name[64];
          int o_port;
          owner_uuid[0] = 0;
          owner_name[0] = 0;
          // Parse: ip:port:uuid:friendly_name|
          int fields = sscanf(block, "%255[^:]:%d:%63[^:]:%63[^|]|", owner, &o_port, owner_uuid, owner_name);
          if (fields >= 2) {
            // Replace "-" placeholders with empty strings
            if (strcmp(owner_uuid, "-") == 0) owner_uuid[0] = 0;
            if (strcmp(owner_name, "-") == 0) owner_name[0] = 0;

            // Skip 0.0.0.0 entries (bind_ip addresses)
            if (strcmp(owner, "0.0.0.0") == 0)
              goto skip_owner;

            bool exists = false;
            for (int k = 0; k < count; k++) {
              // Match by UUID if both have UUIDs (preferred)
              if (owner_uuid[0] && all_peers[k].uuid[0]) {
                if (strcmp(all_peers[k].uuid, owner_uuid) == 0) {
                  exists = true;
                  break;
                }
              }
              // Fall back to IP:port matching
              else if (all_peers[k].port == o_port &&
                       strcmp(all_peers[k].ip, owner) == 0) {
                exists = true;
                break;
              }
            }
            if (!exists && count < 64) {
              snprintf(all_peers[count].ip, 256, "%s", owner);
              all_peers[count].port = o_port;
              snprintf(all_peers[count].uuid, sizeof(all_peers[count].uuid), "%s", owner_uuid);
              snprintf(all_peers[count].friendly_name, sizeof(all_peers[count].friendly_name), "%s", owner_name);
              all_peers[count].is_me = false;
              count++;
            }
            skip_owner: ;
            char *list = strchr(block, '|');
            if (list) {
              char *t_save, *tok = strtok_r(list + 1, ",", &t_save);
              while (tok) {
                char t_ip[256], t_uuid[64], t_name[64];
                int t_port, t_up;
                t_uuid[0] = 0;
                t_name[0] = 0;
                // Parse: ip:port:is_up:uuid:friendly_name
                int t_fields = sscanf(tok, "%255[^:]:%d:%d:%63[^:]:%63s", t_ip, &t_port, &t_up, t_uuid, t_name);
                if (t_fields >= 2) {
                  // Replace "-" placeholders with empty strings
                  if (t_fields >= 4 && strcmp(t_uuid, "-") == 0) t_uuid[0] = 0;
                  if (t_fields >= 5 && strcmp(t_name, "-") == 0) t_name[0] = 0;

                  // Skip 0.0.0.0 entries (bind_ip addresses)
                  if (strcmp(t_ip, "0.0.0.0") == 0)
                    goto skip_peer;

                  bool t_exists = false;
                  for (int k = 0; k < count; k++) {
                    // Match by UUID if both have UUIDs (preferred)
                    if (t_uuid[0] && all_peers[k].uuid[0]) {
                      if (strcmp(all_peers[k].uuid, t_uuid) == 0) {
                        t_exists = true;
                        break;
                      }
                    }
                    // Fall back to IP:port matching
                    else if (all_peers[k].port == t_port &&
                             strcmp(all_peers[k].ip, t_ip) == 0) {
                      t_exists = true;
                      break;
                    }
                  }
                  if (!t_exists && count < 64) {
                    snprintf(all_peers[count].ip, 256, "%s", t_ip);
                    all_peers[count].port = t_port;
                    snprintf(all_peers[count].uuid, sizeof(all_peers[count].uuid), "%s", t_uuid);
                    snprintf(all_peers[count].friendly_name, sizeof(all_peers[count].friendly_name), "%s", t_name);
                    all_peers[count].is_me = false;
                    count++;
                  }
                  skip_peer: ;
                }
                tok = strtok_r(NULL, ",", &t_save);
              }
            }
          }
          block = strtok_r(NULL, ";", &saveptr);
        }
      }
    }

    int peer_col_width = 25;
    for (int i = 0; i < count; i++) {
      char tmp[512];
      // Calculate width based on actual display format (friendly name + full UUID)
      if (all_peers[i].friendly_name[0]) {
        if (all_peers[i].uuid[0]) {
          snprintf(tmp, 512, "%s (%s)", all_peers[i].friendly_name, all_peers[i].uuid);
        } else {
          snprintf(tmp, 512, "%s (no-uuid)", all_peers[i].friendly_name);
        }
      } else {
        snprintf(tmp, 512, "%.255s:%d", all_peers[i].ip, all_peers[i].port);
      }
      int len = strlen(tmp);
      if (len > peer_col_width)
        peer_col_width = len;
    }
    peer_col_width += 3;

    // CRITICAL FIX: Add overflow check before write
    written = snprintf(
        response + offset, sizeof(response) - offset,
        "\n [M] MESH CONNECTION MATRIX        You are connected to peer 1\n");
    if (written < 0 || written >= (int)(sizeof(response) - offset)) {
      return send_response(state, client, "ERROR: Response buffer overflow");
    }
    offset += written;

    // Add 25 for the IP:Port column (21 chars + " | " = 24)
    int line_len = peer_col_width + 3 + 24 + (count * 5) + 15 + 10;

    // CRITICAL FIX: Bounds check for line drawing
    for (int k = 0; k < line_len && offset < (int)sizeof(response) - 1; k++) {
      response[offset++] = '-';
    }
    if (offset >= (int)sizeof(response) - 1) {
      return send_response(state, client, "ERROR: Response buffer overflow");
    }
    response[offset++] = '\n';
    response[offset] = '\0';

    // CRITICAL FIX: Add overflow check
    written = snprintf(response + offset, sizeof(response) - offset, " %-*s | %-21s |",
                       peer_col_width, "Peer", "IP:Port");
    if (written < 0 || written >= (int)(sizeof(response) - offset)) {
      return send_response(state, client, "ERROR: Response buffer overflow");
    }
    offset += written;

    for (int i = 0; i < count; i++) {
      // CRITICAL FIX: Add overflow check in loop
      written = snprintf(response + offset, sizeof(response) - offset,
                         " %-2d |", i + 1);
      if (written < 0 || written >= (int)(sizeof(response) - offset))
        break;
      offset += written;
    }

    // CRITICAL FIX: Add overflow check
    written = snprintf(response + offset, sizeof(response) - offset,
                       " Mesh State    | Bots |\n");
    if (written < 0 || written >= (int)(sizeof(response) - offset)) {
      return send_response(state, client, "ERROR: Response buffer overflow");
    }
    offset += written;

    // CRITICAL FIX: Bounds check for line drawing
    for (int k = 0; k < line_len && offset < (int)sizeof(response) - 1; k++) {
      response[offset++] = '-';
    }
    if (offset >= (int)sizeof(response) - 1) {
      return send_response(state, client, "ERROR: Response buffer overflow");
    }
    response[offset++] = '\n';
    response[offset] = '\0';

    int issues = 0;
    char issue_log[MAX_BUFFER];
    memset(issue_log, 0, sizeof(issue_log));
    int issue_off = 0;
    char reported_mismatches[64][MAX_BUFFER];
    int rm_count = 0;

    for (int row = 0; row < count; row++) {
      char peer_str[512];
      char ip_port_str[64];

      // Show friendly name and full UUID, or IP:port if no name
      if (all_peers[row].friendly_name[0]) {
        if (all_peers[row].uuid[0]) {
          snprintf(peer_str, 512, "%s (%s)", all_peers[row].friendly_name, all_peers[row].uuid);
        } else {
          snprintf(peer_str, 512, "%s (no-uuid)", all_peers[row].friendly_name);
        }
      } else {
        snprintf(peer_str, 512, "%.255s:%d", all_peers[row].ip, all_peers[row].port);
      }

      // For IP:Port column - show actual connection info
      if (all_peers[row].is_me) {
        // For local hub (peer 1), show the IP:port that hub_admin used to connect
        // Use the stored connection info from the admin client if available
        if (client->admin_connect_ip[0] && client->admin_connect_port > 0) {
          snprintf(ip_port_str, sizeof(ip_port_str), "%.45s:%d",
                   client->admin_connect_ip, client->admin_connect_port);
        } else {
          // Fallback to bind_ip:port if connection info not available
          snprintf(ip_port_str, sizeof(ip_port_str), "%.45s:%d",
                   state->bind_ip[0] ? state->bind_ip : "0.0.0.0",
                   state->port);
        }
      } else {
        // For remote peers, show their IP:port
        snprintf(ip_port_str, sizeof(ip_port_str), "%.45s:%d",
                 all_peers[row].ip, all_peers[row].port);
      }

      // CRITICAL FIX: Add overflow check
      written = snprintf(response + offset, sizeof(response) - offset,
                         " %d. %-*s | %-21s |", row + 1, peer_col_width - 3, peer_str, ip_port_str);
      if (written < 0 || written >= (int)(sizeof(response) - offset)) {
        return send_response(state, client,
                             "ERROR: Matrix too large for buffer");
      }
      offset += written;

      int row_connected = 0, row_total = 0;
      for (int col = 0; col < count; col++) {
        char cell[32] = "??";
        if (row == col)
          strcpy(cell, "--");
        else {
          bool found_block = false, found_link = false, link_up = false;
          if (all_peers[row].is_me) {
            found_block = true;
            for (int p = 0; p < state->peer_count; p++) {
              // Match by UUID if both have UUIDs, otherwise fall back to IP:port
              bool peer_matches = false;
              if (all_peers[col].uuid[0] && state->peers[p].uuid[0]) {
                peer_matches = (strcmp(state->peers[p].uuid, all_peers[col].uuid) == 0);
              } else {
                peer_matches = (state->peers[p].port == all_peers[col].port &&
                                strcmp(state->peers[p].ip, all_peers[col].ip) == 0);
              }

              if (peer_matches) {
                found_link = true;
                for (int c = 0; c < state->client_count; c++) {
                  if (state->clients[c]->type == CLIENT_HUB &&
                      state->clients[c]->authenticated &&
                      state->clients[c]->fd == state->peers[p].fd)
                    link_up = true;
                }
              }
            }
          } else {
            for (int p = 0; p < state->peer_count; p++) {
              if (state->peers[p].connected &&
                  strlen(state->peers[p].last_gossip) > 0) {
                char *body = strchr(state->peers[p].last_gossip, '|');
                if (!body)
                  continue;
                char work_buf[MAX_BUFFER];
                snprintf(work_buf, sizeof(work_buf), "%.*s", MAX_BUFFER - 1,
                         body + 1);
                char *bsave, *block = strtok_r(work_buf, ";", &bsave);
                while (block) {
                  char owner[256], owner_uuid[64], owner_name[64];
                  int o_port;
                  owner_uuid[0] = 0;
                  owner_name[0] = 0;
                  // Parse: ip:port:uuid:friendly_name|
                  int fields = sscanf(block, "%255[^:]:%d:%63[^:]:%63[^|]|", owner, &o_port, owner_uuid, owner_name);
                  if (fields >= 2) {
                    // Replace "-" placeholders with empty strings
                    if (strcmp(owner_uuid, "-") == 0) owner_uuid[0] = 0;
                    if (strcmp(owner_name, "-") == 0) owner_name[0] = 0;

                    // Match by UUID if both have UUIDs, otherwise fall back to IP:port
                    bool owner_matches = false;
                    if (owner_uuid[0] && all_peers[row].uuid[0]) {
                      owner_matches = (strcmp(owner_uuid, all_peers[row].uuid) == 0);
                    } else {
                      owner_matches = (o_port == all_peers[row].port &&
                                       strcmp(owner, all_peers[row].ip) == 0);
                    }

                    if (owner_matches) {
                      found_block = true;
                      char *list = strchr(block, '|');
                      if (list) {
                        char *lsave, *tok = strtok_r(list + 1, ",", &lsave);
                        while (tok) {
                          char t_ip[256], t_uuid[64], t_name[64];
                          int t_port, stat;
                          t_uuid[0] = 0;
                          t_name[0] = 0;
                          // Parse: ip:port:is_up:uuid:friendly_name
                          int t_fields = sscanf(tok, "%255[^:]:%d:%d:%63[^:]:%63s", t_ip, &t_port,
                                                &stat, t_uuid, t_name);
                          if (t_fields >= 3) {
                            // Replace "-" placeholders with empty strings
                            if (t_fields >= 4 && strcmp(t_uuid, "-") == 0) t_uuid[0] = 0;
                            if (t_fields >= 5 && strcmp(t_name, "-") == 0) t_name[0] = 0;

                            // Match by UUID if both have UUIDs, otherwise fall back to IP:port
                            bool target_matches = false;
                            if (t_uuid[0] && all_peers[col].uuid[0]) {
                              target_matches = (strcmp(t_uuid, all_peers[col].uuid) == 0);
                            } else {
                              target_matches = (t_port == all_peers[col].port &&
                                                strcmp(t_ip, all_peers[col].ip) == 0);
                            }

                            if (target_matches) {
                              found_link = true;
                              if (stat)
                                link_up = true;
                            }
                          }
                          tok = strtok_r(NULL, ",", &lsave);
                        }
                      }
                    }
                  }
                  block = strtok_r(NULL, ";", &bsave);
                }
              }
            }
          }
          if (all_peers[col].is_me) {
            if (found_link && link_up) {
              bool actually_connected = false;
              for (int p = 0; p < state->peer_count; p++) {
                // Match by UUID if both have UUIDs, otherwise fall back to IP:port
                bool peer_matches = false;
                if (all_peers[row].uuid[0] && state->peers[p].uuid[0]) {
                  peer_matches = (strcmp(state->peers[p].uuid, all_peers[row].uuid) == 0);
                } else {
                  peer_matches = (state->peers[p].port == all_peers[row].port &&
                                  strcmp(state->peers[p].ip, all_peers[row].ip) == 0);
                }

                if (peer_matches) {
                  for (int c = 0; c < state->client_count; c++) {
                    if (state->clients[c]->type == CLIENT_HUB &&
                        state->clients[c]->authenticated &&
                        state->clients[c]->fd == state->peers[p].fd)
                      actually_connected = true;
                  }
                }
              }
              if (!actually_connected)
                link_up = false;
            }
          }
          if (found_block) {
            if (found_link) {
              strcpy(cell, link_up ? "\033[32mUP\033[0m" : "\033[31mDN\033[0m");
              row_total++;
              if (link_up)
                row_connected++;
            } else
              strcpy(cell, "??");
          } else
            strcpy(cell, "??");
        }

        // CRITICAL FIX: Add overflow check
        written = snprintf(response + offset, sizeof(response) - offset,
                           " %s |", cell);
        if (written < 0 || written >= (int)(sizeof(response) - offset)) {
          return send_response(state, client,
                               "ERROR: Matrix too large for buffer");
        }
        offset += written;
      }

      bool is_offline = false;

      // Check if we're directly connected to this peer
      bool directly_connected = false;
      if (all_peers[row].is_me) {
        directly_connected = true;
      } else {
        for (int p = 0; p < state->peer_count; p++) {
          // Match by UUID if both have UUIDs, otherwise fall back to IP:port
          bool peer_matches = false;
          if (all_peers[row].uuid[0] && state->peers[p].uuid[0]) {
            peer_matches = (strcmp(state->peers[p].uuid, all_peers[row].uuid) == 0);
          } else {
            peer_matches = (state->peers[p].port == all_peers[row].port &&
                            strcmp(state->peers[p].ip, all_peers[row].ip) == 0);
          }

          if (peer_matches) {
            // Check if there's an active connection
            for (int c = 0; c < state->client_count; c++) {
              if (state->clients[c]->type == CLIENT_HUB &&
                  state->clients[c]->authenticated &&
                  state->clients[c]->fd == state->peers[p].fd) {
                directly_connected = true;
                break;
              }
            }
            break;
          }
        }
      }

      if (row_total > 0) {
        if (row_connected > 0) {
          // CRITICAL FIX: Add overflow check
          written = snprintf(response + offset, sizeof(response) - offset,
                             " %d/%d Connected |", row_connected, row_total);
        } else {
          // Show as "Offline" only if not directly connected
          if (directly_connected) {
            // CRITICAL FIX: Add overflow check
            written = snprintf(response + offset, sizeof(response) - offset,
                               " 0/%d Partial   |", row_total);
          } else {
            // CRITICAL FIX: Add overflow check
            written = snprintf(response + offset, sizeof(response) - offset,
                               " \033[31mOffline\033[0m       |");
            is_offline = true;
            issues++;
          }
        }
      } else {
        if (all_peers[row].is_me) {
          // CRITICAL FIX: Add overflow check
          written = snprintf(response + offset, sizeof(response) - offset,
                             " ---          |");
        } else if (directly_connected) {
          // Directly connected but no peer mesh info yet
          // CRITICAL FIX: Add overflow check
          written = snprintf(response + offset, sizeof(response) - offset,
                             " Connected     |");
        } else {
          // CRITICAL FIX: Add overflow check
          written = snprintf(response + offset, sizeof(response) - offset,
                             " \033[31mOffline\033[0m       |");
          is_offline = true;
          issues++;
        }
      }

      // CRITICAL FIX: Check the write result
      if (written < 0 || written >= (int)(sizeof(response) - offset)) {
        return send_response(state, client,
                             "ERROR: Matrix too large for buffer");
      }
      offset += written;

      if (is_offline) {
        // CRITICAL FIX: Add overflow check
        written =
            snprintf(response + offset, sizeof(response) - offset, " ??   |\n");
      } else {
        int bot_cnt = 0;
        if (all_peers[row].is_me) {
          for (int k = 0; k < state->client_count; k++) {
            if (state->clients[k]->type == CLIENT_BOT &&
                state->clients[k]->authenticated)
              bot_cnt++;
          }
        } else {
          for (int p = 0; p < state->peer_count; p++) {
            if (state->peers[p].connected &&
                state->peers[p].port == all_peers[row].port &&
                strcmp(state->peers[p].ip, all_peers[row].ip) == 0) {
              int rc, rt, rb;
              if (sscanf(state->peers[p].last_gossip, "%d:%d:%d|", &rc, &rt,
                         &rb) == 3) {
                bot_cnt = rb;
              }
              break;
            }
          }
        }
        // CRITICAL FIX: Add overflow check
        written = snprintf(response + offset, sizeof(response) - offset,
                           " %-4d |\n", bot_cnt);
      }

      // CRITICAL FIX: Check the write result
      if (written < 0 || written >= (int)(sizeof(response) - offset)) {
        return send_response(state, client,
                             "ERROR: Matrix too large for buffer");
      }
      offset += written;

      if (all_peers[row].is_me) {
        for (int p = 0; p < state->peer_count; p++) {
          bool active = false;
          for (int c = 0; c < state->client_count; c++) {
            if (state->clients[c]->type == CLIENT_HUB &&
                state->clients[c]->authenticated &&
                state->clients[c]->fd == state->peers[p].fd)
              active = true;
          }
          if (!active) {
            issues++;
            // CRITICAL FIX: Add overflow check for issue_log
            int w =
                snprintf(issue_log + issue_off, sizeof(issue_log) - issue_off,
                         " [!] Peer %s:%d is DOWN.\n", state->peers[p].ip,
                         state->peers[p].port);
            if (w > 0 && w < (int)(sizeof(issue_log) - issue_off)) {
              issue_off += w;
            }
          }
        }
      }
    }

    for (int i = 0; i < count; i++) {
      if (!all_peers[i].is_me) {
        bool in_config = false;
        for (int p = 0; p < state->peer_count; p++)
          if (state->peers[p].port == all_peers[i].port &&
              strcmp(state->peers[p].ip, all_peers[i].ip) == 0)
            in_config = true;
        if (!in_config) {
          for (int p = 0; p < state->peer_count; p++) {
            if (state->peers[p].connected &&
                strlen(state->peers[p].last_gossip) > 0) {
              char *body = strchr(state->peers[p].last_gossip, '|');
              if (!body)
                continue;
              char work_buf[MAX_BUFFER];
              snprintf(work_buf, sizeof(work_buf), "%.*s", MAX_BUFFER - 1,
                       body + 1);
              char *bsave, *block = strtok_r(work_buf, ";", &bsave);
              while (block) {
                char owner[256];
                int o_port;
                sscanf(block, "%255[^:]:%d|", owner, &o_port);
                bool owner_is_known = false;
                for (int z = 0; z < state->peer_count; z++)
                  if (state->peers[z].port == o_port &&
                      strcmp(state->peers[z].ip, owner) == 0)
                    owner_is_known = true;
                if (owner_is_known) {
                  if (strstr(block, all_peers[i].ip)) {
                    char check_sig[MAX_BUFFER];
                    snprintf(check_sig, sizeof(check_sig),
                             "%.255s:%d->%.255s:%d", owner, o_port,
                             all_peers[i].ip, all_peers[i].port);
                    bool already_rept = false;
                    for (int k = 0; k < rm_count; k++)
                      if (strcmp(reported_mismatches[k], check_sig) == 0)
                        already_rept = true;
                    if (!already_rept && rm_count < 64) {
                      snprintf(reported_mismatches[rm_count++], MAX_BUFFER,
                               "%.1023s", check_sig);
                      issues++;
                      // CRITICAL FIX: Add overflow check
                      int w = snprintf(
                          issue_log + issue_off, sizeof(issue_log) - issue_off,
                          " [!] Config Mismatch: Peer %.255s:%d knows "
                          "%.255s:%d, but we don't.\n",
                          owner, o_port, all_peers[i].ip, all_peers[i].port);
                      if (w > 0 && w < (int)(sizeof(issue_log) - issue_off)) {
                        issue_off += w;
                      }
                    }
                  }
                }
                block = strtok_r(NULL, ";", &bsave);
              }
            }
          }
        }
      }
    }

    // CRITICAL FIX: Bounds check for line drawing
    for (int k = 0; k < line_len && offset < (int)sizeof(response) - 1; k++) {
      response[offset++] = '-';
    }
    if (offset >= (int)sizeof(response) - 1) {
      return send_response(state, client, "ERROR: Response buffer overflow");
    }
    response[offset++] = '\n';
    response[offset] = '\0';

    char status_str[128];
    if (issues == 0) {
      // Show HEALTHY if no issues, regardless of peer count
      snprintf(status_str, 64, "\033[32mHEALTHY\033[0m");
    } else {
      snprintf(status_str, 64, "\033[33mDEGRADED (%d ISSUES)\033[0m", issues);
    }

    // CRITICAL FIX: Add overflow check
    written = snprintf(response + offset, sizeof(response) - offset,
                       " [i] MESH STATUS: %s\n [Legend: -- = Self, UP = "
                       "Connected, DN = Down, ?? = Unknown/Not Configured]\n",
                       status_str);
    if (written < 0 || written >= (int)(sizeof(response) - offset)) {
      return send_response(state, client, "ERROR: Response buffer overflow");
    }
    offset += written;

    if (issues > 0) {
      // CRITICAL FIX: Add overflow check
      written = snprintf(response + offset, sizeof(response) - offset,
                         " --- Mesh Diagnostics ---\n%s", issue_log);
      if (written < 0 || written >= (int)(sizeof(response) - offset)) {
        return send_response(state, client, "ERROR: Response buffer overflow");
      }
      offset += written;
    }

    return send_response(state, client, response);
  }

  case CMD_ADMIN_LIST_CHANNELS: {
    offset = 0;
    written = snprintf(response, sizeof(response), "--- Global Channels ---\n");
    if (written >= (int)sizeof(response))
      return send_response(state, client, "ERROR: Buffer overflow");
    offset += written;

    written = snprintf(response + offset, sizeof(response) - offset,
                       "%-30s %-20s\n", "Channel", "Key");
    if (written >= (int)(sizeof(response) - offset))
      return send_response(state, client, "ERROR: Buffer overflow");
    offset += written;

    written = snprintf(response + offset, sizeof(response) - offset,
                       "%-30s %-20s\n", "-------", "---");
    if (written >= (int)(sizeof(response) - offset))
      return send_response(state, client, "ERROR: Buffer overflow");
    offset += written;

    int chan_count = 0;
    for (int i = 0; i < state->global_entry_count; i++) {
      if (strcmp(state->global_entries[i].key, "c") == 0) {
        char chan_name[128] = "", chan_key[64] = "", op[16] = "";
        // Parse: channel|key|op or channel||op (empty key)
        int parsed = sscanf(state->global_entries[i].value, "%127[^|]|%63[^|]|%15s",
                           chan_name, chan_key, op);
        if (parsed < 2) {
          // Try empty key format: channel||op
          parsed = sscanf(state->global_entries[i].value, "%127[^|]||%15s",
                         chan_name, op);
          chan_key[0] = '\0';
        }
        // Skip deleted channels
        if (strcmp(op, "del") == 0)
          continue;

        if (parsed >= 2 || (parsed == 1 && chan_name[0])) {
          chan_count++;
          written = snprintf(response + offset, sizeof(response) - offset,
                             "%-30s %-20s\n", chan_name,
                             strlen(chan_key) > 0 ? chan_key : "");
          if (written >= (int)(sizeof(response) - offset))
            break;
          offset += written;
        }
      }
    }
    if (chan_count == 0) {
      written = snprintf(response + offset, sizeof(response) - offset,
                         "  (No channels configured)\n");
      offset += written;
    }
    return send_response(state, client, response);
  }

  case CMD_ADMIN_ADD_CHANNEL: {
    if (payload && strlen(payload) > 0) {
      char chan[128], key[64];
      key[0] = '\0';
      if (sscanf(payload, "%127[^|]|%63s", chan, key) >= 1) {
        time_t now = time(NULL);
        hub_storage_update_global_entry(state, "c", chan, key, "add", now);
        hub_config_write(state);

        char sync_msg[256];
        if (strlen(key) > 0) {
          snprintf(sync_msg, sizeof(sync_msg), "c|%s|%s|add|%ld\n", chan, key,
                   (long)now);
        } else {
          snprintf(sync_msg, sizeof(sync_msg), "c|%s||add|%ld\n", chan,
                   (long)now);
        }
        hub_broadcast_config_to_bots(state, sync_msg);
        hub_broadcast_sync_to_peers(state, sync_msg, -1);
        return send_response(state, client, "SUCCESS: Channel added and synced.");
      }
    }
    return send_response(state, client, "ERROR: Invalid payload.");
  }

  case CMD_ADMIN_DEL_CHANNEL: {
    if (payload && strlen(payload) > 0) {
      time_t now = time(NULL);
      hub_storage_update_global_entry(state, "c", payload, "", "del", now);
      hub_config_write(state);

      char sync_msg[256];
      snprintf(sync_msg, sizeof(sync_msg), "c|%s||del|%ld\n", payload,
               (long)now);
      hub_broadcast_config_to_bots(state, sync_msg);
      hub_broadcast_sync_to_peers(state, sync_msg, -1);
      return send_response(state, client,
                           "SUCCESS: Channel removed and synced.");
    }
    return send_response(state, client, "ERROR: Missing channel name.");
  }

  case CMD_ADMIN_LIST_MASKS: {
    offset = 0;
    written = snprintf(response, sizeof(response), "--- Admin Masks ---\n");
    if (written >= (int)sizeof(response))
      return send_response(state, client, "ERROR: Buffer overflow");
    offset += written;

    written = snprintf(response + offset, sizeof(response) - offset,
                       "%-50s\n", "Mask");
    if (written >= (int)(sizeof(response) - offset))
      return send_response(state, client, "ERROR: Buffer overflow");
    offset += written;

    written = snprintf(response + offset, sizeof(response) - offset,
                       "%-50s\n", "----");
    if (written >= (int)(sizeof(response) - offset))
      return send_response(state, client, "ERROR: Buffer overflow");
    offset += written;

    int mask_count = 0;
    for (int i = 0; i < state->global_entry_count; i++) {
      if (strcmp(state->global_entries[i].key, "m") == 0) {
        char mask[256], op[16];
        if (sscanf(state->global_entries[i].value, "%255[^|]|%15s", mask, op) ==
            2) {
          // Skip deleted masks
          if (strcmp(op, "del") == 0)
            continue;

          mask_count++;
          written = snprintf(response + offset, sizeof(response) - offset,
                             "%-50s\n", mask);
          if (written >= (int)(sizeof(response) - offset))
            break;
          offset += written;
        }
      }
    }
    if (mask_count == 0) {
      written = snprintf(response + offset, sizeof(response) - offset,
                         "  (No admin masks configured)\n");
      offset += written;
    }
    return send_response(state, client, response);
  }

  case CMD_ADMIN_ADD_MASK: {
    if (payload && strlen(payload) > 0) {
      time_t now = time(NULL);
      hub_storage_update_global_entry(state, "m", payload, "", "add", now);
      hub_config_write(state);

      char sync_msg[256];
      snprintf(sync_msg, sizeof(sync_msg), "m|%s|add|%ld\n", payload,
               (long)now);
      hub_broadcast_config_to_bots(state, sync_msg);
      hub_broadcast_sync_to_peers(state, sync_msg, -1);
      return send_response(state, client, "SUCCESS: Admin mask added and synced.");
    }
    return send_response(state, client, "ERROR: Missing mask.");
  }

  case CMD_ADMIN_DEL_MASK: {
    if (payload && strlen(payload) > 0) {
      time_t now = time(NULL);
      hub_storage_update_global_entry(state, "m", payload, "", "del", now);
      hub_config_write(state);

      char sync_msg[256];
      snprintf(sync_msg, sizeof(sync_msg), "m|%s|del|%ld\n", payload,
               (long)now);
      hub_broadcast_config_to_bots(state, sync_msg);
      hub_broadcast_sync_to_peers(state, sync_msg, -1);
      return send_response(state, client,
                           "SUCCESS: Admin mask removed and synced.");
    }
    return send_response(state, client, "ERROR: Missing mask.");
  }

  case CMD_ADMIN_LIST_OPERS: {
    offset = 0;
    written = snprintf(response, sizeof(response), "--- Oper Masks ---\n");
    if (written >= (int)sizeof(response))
      return send_response(state, client, "ERROR: Buffer overflow");
    offset += written;

    written = snprintf(response + offset, sizeof(response) - offset,
                       "%-40s %-20s\n", "Mask", "Password");
    if (written >= (int)(sizeof(response) - offset))
      return send_response(state, client, "ERROR: Buffer overflow");
    offset += written;

    written = snprintf(response + offset, sizeof(response) - offset,
                       "%-40s %-20s\n", "----", "--------");
    if (written >= (int)(sizeof(response) - offset))
      return send_response(state, client, "ERROR: Buffer overflow");
    offset += written;

    int oper_count = 0;
    for (int i = 0; i < state->global_entry_count; i++) {
      if (strcmp(state->global_entries[i].key, "o") == 0) {
        char mask[256], pass[128], op[16];
        if (sscanf(state->global_entries[i].value, "%255[^|]|%127[^|]|%15s",
                   mask, pass, op) == 3) {
          // Skip deleted opers
          if (strcmp(op, "del") == 0)
            continue;

          oper_count++;
          written = snprintf(response + offset, sizeof(response) - offset,
                             "%-40s %-20s\n", mask, pass);
          if (written >= (int)(sizeof(response) - offset))
            break;
          offset += written;
        }
      }
    }
    if (oper_count == 0) {
      written = snprintf(response + offset, sizeof(response) - offset,
                         "  (No oper masks configured)\n");
      offset += written;
    }
    return send_response(state, client, response);
  }

  case CMD_ADMIN_ADD_OPER: {
    if (payload && strlen(payload) > 0) {
      char mask[256], pass[128];
      if (sscanf(payload, "%255[^|]|%127s", mask, pass) == 2) {
        time_t now = time(NULL);
        hub_storage_update_global_entry(state, "o", mask, pass, "add", now);
        hub_config_write(state);

        char sync_msg[512];
        snprintf(sync_msg, sizeof(sync_msg), "o|%s|%s|add|%ld\n", mask, pass,
                 (long)now);
        hub_broadcast_config_to_bots(state, sync_msg);
        hub_broadcast_sync_to_peers(state, sync_msg, -1);
        return send_response(state, client, "SUCCESS: Oper mask added and synced.");
      }
    }
    return send_response(state, client, "ERROR: Invalid payload (need mask|password).");
  }

  case CMD_ADMIN_DEL_OPER: {
    if (payload && strlen(payload) > 0) {
      time_t now = time(NULL);
      hub_storage_update_global_entry(state, "o", payload, "", "del", now);
      hub_config_write(state);

      char sync_msg[256];
      snprintf(sync_msg, sizeof(sync_msg), "o|%s||del|%ld\n", payload,
               (long)now);
      hub_broadcast_config_to_bots(state, sync_msg);
      hub_broadcast_sync_to_peers(state, sync_msg, -1);
      return send_response(state, client, "SUCCESS: Oper mask removed and synced.");
    }
    return send_response(state, client, "ERROR: Missing mask.");
  }

  case CMD_ADMIN_SET_ADMIN_PASS: {
    if (payload && strlen(payload) > 0) {
      time_t now = time(NULL);
      hub_storage_update_global_entry(state, "a", payload, "", "", now);
      hub_config_write(state);

      char sync_msg[256];
      snprintf(sync_msg, sizeof(sync_msg), "a|%s|%ld\n", payload, (long)now);
      hub_broadcast_config_to_bots(state, sync_msg);
      hub_broadcast_sync_to_peers(state, sync_msg, -1);
      return send_response(state, client,
                           "SUCCESS: Admin password updated and synced.");
    }
    return send_response(state, client, "ERROR: Missing password.");
  }

  case CMD_ADMIN_SET_BOT_PASS: {
    if (payload && strlen(payload) > 0) {
      time_t now = time(NULL);
      hub_storage_update_global_entry(state, "p", payload, "", "", now);
      hub_config_write(state);

      char sync_msg[256];
      snprintf(sync_msg, sizeof(sync_msg), "p|%s|%ld\n", payload, (long)now);
      hub_broadcast_config_to_bots(state, sync_msg);
      // Also broadcast to peer hubs for mesh sync
      hub_broadcast_sync_to_peers(state, sync_msg, -1);
      return send_response(state, client,
                           "SUCCESS: Bot password updated and synced.");
    }
    return send_response(state, client, "ERROR: Missing password.");
  }

  case CMD_ADMIN_OP_USER: {
    if (payload && strlen(payload) > 0) {
      char nick[64], channel[64];
      if (sscanf(payload, "%63[^|]|%63s", nick, channel) == 2) {
        // Generate unique request ID
        char request_id[64];
        generate_request_id(request_id, sizeof(request_id));

        // Try to find a bot in the channel locally
        int sent_count = 0;
        for (int i = 0; i < state->client_count; i++) {
          if (state->clients[i]->type == CLIENT_BOT &&
              state->clients[i]->authenticated) {
            // Send op grant request to all connected bots
            // They'll ignore it if they're not in the channel
            char op_payload[256];
            snprintf(op_payload, sizeof(op_payload), "%s|%s", nick, channel);

            unsigned char plain[MAX_BUFFER];
            plain[0] = CMD_OP_GRANT;
            uint32_t pay_len = strlen(op_payload);
            uint32_t net_len = htonl(pay_len);
            memcpy(&plain[1], &net_len, 4);
            memcpy(&plain[5], op_payload, pay_len);

            unsigned char enc[MAX_BUFFER], tag[GCM_TAG_LEN];
            int enc_len = aes_gcm_encrypt(
                plain, 5 + pay_len, state->clients[i]->session_key, enc + 4, tag);

            if (enc_len > 0) {
              memcpy(enc + 4 + enc_len, tag, GCM_TAG_LEN);
              net_len = htonl(enc_len + GCM_TAG_LEN);
              memcpy(enc, &net_len, 4);

              if (send(state->clients[i]->fd, enc, 4 + enc_len + GCM_TAG_LEN, 0) > 0) {
                sent_count++;
              }
            }
          }
        }

        // Also forward to peer hubs to reach bots connected to them
        // Encode nick:channel for admin requests
        char admin_payload[256];
        snprintf(admin_payload, sizeof(admin_payload), "%s:%s", nick, channel);
        forward_op_request_to_peers(state, request_id, "ADMIN", "ANY", admin_payload, -1);

        if (sent_count > 0) {
          snprintf(response, sizeof(response),
                   "SUCCESS: Op request sent to %d local bot(s) and forwarded to peer hubs",
                   sent_count);
        } else {
          snprintf(response, sizeof(response),
                   "SUCCESS: Op request forwarded to peer hubs (no local bots connected)");
        }
        return send_response(state, client, response);
      }
    }
    return send_response(state, client, "ERROR: Invalid payload (need nick|channel).");
  }

  case CMD_ADMIN_PURGE_TOMBSTONES: {
    // Parse payload: "immediate" or number of days (default 30)
    bool immediate = false;
    if (payload && strlen(payload) > 0 && strcmp(payload, "immediate") == 0) {
      immediate = true;
    }

    // Execute purge using extracted function
    // Use smaller buffer for log to ensure response won't overflow
    char purge_log[MAX_BUFFER / 2];
    int purged_count = hub_execute_purge(state, payload, immediate,
                                          purge_log, sizeof(purge_log));

    // Send response
    if (purged_count > 0) {
      snprintf(response, sizeof(response),
               "SUCCESS: Purged %d tombstoned entries (%s)\n%.*s",
               purged_count, immediate ? "immediate" :
               (payload && strlen(payload) > 0 ? payload : "30 days"),
               (int)(sizeof(response) - 100), purge_log);
    } else {
      snprintf(response, sizeof(response),
               "No tombstoned entries found to purge (%s)",
               immediate ? "immediate" :
               (payload && strlen(payload) > 0 ? payload : "30 days"));
    }

    return send_response(state, client, response);
  }

  case CMD_ADMIN_SET_PURGE_DAYS: {
    if (payload && strlen(payload) > 0) {
      int days = atoi(payload);
      if (days < 0) days = 0;  // 0 = disabled

      state->purge_days_setting = days;
      hub_config_write(state);

      if (days > 0) {
        snprintf(response, sizeof(response),
                 "SUCCESS: Automatic purge enabled (purge tombstones older than %d days, runs daily)",
                 days);
      } else {
        snprintf(response, sizeof(response),
                 "SUCCESS: Automatic purge disabled");
      }
      return send_response(state, client, response);
    }
    return send_response(state, client, "ERROR: Missing days parameter (use 0 to disable)");
  }

  case CMD_ADMIN_SET_BIND_IP: {
    if (payload && strlen(payload) > 0) {
      // Validate IP format
      struct in_addr test_addr;
      if (inet_pton(AF_INET, payload, &test_addr) != 1) {
        return send_response(state, client, "ERROR: Invalid IP address format.");
      }

      // Update bind_ip in memory
      strncpy(state->bind_ip, payload, sizeof(state->bind_ip) - 1);
      state->bind_ip[sizeof(state->bind_ip) - 1] = '\0';

      // Save to config
      hub_config_write(state);

      // Sync to peers
      time_t now = time(NULL);
      char sync_msg[256];
      snprintf(sync_msg, sizeof(sync_msg), "bind_ip|%s|%ld\n", payload, (long)now);
      hub_broadcast_sync_to_peers(state, sync_msg, -1);

      return send_response(state, client,
                         "SUCCESS: Bind IP updated. Restart hub for changes to take effect.");
    }
    return send_response(state, client, "ERROR: Missing IP address.");
  }

  case CMD_ADMIN_SET_HUB_NAME: {
    if (payload && strlen(payload) > 0) {
      // Update hub friendly name in memory
      strncpy(state->hub_friendly_name, payload, sizeof(state->hub_friendly_name) - 1);
      state->hub_friendly_name[sizeof(state->hub_friendly_name) - 1] = '\0';

      // Save to config
      hub_config_write(state);

      // Sync to peers
      time_t now = time(NULL);
      char sync_msg[256];
      snprintf(sync_msg, sizeof(sync_msg), "hub_name|%s|%ld\n", payload, (long)now);
      hub_broadcast_sync_to_peers(state, sync_msg, -1);

      char response[256];
      snprintf(response, sizeof(response), "SUCCESS: Hub name updated to '%s'", payload);
      return send_response(state, client, response);
    }
    return send_response(state, client, "ERROR: Missing hub name.");
  }

  case CMD_ADMIN_SET_BIND_PORT: {
    if (payload && strlen(payload) > 0) {
      int port = atoi(payload);
      if (port <= 0 || port > 65535) {
        return send_response(state, client, "ERROR: Port must be between 1 and 65535.");
      }

      // Update port in memory
      state->port = port;

      // Save to config
      hub_config_write(state);

      // Sync to peers
      time_t now = time(NULL);
      char sync_msg[256];
      snprintf(sync_msg, sizeof(sync_msg), "port|%d|%ld\n", port, (long)now);
      hub_broadcast_sync_to_peers(state, sync_msg, -1);

      return send_response(state, client,
                         "SUCCESS: Bind port updated. Restart hub for changes to take effect.");
    }
    return send_response(state, client, "ERROR: Missing port number.");
  }

  case CMD_ADMIN_LIST_ALLOWLIST: {
    char list[MAX_BUFFER];
    int offset = 0;
    int count = 0;

    offset += snprintf(list + offset, MAX_BUFFER - offset,
                      "════════════════════════════════════════════\n");
    offset += snprintf(list + offset, MAX_BUFFER - offset,
                      "           IP ALLOWLIST\n");
    offset += snprintf(list + offset, MAX_BUFFER - offset,
                      "════════════════════════════════════════════\n\n");

    for (int i = 0; i < state->global_entry_count && offset < MAX_BUFFER - 256; i++) {
        if (strcmp(state->global_entries[i].key, "w") == 0) {
            // Skip tombstones
            if (strstr(state->global_entries[i].value, "|del") != NULL) {
                continue;
            }

            // Extract IP pattern
            char pattern[256];
            const char *pipe = strchr(state->global_entries[i].value, '|');
            if (pipe) {
                size_t len = pipe - state->global_entries[i].value;
                if (len >= sizeof(pattern)) len = sizeof(pattern) - 1;
                memcpy(pattern, state->global_entries[i].value, len);
                pattern[len] = '\0';
            } else {
                strncpy(pattern, state->global_entries[i].value, sizeof(pattern) - 1);
                pattern[sizeof(pattern) - 1] = '\0';
            }

            offset += snprintf(list + offset, MAX_BUFFER - offset,
                             "%3d. %s\n", ++count, pattern);
        }
    }

    if (count == 0) {
        offset += snprintf(list + offset, MAX_BUFFER - offset,
                         "(No allowlist entries - all IPs allowed)\n");
    }

    return send_response(state, client, list);
  }

  case CMD_ADMIN_ADD_ALLOWLIST: {
    if (payload && strlen(payload) > 0) {
        time_t now = time(NULL);
        hub_storage_update_global_entry(state, "w", payload, "", "add", now);
        hub_config_write(state);

        // NOTE: Allowlist is local-only, do not broadcast to peers

        return send_response(state, client, "SUCCESS: IP added to allowlist.");
    }
    return send_response(state, client, "ERROR: Missing IP pattern.");
  }

  case CMD_ADMIN_DEL_ALLOWLIST: {
    if (payload && strlen(payload) > 0) {
        time_t now = time(NULL);
        hub_storage_update_global_entry(state, "w", payload, "", "del", now);
        hub_config_write(state);

        // NOTE: Allowlist is local-only, do not broadcast to peers

        return send_response(state, client, "SUCCESS: IP removed from allowlist.");
    }
    return send_response(state, client, "ERROR: Missing IP pattern.");
  }

  case CMD_ADMIN_LIST_DENYLIST: {
    char list[MAX_BUFFER];
    int offset = 0;
    int count = 0;

    offset += snprintf(list + offset, MAX_BUFFER - offset,
                      "════════════════════════════════════════════\n");
    offset += snprintf(list + offset, MAX_BUFFER - offset,
                      "           IP DENYLIST\n");
    offset += snprintf(list + offset, MAX_BUFFER - offset,
                      "════════════════════════════════════════════\n\n");

    for (int i = 0; i < state->global_entry_count && offset < MAX_BUFFER - 256; i++) {
        if (strcmp(state->global_entries[i].key, "x") == 0) {
            if (strstr(state->global_entries[i].value, "|del") != NULL) {
                continue;
            }

            char pattern[256];
            const char *pipe = strchr(state->global_entries[i].value, '|');
            if (pipe) {
                size_t len = pipe - state->global_entries[i].value;
                if (len >= sizeof(pattern)) len = sizeof(pattern) - 1;
                memcpy(pattern, state->global_entries[i].value, len);
                pattern[len] = '\0';
            } else {
                strncpy(pattern, state->global_entries[i].value, sizeof(pattern) - 1);
                pattern[sizeof(pattern) - 1] = '\0';
            }

            offset += snprintf(list + offset, MAX_BUFFER - offset,
                             "%3d. %s\n", ++count, pattern);
        }
    }

    if (count == 0) {
        offset += snprintf(list + offset, MAX_BUFFER - offset,
                         "(No denylist entries)\n");
    }

    return send_response(state, client, list);
  }

  case CMD_ADMIN_ADD_DENYLIST: {
    if (payload && strlen(payload) > 0) {
        time_t now = time(NULL);
        hub_storage_update_global_entry(state, "x", payload, "", "add", now);
        hub_config_write(state);

        // NOTE: Denylist is local-only, do not broadcast to peers

        return send_response(state, client, "SUCCESS: IP added to denylist.");
    }
    return send_response(state, client, "ERROR: Missing IP pattern.");
  }

  case CMD_ADMIN_DEL_DENYLIST: {
    if (payload && strlen(payload) > 0) {
        time_t now = time(NULL);
        hub_storage_update_global_entry(state, "x", payload, "", "del", now);
        hub_config_write(state);

        // NOTE: Denylist is local-only, do not broadcast to peers

        return send_response(state, client, "SUCCESS: IP removed from denylist.");
    }
    return send_response(state, client, "ERROR: Missing IP pattern.");
  }

  default:
    return send_response(state, client, "ERROR: Unknown command.");
  }

  return true;
}

// ========== OP Request Forwarding Helper Functions ==========

static void generate_request_id(char *out_id, size_t len) {
  unsigned char rand_bytes[16];
  RAND_bytes(rand_bytes, sizeof(rand_bytes));
  snprintf(out_id, len, "%02x%02x%02x%02x-%02x%02x-%02x%02x",
           rand_bytes[0], rand_bytes[1], rand_bytes[2], rand_bytes[3],
           rand_bytes[4], rand_bytes[5], rand_bytes[6], rand_bytes[7]);
}

static int add_pending_op_request(hub_state_t *state, const char *request_id,
                                   const char *requester_uuid,
                                   const char *target_uuid,
                                   const char *channel, int origin_fd) {
  // Find an empty slot
  for (int i = 0; i < MAX_PENDING_OP_REQUESTS; i++) {
    if (!state->pending_op_requests[i].active) {
      snprintf(state->pending_op_requests[i].request_id,
               sizeof(state->pending_op_requests[i].request_id), "%s",
               request_id);
      snprintf(state->pending_op_requests[i].requester_uuid,
               sizeof(state->pending_op_requests[i].requester_uuid), "%s",
               requester_uuid);
      snprintf(state->pending_op_requests[i].target_uuid,
               sizeof(state->pending_op_requests[i].target_uuid), "%s",
               target_uuid);
      snprintf(state->pending_op_requests[i].channel,
               sizeof(state->pending_op_requests[i].channel), "%s", channel);
      state->pending_op_requests[i].origin_fd = origin_fd;
      state->pending_op_requests[i].timestamp = time(NULL);
      state->pending_op_requests[i].active = true;
      return i;
    }
  }
  return -1; // No space available
}

static pending_op_request_t *find_pending_op_request(hub_state_t *state,
                                                      const char *request_id) {
  for (int i = 0; i < MAX_PENDING_OP_REQUESTS; i++) {
    if (state->pending_op_requests[i].active &&
        strcmp(state->pending_op_requests[i].request_id, request_id) == 0) {
      return &state->pending_op_requests[i];
    }
  }
  return NULL;
}

static void remove_pending_op_request(hub_state_t *state,
                                       const char *request_id) {
  for (int i = 0; i < MAX_PENDING_OP_REQUESTS; i++) {
    if (state->pending_op_requests[i].active &&
        strcmp(state->pending_op_requests[i].request_id, request_id) == 0) {
      state->pending_op_requests[i].active = false;
      return;
    }
  }
}

static void forward_op_request_to_peers(hub_state_t *state,
                                         const char *request_id,
                                         const char *requester_uuid,
                                         const char *target_uuid,
                                         const char *channel, int exclude_fd) {
  // Payload format: request_id|requester_uuid|target_uuid|channel
  char forward_payload[512];
  snprintf(forward_payload, sizeof(forward_payload), "%s|%s|%s|%s", request_id,
           requester_uuid, target_uuid, channel);

  unsigned char plain[MAX_BUFFER];
  unsigned char buffer[MAX_BUFFER];
  unsigned char tag[GCM_TAG_LEN];

  plain[0] = CMD_OP_FORWARD_REQUEST;
  int pay_len = strlen(forward_payload);
  uint32_t net_pay_len = htonl(pay_len);
  memcpy(&plain[1], &net_pay_len, 4);
  memcpy(&plain[5], forward_payload, pay_len);

  // Send to all connected peer hubs (excluding origin)
  for (int i = 0; i < state->client_count; i++) {
    if (state->clients[i]->type == CLIENT_HUB &&
        state->clients[i]->authenticated && state->clients[i]->fd != exclude_fd) {

      int enc_len = aes_gcm_encrypt(plain, 5 + pay_len,
                                    state->clients[i]->session_key, buffer + 4,
                                    tag);
      if (enc_len > 0) {
        memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
        uint32_t net_len = htonl(enc_len + GCM_TAG_LEN);
        memcpy(buffer, &net_len, 4);

        if (write(state->clients[i]->fd, buffer, 4 + enc_len + GCM_TAG_LEN) >
            0) {
          hub_log("[HUB] Forwarded OP_REQUEST (id:%s) to peer hub fd=%d\n",
                  request_id, state->clients[i]->fd);
        }
      }
    }
  }
}

// ========== End OP Request Forwarding Helper Functions ==========

// ========== Handlers for Forwarded OP Commands from Peer Hubs ==========

static void process_forward_op_request(hub_state_t *state,
                                        hub_client_t *client, char *payload) {
  // Payload format: request_id|requester_uuid|target_uuid|channel
  char request_id[64], requester_uuid[64], target_uuid[64], channel[MAX_CHAN];

  if (sscanf(payload, "%63[^|]|%63[^|]|%63[^|]|%64s", request_id,
             requester_uuid, target_uuid, channel) != 4) {
    hub_log("[HUB] Invalid OP_FORWARD_REQUEST payload from peer fd=%d\n",
            client->fd);
    return;
  }

  hub_log(
      "[HUB] Received OP_FORWARD_REQUEST (id:%s) from peer for target %s in channel %s\n",
      request_id, target_uuid, channel);

  // Handle admin requests specially (target_uuid = "ANY", requester_uuid = "ADMIN")
  if (strcmp(target_uuid, "ANY") == 0 && strcmp(requester_uuid, "ADMIN") == 0) {
    // Admin op request - decode nick:channel format
    char nick[64], chan[MAX_CHAN];
    if (sscanf(channel, "%63[^:]:%64s", nick, chan) == 2) {
      hub_log("[HUB] Admin OP_REQUEST for %s in %s - broadcasting to local bots\n",
              nick, chan);

      // Send op grant to all local bots (they'll filter if not in channel)
      int sent_count = 0;
      for (int i = 0; i < state->client_count; i++) {
        if (state->clients[i]->type == CLIENT_BOT &&
            state->clients[i]->authenticated) {
          char op_payload[256];
          snprintf(op_payload, sizeof(op_payload), "%s|%s", nick, chan);

          unsigned char plain[MAX_BUFFER], buffer[MAX_BUFFER], tag[GCM_TAG_LEN];
          plain[0] = CMD_OP_GRANT;
          int pay_len = strlen(op_payload);
          uint32_t net_pay_len = htonl(pay_len);
          memcpy(&plain[1], &net_pay_len, 4);
          memcpy(&plain[5], op_payload, pay_len);

          int enc_len = aes_gcm_encrypt(plain, 5 + pay_len,
                                       state->clients[i]->session_key,
                                       buffer + 4, tag);
          if (enc_len > 0) {
            memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
            uint32_t net_len = htonl(enc_len + GCM_TAG_LEN);
            memcpy(buffer, &net_len, 4);

            if (send(state->clients[i]->fd, buffer, 4 + enc_len + GCM_TAG_LEN, 0) > 0) {
              sent_count++;
            }
          }
        }
      }

      // Forward to other peer hubs
      forward_op_request_to_peers(state, request_id, requester_uuid, target_uuid,
                                  channel, client->fd);
      hub_log("[HUB] Admin OP_REQUEST sent to %d local bots and forwarded to peers\n",
              sent_count);
    }
    return;
  }

  // Search for target bot locally
  hub_client_t *target = NULL;
  for (int i = 0; i < state->client_count; i++) {
    if (state->clients[i]->type == CLIENT_BOT &&
        state->clients[i]->authenticated &&
        strcmp(state->clients[i]->id, target_uuid) == 0) {
      target = state->clients[i];
      break;
    }
  }

  if (target) {
    // Target bot found locally - look up requester's hostmask
    char requester_hostmask[MAX_MASK_LEN] = "";
    for (int i = 0; i < state->bot_count; i++) {
      if (strcmp(state->bots[i].uuid, requester_uuid) == 0) {
        for (int j = 0; j < state->bots[i].entry_count; j++) {
          if (strcmp(state->bots[i].entries[j].key, "h") == 0) {
            strncpy(requester_hostmask, state->bots[i].entries[j].value,
                    sizeof(requester_hostmask) - 1);
            break;
          }
        }
        break;
      }
    }

    if (requester_hostmask[0] == '\0') {
      hub_log("[HUB] No hostmask stored for requester %s\n", requester_uuid);
      // Send FORWARD_FAILED back to origin
      char fail_payload[256];
      snprintf(fail_payload, sizeof(fail_payload), "%s|No hostmask found",
               request_id);

      unsigned char plain[MAX_BUFFER], buffer[MAX_BUFFER], tag[GCM_TAG_LEN];
      plain[0] = CMD_OP_FORWARD_FAILED;
      int pay_len = strlen(fail_payload);
      uint32_t net_pay_len = htonl(pay_len);
      memcpy(&plain[1], &net_pay_len, 4);
      memcpy(&plain[5], fail_payload, pay_len);

      int enc_len =
          aes_gcm_encrypt(plain, 5 + pay_len, client->session_key, buffer + 4,
tag);
      if (enc_len > 0) {
        memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
        uint32_t net_len = htonl(enc_len + GCM_TAG_LEN);
        memcpy(buffer, &net_len, 4);
        if (write(client->fd, buffer, 4 + enc_len + GCM_TAG_LEN) < 0) {
          hub_log("[HUB] Failed to send OP_FORWARD_FAILED to peer\n");
        }
      }
      return;
    }

    // Send OP_GRANT to local target bot
    char grant_payload[512];
    snprintf(grant_payload, sizeof(grant_payload), "%s|%s", requester_hostmask,
             channel);

    unsigned char plain[MAX_BUFFER], buffer[MAX_BUFFER], tag[GCM_TAG_LEN];
    plain[0] = CMD_OP_GRANT;
    int pay_len = strlen(grant_payload);
    uint32_t net_pay_len = htonl(pay_len);
    memcpy(&plain[1], &net_pay_len, 4);
    memcpy(&plain[5], grant_payload, pay_len);

    int enc_len = aes_gcm_encrypt(plain, 5 + pay_len, target->session_key,
                                  buffer + 4, tag);
    if (enc_len > 0) {
      memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
      uint32_t net_len = htonl(enc_len + GCM_TAG_LEN);
      memcpy(buffer, &net_len, 4);

      if (write(target->fd, buffer, 4 + enc_len + GCM_TAG_LEN) > 0) {
        hub_log("[HUB] Sent OP_GRANT to local bot %s for request id:%s\n",
                target_uuid, request_id);

        // Send FORWARD_GRANT back to origin peer
        char success_payload[256];
        snprintf(success_payload, sizeof(success_payload), "%s", request_id);

        plain[0] = CMD_OP_FORWARD_GRANT;
        pay_len = strlen(success_payload);
        net_pay_len = htonl(pay_len);
        memcpy(&plain[1], &net_pay_len, 4);
        memcpy(&plain[5], success_payload, pay_len);

        enc_len = aes_gcm_encrypt(plain, 5 + pay_len, client->session_key,
                                  buffer + 4, tag);
        if (enc_len > 0) {
          memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
          net_len = htonl(enc_len + GCM_TAG_LEN);
          memcpy(buffer, &net_len, 4);
          if (write(client->fd, buffer, 4 + enc_len + GCM_TAG_LEN) > 0) {
            hub_log("[HUB] Sent OP_FORWARD_GRANT back to peer for id:%s\n",
                    request_id);
          }
        }
      }
    }
  } else {
    // Target not found locally - forward to other peers (exclude origin)
    hub_log("[HUB] Target bot %s not found locally, forwarding to other "
            "peers\n",
            target_uuid);
    forward_op_request_to_peers(state, request_id, requester_uuid, target_uuid,
                                 channel, client->fd);
  }
}

static void process_forward_op_grant(hub_state_t *state, hub_client_t *client,
                                      char *payload) {
  (void)client; // Not used - response goes to original requester
  // Payload format: request_id
  char request_id[64];
  strncpy(request_id, payload, 63);
  request_id[63] = '\0';

  hub_log("[HUB] Received OP_FORWARD_GRANT from peer for request id:%s\n",
          request_id);

  // Find the pending request
  pending_op_request_t *req = find_pending_op_request(state, request_id);
  if (!req) {
    hub_log("[HUB] No pending request found for id:%s\n", request_id);
    return;
  }

  // Find the original requester bot
  hub_client_t *requester = NULL;
  for (int i = 0; i < state->client_count; i++) {
    if (state->clients[i]->fd == req->origin_fd &&
        state->clients[i]->type == CLIENT_BOT) {
      requester = state->clients[i];
      break;
    }
  }

  if (requester) {
    // Send success notification to requester
    unsigned char plain[MAX_BUFFER], buffer[MAX_BUFFER], tag[GCM_TAG_LEN];
    plain[0] = CMD_OP_GRANT;
    const char *success_msg = "Request forwarded successfully";
    int msg_len = strlen(success_msg);
    uint32_t net_msg_len = htonl(msg_len);
    memcpy(&plain[1], &net_msg_len, 4);
    memcpy(&plain[5], success_msg, msg_len);

    int enc_len = aes_gcm_encrypt(plain, 5 + msg_len, requester->session_key,
                                  buffer + 4, tag);
    if (enc_len > 0) {
      memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
      uint32_t net_len = htonl(enc_len + GCM_TAG_LEN);
      memcpy(buffer, &net_len, 4);
      if (write(requester->fd, buffer, 4 + enc_len + GCM_TAG_LEN) > 0) {
        hub_log("[HUB] Notified requester bot of successful grant for id:%s\n",
                request_id);
      }
    }
  }

  // Remove the pending request
  remove_pending_op_request(state, request_id);
}

static void process_forward_op_failed(hub_state_t *state, hub_client_t *client,
                                       char *payload) {
  (void)client; // Not used - response goes to original requester
  // Payload format: request_id|reason
  char request_id[64], reason[256];

  if (sscanf(payload, "%63[^|]|%255[^\n]", request_id, reason) < 1) {
    hub_log("[HUB] Invalid OP_FORWARD_FAILED payload from peer\n");
    return;
  }

  hub_log("[HUB] Received OP_FORWARD_FAILED from peer for request id:%s\n",
          request_id);

  // Find the pending request
  pending_op_request_t *req = find_pending_op_request(state, request_id);
  if (!req) {
    hub_log("[HUB] No pending request found for id:%s\n", request_id);
    return;
  }

  // Find the original requester bot
  hub_client_t *requester = NULL;
  for (int i = 0; i < state->client_count; i++) {
    if (state->clients[i]->fd == req->origin_fd &&
        state->clients[i]->type == CLIENT_BOT) {
      requester = state->clients[i];
      break;
    }
  }

  if (requester) {
    // Send failure notification to requester
    unsigned char plain[MAX_BUFFER], buffer[MAX_BUFFER], tag[GCM_TAG_LEN];
    plain[0] = CMD_OP_FAILED;
    const char *fail_msg =
        (reason[0] != '\0') ? reason : "Target bot not found on network";
    int msg_len = strlen(fail_msg);
    uint32_t net_msg_len = htonl(msg_len);
    memcpy(&plain[1], &net_msg_len, 4);
    memcpy(&plain[5], fail_msg, msg_len);

    int enc_len = aes_gcm_encrypt(plain, 5 + msg_len, requester->session_key,
                                  buffer + 4, tag);
    if (enc_len > 0) {
      memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
      uint32_t net_len = htonl(enc_len + GCM_TAG_LEN);
      memcpy(buffer, &net_len, 4);
      if (write(requester->fd, buffer, 4 + enc_len + GCM_TAG_LEN) > 0) {
        hub_log("[HUB] Notified requester bot of failure for id:%s\n",
                request_id);
      }
    }
  }

  // Remove the pending request
  remove_pending_op_request(state, request_id);
}

// ========== End Handlers for Forwarded OP Commands ==========

static void process_bot_command(hub_state_t *state, hub_client_t *client,
                                int cmd, char *payload) {
  switch (cmd) {
  case CMD_PING:
    hub_log("[HUB] Bot %s PING\n", client->id);
    break;

  case CMD_CONFIG_PUSH: {
    process_bot_config_push(state, client, payload);
  } break;

  case CMD_CONFIG_PULL:
    hub_log("[HUB] Config PULL request from %s\n", client->id);
    send_config_to_bot(state, client);
    break;

  case CMD_OP_REQUEST: {
    // Payload format: target_uuid|channel
    char target_uuid[64];
    char channel[MAX_CHAN];

    if (sscanf(payload, "%63[^|]|%64s", target_uuid, channel) != 2) {
      hub_log("[HUB] Invalid OP_REQUEST payload from %s\n", client->id);
      break;
    }

    hub_log("[HUB] OP_REQUEST from %s for target %s in %s\n", client->id,
            target_uuid, channel);

    // Find target bot's client connection
    hub_client_t *target = NULL;
    for (int i = 0; i < state->client_count; i++) {
      if (state->clients[i]->type == CLIENT_BOT &&
          state->clients[i]->authenticated &&
          strcmp(state->clients[i]->id, target_uuid) == 0) {
        target = state->clients[i];
        break;
      }
    }

    if (!target) {
      // Target bot not connected locally - check for peer hubs
      hub_log("[HUB] Target bot %s not connected locally\n", target_uuid);

      // Count connected peer hubs
      int peer_count = 0;
      for (int i = 0; i < state->client_count; i++) {
        if (state->clients[i]->type == CLIENT_HUB &&
            state->clients[i]->authenticated) {
          peer_count++;
        }
      }

      if (peer_count > 0) {
        // Forward request to peer hubs
        char request_id[64];
        generate_request_id(request_id, sizeof(request_id));

        if (add_pending_op_request(state, request_id, client->id, target_uuid,
                                    channel, client->fd) >= 0) {
          forward_op_request_to_peers(state, request_id, client->id,
                                       target_uuid, channel, -1);
          hub_log("[HUB] Forwarded OP_REQUEST (id:%s) to %d peer hub(s)\n",
                  request_id, peer_count);
        } else {
          hub_log("[HUB] Failed to add pending OP request - table full\n");
          // Fall through to send OP_FAILED
          peer_count = 0;
        }
      }

      if (peer_count == 0) {
        // No peers available or table full - send OP_FAILED
        unsigned char plain[MAX_BUFFER];
        unsigned char buffer[MAX_BUFFER];
        unsigned char tag[GCM_TAG_LEN];

        plain[0] = CMD_OP_FAILED;
        const char *reason = "Target bot not connected";
        int reason_len = strlen(reason);
        uint32_t net_len_inner = htonl(reason_len);
        memcpy(&plain[1], &net_len_inner, 4);
        memcpy(&plain[5], reason, reason_len);

        int enc_len = aes_gcm_encrypt(plain, 5 + reason_len,
                                      client->session_key, buffer + 4, tag);
        if (enc_len > 0) {
          memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
          uint32_t net_len = htonl(enc_len + GCM_TAG_LEN);
          memcpy(buffer, &net_len, 4);
          if (write(client->fd, buffer, 4 + enc_len + GCM_TAG_LEN) < 0) {
            hub_log("[HUB][ERROR] Failed to send OP_FAILED response to %s\n",
                    client->id);
          }
        }
      }
      break;
    }

    // Look up requesting bot's hostmask from storage
    char requester_hostmask[MAX_MASK_LEN] = "";
    for (int i = 0; i < state->bot_count; i++) {
      if (strcmp(state->bots[i].uuid, client->id) == 0) {
        for (int j = 0; j < state->bots[i].entry_count; j++) {
          if (strcmp(state->bots[i].entries[j].key, "h") == 0) {
            strncpy(requester_hostmask, state->bots[i].entries[j].value,
                    sizeof(requester_hostmask) - 1);
            break;
          }
        }
        break;
      }
    }

    if (requester_hostmask[0] == '\0') {
      hub_log("[HUB] No hostmask stored for requesting bot %s\n", client->id);
      break;
    }

    // Forward CMD_OP_GRANT to target bot
    // Payload: requester_hostmask|channel
    char grant_payload[512];
    snprintf(grant_payload, sizeof(grant_payload), "%s|%s", requester_hostmask,
             channel);

    unsigned char plain[MAX_BUFFER];
    unsigned char buffer[MAX_BUFFER];
    unsigned char tag[GCM_TAG_LEN];

    plain[0] = CMD_OP_GRANT;
    int pay_len = strlen(grant_payload);
    uint32_t net_pay_len = htonl(pay_len);
    memcpy(&plain[1], &net_pay_len, 4);
    memcpy(&plain[5], grant_payload, pay_len);

    int enc_len = aes_gcm_encrypt(plain, 5 + pay_len, target->session_key,
                                  buffer + 4, tag);
    if (enc_len > 0) {
      memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
      uint32_t net_len = htonl(enc_len + GCM_TAG_LEN);
      memcpy(buffer, &net_len, 4);

      if (write(target->fd, buffer, 4 + enc_len + GCM_TAG_LEN) > 0) {
        hub_log("[HUB] Forwarded OP_GRANT to %s: grant ops to %s in %s\n",
                target_uuid, requester_hostmask, channel);
      }
    }
  } break;
  }
}

// NEW FUNCTION: Send hub's stored config back to bot
static void send_config_to_bot(hub_state_t *state, hub_client_t *client) {
  char payload[MAX_BUFFER];

  // Use the new payload generator that combines Global + Bot-specific
  // and omits "b|uuid|" prefix for correct bot parsing
  hub_generate_bot_payload(state, client->id, payload, sizeof(payload));

  // Even if empty, we might want to send it, but usually there's at least
  // global config
  int len = strlen(payload);
  if (len == 0) {
    hub_log("[HUB] No config to send to %s\n", client->id);
    return;
  }

  hub_log("[HUB-SYNC] Sending to %s (%d bytes)\n", client->id, len);

  // Send CMD_CONFIG_DATA packet
  unsigned char buffer[MAX_BUFFER];
  unsigned char plain[MAX_BUFFER];
  unsigned char tag[GCM_TAG_LEN];

  plain[0] = CMD_CONFIG_DATA;
  uint32_t payload_len = htonl(len);  // Must be network byte order for bot to decode
  memcpy(&plain[1], &payload_len, 4);
  memcpy(&plain[5], payload, len);

  int enc_len =
      aes_gcm_encrypt(plain, 5 + len, client->session_key, buffer + 4, tag);
  if (enc_len > 0) {
    memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
    uint32_t net_len = htonl(enc_len + GCM_TAG_LEN);
    memcpy(buffer, &net_len, 4);

    if (write(client->fd, buffer, 4 + enc_len + GCM_TAG_LEN) > 0) {
      hub_log("[HUB] Sent config (%d bytes) to %s\n", len, client->id);
    }
  }
}

bool hub_handle_client_data(hub_state_t *state, hub_client_t *client) {
  while (client->recv_len >= 4) {
    uint32_t net_len;
    memcpy(&net_len, client->recv_buf, 4);
    int packet_len = ntohl(net_len);

    // ADDED: Enhanced bounds checking
    if (packet_len < 0 || packet_len > (MAX_BUFFER - 4)) {
      hub_log("[ERROR] Invalid packet length %d from %s\n", packet_len,
              client->ip);
      hub_disconnect_client(state, client);
      return false;
    }

    if (client->recv_len < (4 + packet_len)) {
      return true; // Need more data
    }

    unsigned char *data = client->recv_buf + 4;

    // ========================================================================
    // AUTHENTICATION PHASE
    // ========================================================================
    if (!client->authenticated) {
      // Detect packet type: Bot UUID (plaintext, 36-64 chars,
      // alphanumeric+hyphens)
      bool looks_like_uuid = false;
      if (packet_len >= 36 && packet_len <= 64) {
        looks_like_uuid = true;
        for (int i = 0; i < packet_len && looks_like_uuid; i++) {
          char c = data[i];
          if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                (c >= 'A' && c <= 'F') || c == '-')) {
            looks_like_uuid = false;
          }
        }
      }

      // Bot authentication (plaintext UUID or signature)
      if (looks_like_uuid || client->bot_auth_state != BOT_AUTH_IDLE) {
        goto bot_authentication;
      }

      // Try RSA decryption (for ADMIN and HUB peer auth)
      if (packet_len > 32 && packet_len <= 512) {
        unsigned char dec[512];
        int dec_len =
            evp_private_decrypt(state->priv_key, data, packet_len, dec);

        if (dec_len > 32) {
          memcpy(client->session_key, dec, 32);
          char *payload = (char *)dec + 32;
          dec[dec_len] = 0;

          // ADMIN Authentication
          if (strncmp(payload, "ADMIN", 5) == 0) {
            // Parse: "ADMIN password|connect_ip:connect_port"
            char *pipe = strchr(payload + 6, '|');
            char pass_buf[128];
            int pass_len;

            if (pipe) {
              // Extract password (everything between "ADMIN " and "|")
              pass_len = pipe - (payload + 6);
              if (pass_len >= (int)sizeof(pass_buf)) pass_len = sizeof(pass_buf) - 1;
              memcpy(pass_buf, payload + 6, pass_len);
              pass_buf[pass_len] = '\0';
            } else {
              // Old format without connection info
              strncpy(pass_buf, payload + 6, sizeof(pass_buf) - 1);
              pass_buf[sizeof(pass_buf) - 1] = '\0';
            }

            if (strcmp(pass_buf, state->admin_password) == 0) {
              client->type = CLIENT_ADMIN;
              client->authenticated = true;
              strncpy(client->id, "ADMIN", sizeof(client->id) - 1);
              client->id[sizeof(client->id) - 1] = 0;

              // Parse and store connection IP:port if available
              if (pipe) {
                char *colon = strchr(pipe + 1, ':');
                if (colon) {
                  int ip_len = colon - (pipe + 1);
                  if (ip_len >= (int)sizeof(client->admin_connect_ip))
                    ip_len = sizeof(client->admin_connect_ip) - 1;
                  memcpy(client->admin_connect_ip, pipe + 1, ip_len);
                  client->admin_connect_ip[ip_len] = '\0';
                  client->admin_connect_port = atoi(colon + 1);
                } else {
                  client->admin_connect_ip[0] = '\0';
                  client->admin_connect_port = 0;
                }
              } else {
                client->admin_connect_ip[0] = '\0';
                client->admin_connect_port = 0;
              }

              hub_log("[HUB] Admin Login: %s\n", client->ip);
            } else {
              hub_log("[HUB] Failed admin auth from %s\n", client->ip);
              record_failed_auth(state, client->ip);
              secure_wipe(dec, sizeof(dec));
              hub_disconnect_client(state, client);
              return false;
            }
          }
          // HUB Peer Authentication
          else if (strncmp(payload, "HUB", 3) == 0) {
            char pass[128], peer_uuid[64], peer_name[64], peer_bind_ip[64];
            int claimed_port = 0;
            memset(peer_uuid, 0, sizeof(peer_uuid));
            memset(peer_name, 0, sizeof(peer_name));
            memset(peer_bind_ip, 0, sizeof(peer_bind_ip));

            // Parse: HUB <password> <port> <uuid> <friendly_name> <bind_ip>
            int args = sscanf(payload + 4, "%127s %d %63s %63s %63s",
                            pass, &claimed_port, peer_uuid, peer_name, peer_bind_ip);

            if (args >= 1 && strcmp(pass, state->admin_password) == 0) {
              client->type = CLIENT_HUB;

              bool is_authorized_peer = false;
              int peer_idx = -1;

              // Find and validate peer by UUID (primary) or IP:port (fallback)
              for (int p = 0; p < state->peer_count; p++) {
                // UUID-based matching (preferred)
                if (args >= 3 && peer_uuid[0] && state->peers[p].uuid[0]) {
                  if (strcmp(state->peers[p].uuid, peer_uuid) == 0) {
                    peer_idx = p;
                    is_authorized_peer = true;
                    break;
                  }
                }
                // Fallback to IP:port matching for backward compatibility
                else {
                  bool ip_match = (strcmp(state->peers[p].ip, client->ip) == 0 ||
                                   strcmp(state->bind_ip, client->ip) == 0);

                  if (ip_match && claimed_port > 0 && state->peers[p].port == claimed_port) {
                    peer_idx = p;
                    is_authorized_peer = true;
                    break;
                  }
                }
              }

              if (!is_authorized_peer) {
                hub_log("[HUB] Unauthorized peer from %s (UUID: %s)\n",
                       client->ip, peer_uuid[0] ? peer_uuid : "none");
                secure_wipe(dec, sizeof(dec));
                hub_disconnect_client(state, client);
                return false;
              }

              // UUID mismatch check - disconnect if UUIDs don't match
              if (args >= 3 && peer_uuid[0] && state->peers[peer_idx].uuid[0]) {
                if (strcmp(state->peers[peer_idx].uuid, peer_uuid) != 0) {
                  hub_log("[HUB] UUID mismatch for peer %s (expected: %s, got: %s)\n",
                         client->ip, state->peers[peer_idx].uuid, peer_uuid);
                  secure_wipe(dec, sizeof(dec));
                  hub_disconnect_client(state, client);
                  return false;
                }
              }

              // Update peer connection info
              client->authenticated = true;
              state->peers[peer_idx].connected = true;
              state->peers[peer_idx].fd = client->fd;

              // Store actual connection IP (from socket)
              snprintf(state->peers[peer_idx].remote_ip,
                      sizeof(state->peers[peer_idx].remote_ip), "%s", client->ip);

              // Don't overwrite friendly_name from handshake - config is source of truth
              // Only update if it's currently empty AND handshake provides one
              if (!state->peers[peer_idx].friendly_name[0] && args >= 4 && peer_name[0]) {
                snprintf(state->peers[peer_idx].friendly_name,
                        sizeof(state->peers[peer_idx].friendly_name), "%s", peer_name);
              }

              snprintf(client->id, sizeof(client->id), "%s",
                      state->peers[peer_idx].friendly_name[0] ?
                      state->peers[peer_idx].friendly_name :
                      (peer_name[0] ? peer_name : "HUB-PEER"));
              client->id[sizeof(client->id) - 1] = 0;

              // Send initial sync (existing code)...
              hub_log("[HUB] Peer connected: %s (%s)\n",
                     peer_name[0] ? peer_name : client->ip,
                     peer_uuid[0] ? peer_uuid : "no-uuid");
            } else {
              hub_log("[HUB] Failed peer auth from %s\n", client->ip);
              record_failed_auth(state, client->ip);
              secure_wipe(dec, sizeof(dec));
              hub_disconnect_client(state, client);
              return false;
            }
          } else {
            // Unknown RSA payload
            secure_wipe(dec, sizeof(dec));
            hub_disconnect_client(state, client);
            return false;
          }

          secure_wipe(dec, sizeof(dec));
        } else {
          // RSA decrypt failed - treat as bot auth (plaintext UUID or
          // signature)
          goto bot_authentication;
        }
      } else {
      // Packet too small/large for RSA - must be bot auth
      bot_authentication:

        // PHASE 1: Receive plaintext UUID
        if (client->bot_auth_state == BOT_AUTH_IDLE) {
          char uuid[64];
          int copy_len = (packet_len < 63) ? packet_len : 63;
          memcpy(uuid, data, copy_len);
          uuid[copy_len] = '\0';

          hub_log("[HUB] Bot auth: UUID=%s from %s\n", uuid, client->ip);

          // Check authorization
          bool authorized = false;
          for (int i = 0; i < state->bot_count; i++) {
            if (strcmp(state->bots[i].uuid, uuid) == 0 &&
                state->bots[i].is_active) {
              authorized = true;
              break;
            }
          }

          if (!authorized) {
            hub_log("[HUB] Unauthorized bot: %s\n", uuid);
            add_pending_bot(state, uuid, client->ip);
            hub_disconnect_client(state, client);
            return false;
          }

          // Load bot's public key
          EVP_PKEY *pub_key = load_bot_public_key(state, uuid);
          if (!pub_key) {
            hub_log("[HUB][ERROR] No public key for bot %s\n", uuid);
            hub_disconnect_client(state, client);
            return false;
          }

          // Generate challenge
          if (RAND_bytes(client->challenge, 32) != 1) {
            EVP_PKEY_free(pub_key);
            hub_log("[HUB][ERROR] Failed to generate challenge\n");
            hub_disconnect_client(state, client);
            return false;
          }

          // Encrypt challenge with bot's public key
          unsigned char enc_challenge[512];
          int enc_len = rsa_encrypt_with_bot_pubkey(pub_key, client->challenge,
                                                    32, enc_challenge);
          EVP_PKEY_free(pub_key);

          if (enc_len <= 0) {
            hub_log("[HUB][ERROR] Failed to encrypt challenge\n");
            hub_disconnect_client(state, client);
            return false;
          }

          // Send encrypted challenge
          uint32_t net_len_send = htonl(enc_len);
          if (write(client->fd, &net_len_send, 4) != 4 ||
              write(client->fd, enc_challenge, enc_len) != enc_len) {
            hub_log("[HUB][ERROR] Failed to send challenge\n");
            hub_disconnect_client(state, client);
            return false;
          }

          strncpy(client->id, uuid, sizeof(client->id) - 1);
          client->id[sizeof(client->id) - 1] = '\0';
          client->bot_auth_state = BOT_AUTH_CHALLENGE_SENT;
          client->last_seen = time(NULL);

          hub_log("[HUB] Challenge sent to bot %s\n", uuid);
        }
        // PHASE 2: Receive signature
        else if (client->bot_auth_state == BOT_AUTH_CHALLENGE_SENT) {
          hub_log("[HUB] Received signature from %s (%d bytes)\n", client->id,
                  packet_len);

          // Load bot's public key
          EVP_PKEY *pub_key = load_bot_public_key(state, client->id);
          if (!pub_key) {
            hub_log("[HUB][ERROR] No public key for %s\n", client->id);
            hub_disconnect_client(state, client);
            return false;
          }

          // Verify signature
          bool valid = verify_signature_with_bot_pubkey(
              pub_key, client->challenge, 32, data, packet_len);

          if (!valid) {
            EVP_PKEY_free(pub_key);
            hub_log("[HUB][ERROR] Invalid signature from %s\n", client->id);
            hub_disconnect_client(state, client);
            return false;
          }

          hub_log("[HUB] Signature verified for %s\n", client->id);

          // Generate session key
          if (RAND_bytes(client->session_key, 32) != 1) {
            EVP_PKEY_free(pub_key);
            hub_log("[HUB][ERROR] Failed to generate session key\n");
            hub_disconnect_client(state, client);
            return false;
          }

          // Encrypt session key
          unsigned char enc_session[512];
          int enc_len = rsa_encrypt_with_bot_pubkey(
              pub_key, client->session_key, 32, enc_session);
          EVP_PKEY_free(pub_key);

          if (enc_len <= 0) {
            hub_log("[HUB][ERROR] Failed to encrypt session key\n");
            hub_disconnect_client(state, client);
            return false;
          }

          // Send encrypted session key
          uint32_t net_len_send = htonl(enc_len);
          if (write(client->fd, &net_len_send, 4) != 4 ||
              write(client->fd, enc_session, enc_len) != enc_len) {
            hub_log("[HUB][ERROR] Failed to send session key\n");
            hub_disconnect_client(state, client);
            return false;
          }

          // Mark authenticated
          client->type = CLIENT_BOT;
          client->authenticated = true;
          client->bot_auth_state = BOT_AUTH_COMPLETE;
          client->last_seen = time(NULL);

          // Update "seen" timestamp on successful authentication
          hub_storage_update_entry(state, client->id, "seen", "", "", "", client->last_seen);

          send_config_to_bot(state, client);
          hub_log("[HUB] Bot %s authenticated successfully\n", client->id);
        } else {
          hub_log("[HUB][ERROR] Invalid auth state from %s\n", client->ip);
          hub_disconnect_client(state, client);
          return false;
        }
      }
    }
    // ========================================================================
    // AUTHENTICATED - AES-GCM ENCRYPTED PACKETS
    // ========================================================================
    else {
      if (packet_len > GCM_TAG_LEN) {
        unsigned char plain[MAX_BUFFER], tag[GCM_TAG_LEN];

        memcpy(tag, data + packet_len - GCM_TAG_LEN, GCM_TAG_LEN);

        int pl = aes_gcm_decrypt(data, packet_len - GCM_TAG_LEN,
                                 client->session_key, plain, tag);

        if (pl > 0) {
          unsigned char cmd = plain[0];

          if (cmd == CMD_PING) {
            time_t now = time(NULL);
            if (now - client->last_pong_sent >= 5) {
              if (!send_pong(state, client)) {
                return false;
              }
              client->last_pong_sent = now;
            }
          } else {
            plain[pl] = 0;
            char *payload_ptr = (char *)plain + 5;

            if (client->type == CLIENT_ADMIN) {
              if (!handle_admin_command(state, client, cmd, payload_ptr)) {
                return false;
              }
            } else if (client->type == CLIENT_BOT) {
              process_bot_command(state, client, cmd, payload_ptr);
            } else if (client->type == CLIENT_HUB) {
              if (cmd == CMD_PEER_SYNC) {
                process_peer_sync(state, payload_ptr, client->fd);
              } else if (cmd == CMD_MESH_STATE) {
                process_mesh_state(state, client, payload_ptr);
              } else if (cmd == CMD_OP_FORWARD_REQUEST) {
                process_forward_op_request(state, client, payload_ptr);
              } else if (cmd == CMD_OP_FORWARD_GRANT) {
                process_forward_op_grant(state, client, payload_ptr);
              } else if (cmd == CMD_OP_FORWARD_FAILED) {
                process_forward_op_failed(state, client, payload_ptr);
              } else if (cmd == CMD_PEER_REKEY_BOT) {
                // Peer hub is forwarding a bot rekey request to us
                // Payload format: bot_uuid|new_priv_b64
                if (payload_ptr && strlen(payload_ptr) > 0) {
                  char bot_uuid[64];
                  char *pipe = strchr(payload_ptr, '|');
                  if (pipe && (pipe - payload_ptr) < 64) {
                    memcpy(bot_uuid, payload_ptr, pipe - payload_ptr);
                    bot_uuid[pipe - payload_ptr] = '\0';
                    char *new_priv_b64 = pipe + 1;

                    hub_log("[HUB] Received rekey forward for bot %s from peer %s\n", bot_uuid, client->ip);

                    // Find the bot client connected to THIS hub
                    hub_client_t *bot_client = NULL;
                    for (int i = 0; i < state->client_count; i++) {
                      if (state->clients[i]->type == CLIENT_BOT &&
                          strcmp(state->clients[i]->id, bot_uuid) == 0 &&
                          state->clients[i]->authenticated) {
                        bot_client = state->clients[i];
                        break;
                      }
                    }

                    if (bot_client) {
                      // Send CMD_BOT_KEY_UPDATE to the bot
                      unsigned char buffer[MAX_BUFFER];
                      unsigned char plain[MAX_BUFFER];
                      unsigned char tag[GCM_TAG_LEN];

                      plain[0] = CMD_BOT_KEY_UPDATE;
                      int key_len = strlen(new_priv_b64);
                      uint32_t payload_len = htonl(key_len);
                      memcpy(&plain[1], &payload_len, 4);
                      memcpy(&plain[5], new_priv_b64, key_len);

                      int enc_len = aes_gcm_encrypt(plain, 5 + key_len, bot_client->session_key,
                                                    buffer + 4, tag);
                      if (enc_len > 0) {
                        memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
                        uint32_t net_len = htonl(enc_len + GCM_TAG_LEN);
                        memcpy(buffer, &net_len, 4);

                        if (write(bot_client->fd, buffer, 4 + enc_len + GCM_TAG_LEN) > 0) {
                          hub_log("[HUB] Sent forwarded rekey to bot %s, disconnecting\n", bot_uuid);

                          // Give bot a moment to process and save the new key
                          struct timespec delay = {.tv_sec = 0, .tv_nsec = 100000000}; // 100ms
                          nanosleep(&delay, NULL);

                          // Disconnect so bot reconnects with new key
                          hub_disconnect_client(state, bot_client);
                        } else {
                          hub_log("[HUB] Failed to send forwarded rekey to bot %s\n", bot_uuid);
                        }
                      }
                    } else {
                      hub_log("[HUB] Bot %s not connected to this hub (peer forwarding miss)\n", bot_uuid);
                    }
                  }
                }
              } else if (cmd == CMD_UPDATE_PUBKEY) {
                // Peer hub sent us the new shared private and public keys after rekey
                // Payload format: "PRIVKEY|||PUBKEY"
                if (payload_ptr && strlen(payload_ptr) > 0) {
                  hub_log("[HUB] Received key update from peer %s\n", client->ip);

                  // Parse the combined payload
                  char *separator = strstr(payload_ptr, "|||");
                  if (separator) {
                    // Split into private and public keys
                    size_t priv_len = separator - payload_ptr;
                    char *new_priv_pem = malloc(priv_len + 1);
                    char *new_pub_pem = strdup(separator + 3); // Skip "|||"

                    if (new_priv_pem && new_pub_pem) {
                      memcpy(new_priv_pem, payload_ptr, priv_len);
                      new_priv_pem[priv_len] = '\0';

                      // Validate the new private key
                      EVP_PKEY *new_pkey = load_private_key_from_memory(new_priv_pem);
                      if (new_pkey) {
                        // Save the new private and public keys
                        if (state->private_key_pem) {
                          secure_wipe(state->private_key_pem, strlen(state->private_key_pem));
                          free(state->private_key_pem);
                        }
                        if (state->public_key_pem) {
                          free(state->public_key_pem);
                        }
                        if (state->priv_key) {
                          EVP_PKEY_free(state->priv_key);
                        }

                        state->private_key_pem = new_priv_pem;
                        state->public_key_pem = new_pub_pem;
                        state->priv_key = new_pkey;
                        hub_config_write(state);

                        hub_log("[HUB] Updated private and public keys from peer rekey, disconnecting all peers\n");

                        // Disconnect all peer hubs so they reconnect with new keys
                        for (int i = 0; i < state->client_count; i++) {
                          if (state->clients[i]->type == CLIENT_HUB) {
                            hub_disconnect_client(state, state->clients[i]);
                            i--; // Adjust index since client_count decreased
                          }
                        }

                        return false;
                      } else {
                        hub_log("[HUB] Failed to load new private key from peer %s\n", client->ip);
                        secure_wipe(new_priv_pem, strlen(new_priv_pem));
                        free(new_priv_pem);
                        free(new_pub_pem);
                      }
                    } else {
                      hub_log("[HUB] Failed to allocate memory for keys\n");
                      if (new_priv_pem) free(new_priv_pem);
                      if (new_pub_pem) free(new_pub_pem);
                    }
                  } else {
                    hub_log("[HUB] Invalid key update format from peer %s\n", client->ip);
                  }
                }
              }
            }
          }
        } else {
          hub_log("[HUB] GCM decrypt failed from %s\n", client->ip);
          hub_disconnect_client(state, client);
          return false;
        }
      }
    }

    // Remove processed packet from buffer
    int consumed = 4 + packet_len;
    int remaining = client->recv_len - consumed;

    if (remaining > 0) {
      memmove(client->recv_buf, client->recv_buf + consumed, remaining);
    }

    client->recv_len = remaining;
  }

  return true;
}
