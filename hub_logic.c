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

// --- Forward Declarations ---
static bool send_response(hub_state_t *state, hub_client_t *client,
                          const char *msg);
static bool send_pong(hub_state_t *state, hub_client_t *c);
void hub_broadcast_mesh_state(hub_state_t *state);
static void add_pending_bot(hub_state_t *state, const char *uuid,
                            const char *ip);
static void remove_pending_bot(hub_state_t *state, const char *uuid);
static void broadcast_new_key(hub_state_t *state, const char *new_pub_key);
static void process_mesh_state(hub_state_t *state, hub_client_t *c,
                               char *payload);
static void process_peer_sync(hub_state_t *state, char *payload, int origin_fd);
static bool handle_admin_command(hub_state_t *state, hub_client_t *client,
                                 int cmd, char *payload);
static void process_bot_command(hub_state_t *state, hub_client_t *client,
                                int cmd, char *payload);

// Crypto/Config Forward Decls
bool hub_crypto_generate_bot_creds(char **out_uuid, char **out_priv_b64,
                                   char **out_pub_b64);

// --- Helper Functions ---

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

static void broadcast_new_key(hub_state_t *state, const char *new_pub_key) {
  unsigned char buffer[MAX_BUFFER];
  unsigned char tag[GCM_TAG_LEN];
  unsigned char plain[MAX_BUFFER];

  plain[0] = CMD_UPDATE_PUBKEY;
  int payload_len = strlen(new_pub_key);
  if (payload_len > (MAX_BUFFER - 10))
    return;

  memcpy(&plain[1], &payload_len, 4);
  memcpy(&plain[5], new_pub_key, payload_len);
  int total_plain = 1 + 4 + payload_len;

  int sent_count = 0;
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->authenticated && c->type == CLIENT_BOT) {
      int enc_len =
          aes_gcm_encrypt(plain, total_plain, c->session_key, buffer + 4, tag);
      if (enc_len > 0) {
        memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
        int packet_len = enc_len + GCM_TAG_LEN;
        uint32_t net_len = htonl(packet_len);
        memcpy(buffer, &net_len, 4);

        if (write(c->fd, buffer, 4 + packet_len) == (4 + packet_len)) {
          sent_count++;
        }
      }
    }
  }
  hub_log("[HUB] Broadcasted new key to %d bots.\n", sent_count);
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
    hub_storage_update_entry(state, uuid, "seen", "0", "", "", now);
  }
}

// FIXED: Added comprehensive bounds checking for CMD_ADMIN_LIST_PEERS
void hub_broadcast_mesh_state(hub_state_t *state) {
  char payload[MAX_BUFFER];
  memset(payload, 0, sizeof(payload));
  int offset = 0;
  int written;

  written = snprintf(payload + offset, MAX_BUFFER - offset, "127.0.0.1:%d|",
                     state->port);
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

    written = snprintf(payload + offset, MAX_BUFFER - offset, "%s:%d:%d,",
                       state->peers[i].ip, state->peers[i].port, is_up);
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
          snprintf(my_sig, sizeof(my_sig), "127.0.0.1:%d", state->port);

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
  for (int i = 0; i < state->client_count; i++) {
    if (state->clients[i]->type == CLIENT_BOT &&
        state->clients[i]->authenticated) {
      active_bots++;
    }
  }

  unsigned char buffer[MAX_BUFFER];
  unsigned char plain[MAX_BUFFER];
  unsigned char tag[GCM_TAG_LEN];

  plain[0] = CMD_MESH_STATE;
  char final_packet[MAX_BUFFER];

  written = snprintf(final_packet, sizeof(final_packet), "%d:%d:%d|%s",
                     connected_peers, state->peer_count, active_bots, payload);
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
        if (hub_storage_update_entry(state, client->id, "c", chan, key, op,
                                     ts)) {
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
        if (hub_storage_update_entry(state, client->id, "m", mask, "", op,
                                     ts)) {
          updates++;
          int w = snprintf(sync_buffer + sync_offset,
                           sizeof(sync_buffer) - sync_offset,
                           "b|%s|m|%s||%s|%ld\n", client->id, mask, op, ts);
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
          if (hub_storage_update_entry(state, client->id, "o", mask, pass, op,
                                       ts)) {
            updates++;
            int w = snprintf(
                sync_buffer + sync_offset, sizeof(sync_buffer) - sync_offset,
                "b|%s|o|%s|%s|%s|%ld\n", client->id, mask, pass, op, ts);
            if (w > 0)
              sync_offset += w;
          }
        } else {
          hub_log("[HUB] Rejected oper line without password from %s\n",
                  client->id);
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
      if (hub_storage_update_entry(state, client->id, "a", pass, "", "", ts)) {
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
      if (hub_storage_update_entry(state, client->id, "p", pass, "", "", ts)) {
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
        if (hub_storage_update_entry(state, client->id, "h", hostmask, "", "",
                                     ts)) {
          updates++;
          // Broadcast in format: b|hostmask|uuid|timestamp
          int w = snprintf(sync_buffer + sync_offset,
                           sizeof(sync_buffer) - sync_offset, "b|%s|%s|%ld\n",
                           hostmask, client->id, ts);
          if (w > 0)
            sync_offset += w;
        }
      }
    } else if (type == 'n') {
      // Nick: n|nickname|timestamp
      char nick[MAX_NICK];
      long ts;
      if (sscanf(data, "%32[^|]|%ld", nick, &ts) == 2) {
        if (hub_storage_update_entry(state, client->id, "n", nick, "", "",
                                     ts)) {
          updates++;
          // Broadcast as nickname update (NOT b| prefix)
          int w = snprintf(sync_buffer + sync_offset,
                           sizeof(sync_buffer) - sync_offset, "n|%s|%s|%ld\n",
                           nick, client->id, ts);
          if (w > 0)
            sync_offset += w;
        }
      }
    }

    line = strtok_r(NULL, "\n", &saveptr);
  }

  if (updates > 0) {
    hub_log("[HUB] Applied %d updates from %s\n", updates, client->id);
    hub_config_write(state);

    // Broadcast to peer hubs
    if (sync_offset > 0) {
      hub_broadcast_sync_to_peers(state, sync_buffer, client->fd);
    }

    // Broadcast to other bots
    if (sync_buffer[0] != '\0') {
      unsigned char plain[MAX_BUFFER];
      unsigned char buffer[MAX_BUFFER];
      unsigned char tag[GCM_TAG_LEN];
      int pay_len = strlen(sync_buffer);

      plain[0] = CMD_CONFIG_DATA;
      int net_pay_len = htonl(pay_len);
      memcpy(&plain[1], &net_pay_len, 4);
      memcpy(&plain[5], sync_buffer, pay_len);
      int total_plain = 1 + 4 + pay_len;

      int sent_count = 0;
      for (int i = 0; i < state->client_count; i++) {
        hub_client_t *c = state->clients[i];
        // Send to all authenticated bots (except self is optional, but skipping
        // self saves bandwidth)
        if (c->type == CLIENT_BOT && c->authenticated && c->fd != client->fd) {
          int cipher_len = aes_gcm_encrypt(plain, total_plain, c->session_key,
                                           buffer + 4, tag);
          if (cipher_len > 0) {
            memcpy(buffer + 4 + cipher_len, tag, GCM_TAG_LEN);
            uint32_t net_len = htonl(cipher_len + GCM_TAG_LEN);
            memcpy(buffer, &net_len, 4);
            if (write(c->fd, buffer, 4 + cipher_len + GCM_TAG_LEN) > 0) {
              sent_count++;
            }
          }
        }
      }
      if (sent_count > 0) {
        hub_log("[HUB] Broadcasted updates to %d bots\n", sent_count);
      }
    }
  }
}

void hub_generate_sync_packet(hub_state_t *state, char *buffer, int max_len) {
  int offset = 0;
  int written;
  buffer[0] = 0;

  for (int i = 0; i < state->bot_count; i++) {
    bot_config_t *b = &state->bots[i];
    if (max_len - offset <= 1)
      break;

    written = snprintf(buffer + offset, max_len - offset, "b|%s|t||%ld\n",
                       b->uuid, (long)b->last_sync_time);
    if (written < 0 || written >= (max_len - offset))
      break;
    offset += written;

    for (int j = 0; j < b->entry_count; j++) {
      if (max_len - offset <= 1)
        break;

      written = snprintf(buffer + offset, max_len - offset, "b|%s|%s|%s|%ld\n",
                         b->uuid, b->entries[j].key, b->entries[j].value,
                         (long)b->entries[j].timestamp);
      if (written < 0 || written >= (max_len - offset))
        break;
      offset += written;
    }
  }
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

          if (hub_storage_update_entry(state, uuid, key, val, "", "", ts)) {
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

        // Disconnect bot if currently connected
        for (int i = 0; i < state->client_count; i++) {
          if (state->clients[i]->type == CLIENT_BOT &&
              strcmp(state->clients[i]->id, payload) == 0) {
            hub_log("[ADMIN] Disconnecting bot %s for rekey\n", payload);
            hub_disconnect_client(state, state->clients[i]);
            break;
          }
        }

        // Build response: SUCCESS|<nick>|<base64_priv_key>
        char response[8192];
        snprintf(response, sizeof(response), "SUCCESS|%s|%s", nick,
                 new_priv_b64);

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
          snprintf(connected_to, sizeof(connected_to), "LOCAL (127.0.0.1:%d)",
                   state->port);
          last_seen = state->clients[c]->last_seen;
          break;
        }
      }

      // TODO: Check if connected to remote peers (requires mesh state tracking)

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
      broadcast_new_key(state, pub);

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
      char ip[256];
      int port;
      if (sscanf(payload, "%255[^:]:%d", ip, &port) == 2) {
        if (state->peer_count < MAX_PEERS) {
          size_t ip_len = strlen(ip);
          size_t max_len = sizeof(state->peers[state->peer_count].ip) - 1;
          size_t copy_len = (ip_len < max_len) ? ip_len : max_len;

          memcpy(state->peers[state->peer_count].ip, ip, copy_len);
          state->peers[state->peer_count].ip[copy_len] = '\0';
          state->peers[state->peer_count].port = port;
          state->peers[state->peer_count].connected = false;
          state->peers[state->peer_count].fd = -1;
          state->peer_count++;
          hub_config_write(state);
          return send_response(state, client, "SUCCESS: Peer Added.");
        }
        return send_response(state, client, "ERROR: Max peers reached.");
      }
    }
    return send_response(state, client, "ERROR: Invalid format. Use IP:PORT");

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
      bool is_me;
    } matrix_peer_t;
    matrix_peer_t all_peers[64];
    int count = 0;

    snprintf(all_peers[count].ip, 256, "127.0.0.1");
    all_peers[count].port = state->port;
    all_peers[count].is_me = true;
    count++;

    for (int i = 0; i < state->peer_count; i++) {
      snprintf(all_peers[count].ip, 256, "%s", state->peers[i].ip);
      all_peers[count].port = state->peers[i].port;
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
          char owner[256];
          int o_port;
          if (sscanf(block, "%255[^:]:%d|", owner, &o_port) == 2) {
            bool exists = false;
            for (int k = 0; k < count; k++)
              if (all_peers[k].port == o_port &&
                  strcmp(all_peers[k].ip, owner) == 0)
                exists = true;
            if (!exists && count < 64) {
              snprintf(all_peers[count].ip, 256, "%s", owner);
              all_peers[count].port = o_port;
              all_peers[count].is_me = false;
              count++;
            }
            char *list = strchr(block, '|');
            if (list) {
              char *t_save, *tok = strtok_r(list + 1, ",", &t_save);
              while (tok) {
                char t_ip[256];
                int t_port;
                if (sscanf(tok, "%255[^:]:%d", t_ip, &t_port) >= 2) {
                  bool t_exists = false;
                  for (int k = 0; k < count; k++)
                    if (all_peers[k].port == t_port &&
                        strcmp(all_peers[k].ip, t_ip) == 0)
                      t_exists = true;
                  if (!t_exists && count < 64) {
                    snprintf(all_peers[count].ip, 256, "%s", t_ip);
                    all_peers[count].port = t_port;
                    all_peers[count].is_me = false;
                    count++;
                  }
                }
                tok = strtok_r(NULL, ",", &t_save);
              }
            }
          }
          block = strtok_r(NULL, ";", &saveptr);
        }
      }
    }

    int peer_col_width = 16;
    for (int i = 0; i < count; i++) {
      char tmp[512];
      snprintf(tmp, 512, "%.255s:%d", all_peers[i].ip, all_peers[i].port);
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

    int line_len = peer_col_width + 3 + (count * 5) + 15 + 10;

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
    written = snprintf(response + offset, sizeof(response) - offset, " %-*s |",
                       peer_col_width, "Peer");
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
                       " Mesh State   | Bots |\n");
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
      snprintf(peer_str, 512, "%.255s:%d", all_peers[row].ip,
               all_peers[row].port);

      // CRITICAL FIX: Add overflow check
      written = snprintf(response + offset, sizeof(response) - offset,
                         " %d. %-*s |", row + 1, peer_col_width - 3, peer_str);
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
              if (state->peers[p].port == all_peers[col].port &&
                  strcmp(state->peers[p].ip, all_peers[col].ip) == 0) {
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
                  char owner[256];
                  int o_port;
                  if (sscanf(block, "%255[^:]:%d|", owner, &o_port) == 2) {
                    if (o_port == all_peers[row].port &&
                        strcmp(owner, all_peers[row].ip) == 0) {
                      found_block = true;
                      char *list = strchr(block, '|');
                      if (list) {
                        char *lsave, *tok = strtok_r(list + 1, ",", &lsave);
                        while (tok) {
                          char t_ip[256];
                          int t_port;
                          int stat;
                          if (sscanf(tok, "%255[^:]:%d:%d", t_ip, &t_port,
                                     &stat) >= 3) {
                            if (t_port == all_peers[col].port &&
                                strcmp(t_ip, all_peers[col].ip) == 0) {
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
                if (state->peers[p].port == all_peers[row].port &&
                    strcmp(state->peers[p].ip, all_peers[row].ip) == 0) {
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
      if (row_total > 0) {
        if (row_connected > 0) {
          // CRITICAL FIX: Add overflow check
          written = snprintf(response + offset, sizeof(response) - offset,
                             " %d/%d Connected |", row_connected, row_total);
        } else {
          // CRITICAL FIX: Add overflow check
          written = snprintf(response + offset, sizeof(response) - offset,
                             " \033[31mOffline\033[0m       |");
          is_offline = true;
          issues++;
        }
      } else {
        if (all_peers[row].is_me) {
          // CRITICAL FIX: Add overflow check
          written = snprintf(response + offset, sizeof(response) - offset,
                             " ---          |");
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
    if (issues == 0 && state->peer_count > 0) {
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

  default:
    return send_response(state, client, "ERROR: Unknown command.");
  }

  return true;
}

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

  // Send CMD_CONFIG_DATA packet
  unsigned char buffer[MAX_BUFFER];
  unsigned char plain[MAX_BUFFER];
  unsigned char tag[GCM_TAG_LEN];

  plain[0] = CMD_CONFIG_DATA;
  uint32_t payload_len = len;
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
            if (strcmp(payload + 6, state->admin_password) == 0) {
              client->type = CLIENT_ADMIN;
              client->authenticated = true;
              strncpy(client->id, "ADMIN", sizeof(client->id) - 1);
              client->id[sizeof(client->id) - 1] = 0;
              hub_log("[HUB] Admin Login: %s\n", client->ip);
            } else {
              hub_log("[HUB] Failed admin auth from %s\n", client->ip);
              secure_wipe(dec, sizeof(dec));
              hub_disconnect_client(state, client);
              return false;
            }
          }
          // HUB Peer Authentication
          else if (strncmp(payload, "HUB", 3) == 0) {
            char pass[128];
            int claimed_port = 0;
            int args = sscanf(payload + 4, "%127s %d", pass, &claimed_port);

            if (args >= 1 && strcmp(pass, state->admin_password) == 0) {
              client->type = CLIENT_HUB;
              client->authenticated = true;
              strncpy(client->id, "HUB-PEER", sizeof(client->id) - 1);
              client->id[sizeof(client->id) - 1] = 0;

              bool is_authorized_peer = false;
              for (int p = 0; p < state->peer_count; p++) {
                bool ip_match = (strcmp(state->peers[p].ip, client->ip) == 0 ||
                                 strcmp("127.0.0.1", client->ip) == 0);

                if (ip_match) {
                  if (claimed_port > 0) {
                    if (state->peers[p].port == claimed_port) {
                      state->peers[p].connected = true;
                      state->peers[p].fd = client->fd;
                      is_authorized_peer = true;
                    }
                  } else {
                    state->peers[p].connected = true;
                    state->peers[p].fd = client->fd;
                    is_authorized_peer = true;
                  }
                }
              }

              if (!is_authorized_peer) {
                hub_log("[HUB] Unauthorized peer from %s\n", client->ip);
                secure_wipe(dec, sizeof(dec));
                hub_disconnect_client(state, client);
                return false;
              }

              // Send initial sync (existing code)...
              hub_log("[HUB] Peer connected: %s\n", client->ip);
            } else {
              hub_log("[HUB] Failed peer auth from %s\n", client->ip);
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
