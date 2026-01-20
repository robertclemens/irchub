#include "hub.h"
#include <arpa/inet.h>
#include <openssl/bio.h>
#include <errno.h>

#ifndef CMD_ADMIN_CREATE_BOT
#define CMD_ADMIN_CREATE_BOT 50
#endif

void hub_log(const char *format, ...);

// --- Forward Declarations ---
static bool send_response(hub_state_t *state, hub_client_t *client, const char *msg);
static bool send_pong(hub_state_t *state, hub_client_t *c);
void hub_broadcast_mesh_state(hub_state_t *state);
static void add_pending_bot(hub_state_t *state, const char *uuid, const char *ip);
static void remove_pending_bot(hub_state_t *state, const char *uuid);
static void broadcast_new_key(hub_state_t *state, const char *new_pub_key);
static void process_mesh_state(hub_state_t *state, hub_client_t *c, char *payload);
static void process_peer_sync(hub_state_t *state, char *payload, int origin_fd);
static bool handle_admin_command(hub_state_t *state, hub_client_t *client, int cmd, char *payload);
static void process_bot_command(hub_state_t *state, hub_client_t *client, int cmd, char *payload);

// Crypto/Config Forward Decls
bool hub_crypto_generate_bot_creds(char **out_uuid, char **out_priv_b64, char **out_pub_b64);

// --- Helper Functions ---

static void add_pending_bot(hub_state_t *state, const char *uuid, const char *ip) {
    for (int i = 0; i < state->pending_count; i++) {
        if (strcmp(state->pending[i].uuid, uuid) == 0) {
            state->pending[i].last_attempt = time(NULL);
            size_t ip_len = strlen(ip);
            size_t copy_len = (ip_len < sizeof(state->pending[i].ip) - 1) ? 
                             ip_len : sizeof(state->pending[i].ip) - 1;
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
    size_t copy_uuid_len = (uuid_len < sizeof(p->uuid) - 1) ? 
                          uuid_len : sizeof(p->uuid) - 1;
    memcpy(p->uuid, uuid, copy_uuid_len);
    p->uuid[copy_uuid_len] = '\0';
    
    size_t ip_len = strlen(ip);
    size_t copy_ip_len = (ip_len < sizeof(p->ip) - 1) ? 
                        ip_len : sizeof(p->ip) - 1;
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
                state->pending[j] = state->pending[j+1];
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
    if (payload_len > (MAX_BUFFER - 10)) return;

    memcpy(&plain[1], &payload_len, 4);
    memcpy(&plain[5], new_pub_key, payload_len);
    int total_plain = 1 + 4 + payload_len;

    int sent_count = 0;
    for (int i = 0; i < state->client_count; i++) {
        hub_client_t *c = state->clients[i];
        if (c->authenticated && c->type == CLIENT_BOT) {
            int enc_len = aes_gcm_encrypt(plain, total_plain, c->session_key, 
                                         buffer + 4, tag);
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
    for(int i = 0; i < state->bot_count; i++) {
        if(strcmp(state->bots[i].uuid, uuid) == 0) return;
    }
    
    if (state->bot_count < MAX_BOTS) {
        int idx = state->bot_count++;
        bot_config_t *b = &state->bots[idx];
        memset(b, 0, sizeof(bot_config_t));
        strncpy(b->uuid, uuid, sizeof(b->uuid) - 1);
        b->uuid[sizeof(b->uuid) - 1] = 0;
        b->last_sync_time = 0;
        
        time_t now = time(NULL);
        hub_storage_update_entry(state, uuid, "n", nick, now);
        hub_storage_update_entry(state, uuid, "pub", pub_key, now);
        hub_storage_update_entry(state, uuid, "seen", "0", now);
    }
}

// FIXED: Added bounds checking
void hub_broadcast_mesh_state(hub_state_t *state) {
    char payload[MAX_BUFFER];
    memset(payload, 0, sizeof(payload));
    int offset = 0;
    int written;

    written = snprintf(payload + offset, MAX_BUFFER - offset, "127.0.0.1:%d|", state->port);
    if (written < 0 || written >= MAX_BUFFER - offset) return;
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
        
        written = snprintf(payload + offset, MAX_BUFFER - offset, 
                          "%s:%d:%d,", state->peers[i].ip, 
                          state->peers[i].port, is_up);
        if (written < 0 || written >= MAX_BUFFER - offset) break;
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
            if (!body) continue;
            
            char work_buf[MAX_BUFFER];
            snprintf(work_buf, sizeof(work_buf), "%.*s", MAX_BUFFER-1, body + 1);
            
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
    for(int i = 0; i < state->peer_count; i++) {
        if(state->peers[i].connected) connected_peers++;
    }

    int active_bots = 0;
    for(int i = 0; i < state->client_count; i++) {
        if(state->clients[i]->type == CLIENT_BOT && 
           state->clients[i]->authenticated) {
            active_bots++;
        }
    }

    unsigned char buffer[MAX_BUFFER];
    unsigned char plain[MAX_BUFFER];
    unsigned char tag[GCM_TAG_LEN];

    plain[0] = CMD_MESH_STATE;
    char final_packet[MAX_BUFFER];
    
    written = snprintf(final_packet, sizeof(final_packet), 
                      "%d:%d:%d|%s", connected_peers, state->peer_count, 
                      active_bots, payload);
    if (written < 0 || written >= (int)sizeof(final_packet)) return;

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
            int enc_len = aes_gcm_encrypt(plain, total_plain, c->session_key, 
                                         buffer + 4, tag);
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

static void process_mesh_state(hub_state_t *state, hub_client_t *c, char *payload) {
    int remote_conn = 0, remote_total = 0, remote_bots = 0;
    
    if (sscanf(payload, "%d:%d:%d", &remote_conn, &remote_total, &remote_bots) >= 2) {
        for (int i = 0; i < state->peer_count; i++) {
            if (state->peers[i].connected && state->peers[i].fd == c->fd) {
                state->peers[i].last_mesh_report = time(NULL);
                strncpy(state->peers[i].last_gossip, payload, 
                       sizeof(state->peers[i].last_gossip) - 1);
                state->peers[i].last_gossip[sizeof(state->peers[i].last_gossip) - 1] = 0;
                return;
            }
        }
    }
}

// Continuation of hub_logic.c

void hub_broadcast_sync_to_peers(hub_state_t *state, const char *payload, int exclude_fd) {
    unsigned char buffer[MAX_BUFFER];
    unsigned char plain[MAX_BUFFER];
    unsigned char tag[GCM_TAG_LEN];

    plain[0] = CMD_PEER_SYNC;
    int payload_len = strlen(payload);
    if (payload_len > (MAX_BUFFER - 10)) return;

    memcpy(&plain[1], &payload_len, 4);
    memcpy(&plain[5], payload, payload_len);
    int total_plain = 1 + 4 + payload_len;

    for (int i = 0; i < state->client_count; i++) {
        hub_client_t *c = state->clients[i];
        if (c->type == CLIENT_HUB && c->authenticated && c->fd != exclude_fd) {
            int cipher_len = aes_gcm_encrypt(plain, total_plain, c->session_key, 
                                            buffer + 4, tag);
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

void hub_generate_sync_packet(hub_state_t *state, char *buffer, int max_len) {
    int offset = 0;
    int written;
    buffer[0] = 0;
    
    for (int i = 0; i < state->bot_count; i++) {
        bot_config_t *b = &state->bots[i];
        if (max_len - offset <= 1) break;
        
        written = snprintf(buffer + offset, max_len - offset, 
                          "b|%s|t||%ld\n", b->uuid, (long)b->last_sync_time);
        if (written < 0 || written >= (max_len - offset)) break;
        offset += written;
        
        for (int j = 0; j < b->entry_count; j++) {
            if (max_len - offset <= 1) break;
            
            written = snprintf(buffer + offset, max_len - offset, 
                             "b|%s|%s|%s|%ld\n", b->uuid, 
                             b->entries[j].key, b->entries[j].value, 
                             (long)b->entries[j].timestamp);
            if (written < 0 || written >= (max_len - offset)) break;
            offset += written;
        }
    }
}

static void process_peer_sync(hub_state_t *state, char *payload, int origin_fd) {
    char *saveptr;
    char work_buf[MAX_BUFFER];
    snprintf(work_buf, sizeof(work_buf), "%.*s", MAX_BUFFER-1, payload);
    
    char *line = strtok_r(work_buf, "\n", &saveptr);
    int updates = 0;
    char forward_buf[MAX_BUFFER];
    int fwd_offset = 0;
    forward_buf[0] = 0;

    while(line) {
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

                    if (hub_storage_update_entry(state, uuid, key, val, ts)) {
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

static bool send_response(hub_state_t *state, hub_client_t *client, const char *msg) {
    unsigned char buffer[MAX_BUFFER];
    unsigned char tag[GCM_TAG_LEN];
    int len = strlen(msg);
    
    int enc_len = aes_gcm_encrypt((unsigned char*)msg, len, client->session_key, 
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
    
    switch(cmd) {
        case CMD_ADMIN_LIST_FULL:
            hub_storage_get_full_list(state, response, sizeof(response));
            return send_response(state, client, response);
            
        case CMD_ADMIN_LIST_SUMMARY:
            hub_storage_get_summary_list(state, response, sizeof(response));
            return send_response(state, client, response);
            
        case CMD_ADMIN_GET_PENDING:
            {
                offset = 0;
                if (state->pending_count == 0) {
                    strcpy(response, "No pending bots.");
                } else {
                    written = snprintf(response, sizeof(response), 
                                     "--- Pending Authorization ---\n");
                    if (written >= (int)sizeof(response)) return send_response(state, client, "Buffer overflow");
                    offset += written;
                    
                    for (int i = 0; i < state->pending_count; i++) {
                        struct tm *t = localtime(&state->pending[i].last_attempt);
                        char tbuf[64];
                        strftime(tbuf, sizeof(tbuf), "%H:%M:%S", t);
                        
                        written = snprintf(response + offset, sizeof(response) - offset, 
                                         "[%d] %s | IP: %s\n", i+1, 
                                         state->pending[i].uuid, state->pending[i].ip);
                        if (written >= (int)(sizeof(response) - offset)) break;
                        offset += written;
                    }
                }
                return send_response(state, client, response);
            }
            
        case CMD_ADMIN_APPROVE:
            if (payload && strlen(payload) > 0) {
                char target_uuid[64] = {0};
                
                if (strlen(payload) < 4) {
                    int idx = atoi(payload);
                    if (idx > 0 && idx <= state->pending_count) {
                        strncpy(target_uuid, state->pending[idx-1].uuid, 
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
                    hub_storage_update_entry(state, target_uuid, "t", "", now);
                    hub_config_write(state);
                    remove_pending_bot(state, target_uuid);
                    
                    char sync[256];
                    snprintf(sync, sizeof(sync), "%s|t||%ld\n", target_uuid, now);
                    hub_broadcast_sync_to_peers(state, sync, -1);
                    
                    return send_response(state, client, "SUCCESS: Bot Authorized & Synced.");
                }
            }
            return send_response(state, client, "ERROR: Missing Index or UUID.");
            
        case CMD_ADMIN_ADD:
            if (payload && strlen(payload) > 0) {
                time_t now = time(NULL);
                hub_storage_update_entry(state, payload, "t", "", now);
                hub_config_write(state);
                
                char sync[256];
                snprintf(sync, sizeof(sync), "%s|t||%ld\n", payload, now);
                hub_broadcast_sync_to_peers(state, sync, -1);
                
                return send_response(state, client, "SUCCESS: UUID Authorized & Synced.");
            }
            return send_response(state, client, "ERROR: Invalid UUID.");
            
        case CMD_ADMIN_DEL:
            if (payload && hub_storage_delete(state, payload)) {
                time_t now = time(NULL);
                char sync[256];
                snprintf(sync, sizeof(sync), "%s|d|1|%ld\n", payload, now);
                hub_broadcast_sync_to_peers(state, sync, -1);
                return send_response(state, client, "SUCCESS: Deleted & Synced.");
            }
            return send_response(state, client, "ERROR: Not found.");
            
        case CMD_ADMIN_SYNC_MESH:
            {
                char full_sync[MAX_BUFFER];
                hub_generate_sync_packet(state, full_sync, MAX_BUFFER - 100);
                hub_broadcast_sync_to_peers(state, full_sync, -1);
                return send_response(state, client, "SUCCESS: Full Sync broadcasted.");
            }
            
        case CMD_ADMIN_CREATE_BOT:
            {
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
                    
                    int w = snprintf(response, sizeof(response), 
                                   "SUCCESS|%s|%s", uuid, priv_key);
                    
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
                    if (pub_key) free(pub_key);
                    if (uuid) free(uuid);
                } else {
                    send_response(state, client, "ERROR|Crypto generation failed.");
                }
            }
            return true;
            
        case CMD_ADMIN_REGEN_KEYS:
            {
                char *priv = NULL, *pub = NULL;
                if (hub_crypto_generate_keypair(&priv, &pub)) {
                    broadcast_new_key(state, pub);
                    
                    if (state->private_key_pem) {
                        secure_wipe(state->private_key_pem, strlen(state->private_key_pem));
                        free(state->private_key_pem);
                    }
                    if (state->public_key_pem) free(state->public_key_pem);
                    if (state->priv_key) EVP_PKEY_free(state->priv_key);
                    
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
            
        case CMD_ADMIN_GET_PUBKEY:
            {
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
                if (pub) return send_response(state, client, pub);
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
                    if (state->priv_key) EVP_PKEY_free(state->priv_key);
                    
                    state->private_key_pem = strdup(payload);
                    state->priv_key = new_pkey;
                    hub_config_write(state);
                    return send_response(state, client, "SUCCESS: Private Key Imported & Saved.");
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
                if (state->public_key_pem) free(state->public_key_pem);
                state->public_key_pem = strdup(payload);
                hub_config_write(state);
                return send_response(state, client, "SUCCESS: Public Key Imported & Saved.");
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
                    return send_response(state, client, "ERROR: Cannot remove local hub (Index 1).");
                }
                if (idx > 1 && idx <= state->peer_count + 1) {
                    int target = idx - 2;
                    
                    if (state->peers[target].fd != -1) {
                        int target_fd = state->peers[target].fd;
                        for(int c = 0; c < state->client_count; c++) {
                            if (state->clients[c]->fd == target_fd) {
                                hub_disconnect_client(state, state->clients[c]);
                                break;
                            }
                        }
                    }
                    
                    char confirm_msg[256];
                    snprintf(confirm_msg, sizeof(confirm_msg), 
                            "SUCCESS: Deleted Peer %s:%d.", 
                            state->peers[target].ip, state->peers[target].port);
                    
                    for (int j = target; j < state->peer_count - 1; j++) {
                        state->peers[j] = state->peers[j+1];
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
                                     "[%d] %s:%d\n", i + 2, 
                                     state->peers[i].ip, state->peers[i].port);
                    if (written >= (int)(sizeof(response) - offset)) break;
                    offset += written;
                }
                
                written = snprintf(response + offset, sizeof(response) - offset,
                                 "Enter Index to Remove: ");
                if (written >= 0 && written < (int)(sizeof(response) - offset)) {
                    offset += written;
                }
                return send_response(state, client, response);
            }
            
        case CMD_ADMIN_LIST_PEERS:
            {
                hub_broadcast_mesh_state(state); 
                int offset = 0;
                typedef struct { char ip[256]; int port; bool is_me; } matrix_peer_t;
                matrix_peer_t all_peers[64];
                int count = 0;

                snprintf(all_peers[count].ip, 256, "127.0.0.1"); all_peers[count].port = state->port; all_peers[count].is_me = true; count++;
                for(int i=0; i<state->peer_count; i++) {
                    snprintf(all_peers[count].ip, 256, "%s", state->peers[i].ip); all_peers[count].port = state->peers[i].port; all_peers[count].is_me = false; count++;
                }
                for(int i=0; i<state->peer_count; i++) {
                    if(state->peers[i].connected && strlen(state->peers[i].last_gossip) > 0) {
                        char *body = strchr(state->peers[i].last_gossip, '|');
                        if (!body) continue;
                        char work_buf[MAX_BUFFER]; snprintf(work_buf, sizeof(work_buf), "%.*s", MAX_BUFFER-1, body + 1);
                        char *saveptr, *block = strtok_r(work_buf, ";", &saveptr);
                        while(block) {
                            char owner[256]; int o_port;
                            if (sscanf(block, "%255[^:]:%d|", owner, &o_port) == 2) {
                                bool exists = false;
                                for(int k=0; k<count; k++) if(all_peers[k].port == o_port && strcmp(all_peers[k].ip, owner) == 0) exists=true;
                                if(!exists && count < 64) { snprintf(all_peers[count].ip, 256, "%s", owner); all_peers[count].port = o_port; all_peers[count].is_me = false; count++; }
                                char *list = strchr(block, '|');
                                if(list) {
                                    char *t_save, *tok = strtok_r(list+1, ",", &t_save);
                                    while(tok) {
                                        char t_ip[256]; int t_port;
                                        if (sscanf(tok, "%255[^:]:%d", t_ip, &t_port) >= 2) {
                                            bool t_exists = false;
                                            for(int k=0; k<count; k++) if(all_peers[k].port == t_port && strcmp(all_peers[k].ip, t_ip) == 0) t_exists=true;
                                            if(!t_exists && count < 64) { snprintf(all_peers[count].ip, 256, "%s", t_ip); all_peers[count].port = t_port; all_peers[count].is_me = false; count++; }
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
                for(int i=0; i<count; i++) {
                    char tmp[512]; snprintf(tmp, 512, "%.255s:%d", all_peers[i].ip, all_peers[i].port);
                    int len = strlen(tmp); if(len > peer_col_width) peer_col_width = len;
                }
                peer_col_width += 3;
                
                written = snprintf(response + offset, sizeof(response) - offset, 
                                 "\n [M] MESH CONNECTION MATRIX        You are connected to peer 1\n");
                if (written < 0 || written >= (int)(sizeof(response) - offset)) {
                    return send_response(state, client, "ERROR: Response buffer overflow");
                }
                offset += written;
                
                int line_len = peer_col_width + 3 + (count * 5) + 15 + 10; 
                for(int k=0; k<line_len && offset < (int)sizeof(response); k++) { 
                    response[offset++] = '-'; 
                }
                if (offset >= (int)sizeof(response)) {
                    return send_response(state, client, "ERROR: Response buffer overflow");
                }
                response[offset++] = '\n';
                
                written = snprintf(response + offset, sizeof(response) - offset, 
                                 " %-*s |", peer_col_width, "Peer");
                if (written < 0 || written >= (int)(sizeof(response) - offset)) {
                    return send_response(state, client, "ERROR: Response buffer overflow");
                }
                offset += written;
                
                for(int i=0; i<count; i++) {
                    written = snprintf(response + offset, sizeof(response) - offset, 
                                     " %-2d |", i+1);
                    if (written < 0 || written >= (int)(sizeof(response) - offset)) break;
                    offset += written;
                }
                
                written = snprintf(response + offset, sizeof(response) - offset, 
                                 " Mesh State   | Bots |\n");
                if (written < 0 || written >= (int)(sizeof(response) - offset)) {
                    return send_response(state, client, "ERROR: Response buffer overflow");
                }
                offset += written;
                
                for(int k=0; k<line_len && offset < (int)sizeof(response); k++) { 
                    response[offset++] = '-'; 
                }
                if (offset >= (int)sizeof(response)) {
                    return send_response(state, client, "ERROR: Response buffer overflow");
                }
                response[offset++] = '\n';

                int issues = 0; char issue_log[MAX_BUFFER]; memset(issue_log, 0, sizeof(issue_log)); int issue_off = 0;
                char reported_mismatches[64][MAX_BUFFER]; int rm_count = 0;

                for (int row = 0; row < count; row++) {
                    char peer_str[512]; 
                    snprintf(peer_str, 512, "%.255s:%d", all_peers[row].ip, all_peers[row].port);
                    
                    written = snprintf(response + offset, sizeof(response) - offset, 
                                     " %d. %-*s |", row+1, peer_col_width - 3, peer_str);
                    if (written < 0 || written >= (int)(sizeof(response) - offset)) {
                        return send_response(state, client, "ERROR: Matrix too large for buffer");
                    }
                    offset += written;
                    int row_connected = 0, row_total = 0; 
                    for (int col = 0; col < count; col++) {
                        char cell[32] = "??"; 
                        if (row == col) strcpy(cell, "--");
                        else {
                            bool found_block = false, found_link = false, link_up = false;
                            if (all_peers[row].is_me) {
                                found_block = true;
                                for(int p=0; p<state->peer_count; p++) {
                                    if(state->peers[p].port == all_peers[col].port && strcmp(state->peers[p].ip, all_peers[col].ip)==0) {
                                        found_link = true; 
                                        for(int c=0; c<state->client_count; c++) {
                                            if(state->clients[c]->type == CLIENT_HUB && state->clients[c]->authenticated && state->clients[c]->fd == state->peers[p].fd) link_up = true;
                                        }
                                    }
                                }
                            } else {
                                for(int p=0; p<state->peer_count; p++) {
                                    if (state->peers[p].connected && strlen(state->peers[p].last_gossip) > 0) {
                                        char *body = strchr(state->peers[p].last_gossip, '|');
                                        if (!body) continue;
                                        char work_buf[MAX_BUFFER]; snprintf(work_buf, sizeof(work_buf), "%.*s", MAX_BUFFER-1, body + 1);
                                        char *bsave, *block = strtok_r(work_buf, ";", &bsave);
                                        while(block) {
                                            char owner[256]; int o_port;
                                            if(sscanf(block, "%255[^:]:%d|", owner, &o_port) == 2) {
                                                if (o_port == all_peers[row].port && strcmp(owner, all_peers[row].ip) == 0) {
                                                    found_block = true; char *list = strchr(block, '|');
                                                    if(list) {
                                                        char *lsave, *tok = strtok_r(list+1, ",", &lsave);
                                                        while(tok) {
                                                            char t_ip[256]; int t_port; int stat;
                                                            if(sscanf(tok, "%255[^:]:%d:%d", t_ip, &t_port, &stat) >= 3) {
                                                                if(t_port == all_peers[col].port && strcmp(t_ip, all_peers[col].ip) == 0) {
                                                                    found_link = true; if(stat) link_up = true;
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
                                    for(int p=0; p<state->peer_count; p++) {
                                        if (state->peers[p].port == all_peers[row].port && strcmp(state->peers[p].ip, all_peers[row].ip) == 0) {
                                            for(int c=0; c<state->client_count; c++) {
                                                if(state->clients[c]->type == CLIENT_HUB && state->clients[c]->authenticated && state->clients[c]->fd == state->peers[p].fd) actually_connected = true;
                                            }
                                        }
                                    }
                                    if (!actually_connected) link_up = false;
                                }
                            }
                            if (found_block) {
                                if (found_link) {
                                    strcpy(cell, link_up ? "\033[32mUP\033[0m" : "\033[31mDN\033[0m"); row_total++; if(link_up) row_connected++;
                                } else strcpy(cell, "??"); 
                            } else strcpy(cell, "??"); 
                        }
                        written = snprintf(response + offset, sizeof(response) - offset, " %s |", cell);
                        if (written < 0 || written >= (int)(sizeof(response) - offset)) {
                            return send_response(state, client, "ERROR: Matrix too large for buffer");
                        }
                        offset += written;
                    }
                    bool is_offline = false;
                    if(row_total > 0) {
                        if(row_connected > 0) {
                            written = snprintf(response + offset, sizeof(response) - offset, 
                                             " %d/%d Connected |", row_connected, row_total);
                        } else { 
                            written = snprintf(response + offset, sizeof(response) - offset, 
                                             " \033[31mOffline\033[0m       |"); 
                            is_offline = true; 
                            issues++; 
                        }
                    } else {
                        if (all_peers[row].is_me) {
                            written = snprintf(response + offset, sizeof(response) - offset, 
                                             " ---          |");
                        } else { 
                            written = snprintf(response + offset, sizeof(response) - offset, 
                                             " \033[31mOffline\033[0m       |"); 
                            is_offline = true; 
                            issues++; 
                        }
                    }
                    if (written < 0 || written >= (int)(sizeof(response) - offset)) {
                        return send_response(state, client, "ERROR: Matrix too large for buffer");
                    }
                    offset += written;
                    if (is_offline) {
                        written = snprintf(response + offset, sizeof(response) - offset, " ??   |\n");
                    } else {
                        int bot_cnt = 0;
                        if (all_peers[row].is_me) {
                            for(int k=0; k<state->client_count; k++) {
                                if(state->clients[k]->type == CLIENT_BOT && 
                                   state->clients[k]->authenticated) bot_cnt++;
                            }
                        } else {
                            for(int p=0; p<state->peer_count; p++) {
                                if(state->peers[p].connected && 
                                   state->peers[p].port == all_peers[row].port && 
                                   strcmp(state->peers[p].ip, all_peers[row].ip) == 0) {
                                    int rc, rt, rb; 
                                    if(sscanf(state->peers[p].last_gossip, "%d:%d:%d|", &rc, &rt, &rb) == 3) {
                                        bot_cnt = rb;
                                    }
                                    break;
                                }
                            }
                        }
                        written = snprintf(response + offset, sizeof(response) - offset, 
                                         " %-4d |\n", bot_cnt);
                    }
                    if (written < 0 || written >= (int)(sizeof(response) - offset)) {
                        return send_response(state, client, "ERROR: Matrix too large for buffer");
                    }
                    offset += written;
                    if(all_peers[row].is_me) {
                         for(int p=0; p<state->peer_count; p++) {
                             bool active = false;
                             for(int c=0; c<state->client_count; c++) {
                                 if(state->clients[c]->type == CLIENT_HUB && state->clients[c]->authenticated && state->clients[c]->fd == state->peers[p].fd) active = true;
                             }
                             if(!active) { issues++; issue_off += snprintf(issue_log + issue_off, sizeof(issue_log)-issue_off, " [!] Peer %s:%d is DOWN.\n", state->peers[p].ip, state->peers[p].port); }
                         }
                    }
                }
                for (int i=0; i<count; i++) {
                    if (!all_peers[i].is_me) { 
                        bool in_config = false;
                        for(int p=0; p<state->peer_count; p++) if(state->peers[p].port == all_peers[i].port && strcmp(state->peers[p].ip, all_peers[i].ip)==0) in_config=true;
                        if (!in_config) {
                            for(int p=0; p<state->peer_count; p++) {
                                if (state->peers[p].connected && strlen(state->peers[p].last_gossip) > 0) {
                                    char *body = strchr(state->peers[p].last_gossip, '|'); if (!body) continue;
                                    char work_buf[MAX_BUFFER]; snprintf(work_buf, sizeof(work_buf), "%.*s", MAX_BUFFER-1, body + 1);
                                    char *bsave, *block = strtok_r(work_buf, ";", &bsave);
                                    while(block) {
                                        char owner[256]; int o_port; sscanf(block, "%255[^:]:%d|", owner, &o_port);
                                        bool owner_is_known = false;
                                        for(int z=0; z<state->peer_count; z++) if(state->peers[z].port == o_port && strcmp(state->peers[z].ip, owner) == 0) owner_is_known = true;
                                        if (owner_is_known) {
                                            if(strstr(block, all_peers[i].ip)) { 
                                                char check_sig[MAX_BUFFER]; snprintf(check_sig, sizeof(check_sig), "%.255s:%d->%.255s:%d", owner, o_port, all_peers[i].ip, all_peers[i].port);
                                                bool already_rept = false;
                                                for(int k=0; k<rm_count; k++) if(strcmp(reported_mismatches[k], check_sig)==0) already_rept = true;
                                                if(!already_rept && rm_count < 64) {
                                                    snprintf(reported_mismatches[rm_count++], MAX_BUFFER, "%.1023s", check_sig);
                                                    issues++; issue_off += snprintf(issue_log + issue_off, sizeof(issue_log)-issue_off, " [!] Config Mismatch: Peer %.255s:%d knows %.255s:%d, but we don't.\n", owner, o_port, all_peers[i].ip, all_peers[i].port);
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
                for(int k=0; k<line_len && offset < (int)sizeof(response); k++) { 
                    response[offset++] = '-'; 
                } 
                if (offset >= (int)sizeof(response)) {
                    return send_response(state, client, "ERROR: Response buffer overflow");
                }
                response[offset++] = '\n';
                
                char status_str[128]; 
                if (issues == 0 && state->peer_count > 0) {
                    snprintf(status_str, 64, "\033[32mHEALTHY\033[0m");
                } else {
                    snprintf(status_str, 64, "\033[33mDEGRADED (%d ISSUES)\033[0m", issues);
                }
                
                written = snprintf(response + offset, sizeof(response) - offset, 
                                 " [i] MESH STATUS: %s\n [Legend: -- = Self, UP = Connected, DN = Down, ?? = Unknown/Not Configured]\n", 
                                 status_str);
                if (written < 0 || written >= (int)(sizeof(response) - offset)) {
                    return send_response(state, client, "ERROR: Response buffer overflow");
                }
                offset += written;
                
                if (issues > 0) {
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
    switch(cmd) {
        case CMD_PING:
            hub_log("[HUB] Bot %s PING\n", client->id);
            break;
            
        case CMD_CONFIG_PUSH:
            hub_log("[HUB] Sync from %s\n", client->id);
            if (payload) {
                char target_nick[32], servers[256], chans[256], pass[128];
                time_t now = time(NULL);
                char sync_packet[MAX_BUFFER];
                int sp_len = 0;
                int written;
                
                hub_storage_update_entry(state, client->id, "t", "", now);
                
                written = snprintf(sync_packet + sp_len, sizeof(sync_packet) - sp_len, 
                                 "%s|t||%ld\n", client->id, (long)now);
                if (written > 0 && written < (int)(sizeof(sync_packet) - sp_len)) {
                    sp_len += written;
                }
                
                if (sscanf(payload, "%31[^|]|%255[^|]|%255[^|]|%127s", 
                          target_nick, servers, chans, pass) >= 1) {
                    hub_storage_update_entry(state, client->id, "n", target_nick, now);
                    
                    written = snprintf(sync_packet + sp_len, sizeof(sync_packet) - sp_len, 
                                     "%s|n|%s|%ld\n", client->id, target_nick, (long)now);
                    if (written > 0 && written < (int)(sizeof(sync_packet) - sp_len)) {
                        sp_len += written;
                    }
                    
                    hub_storage_update_entry(state, client->id, "b", pass, now);
                    
                    written = snprintf(sync_packet + sp_len, sizeof(sync_packet) - sp_len, 
                                     "%s|b|%s|%ld\n", client->id, pass, (long)now);
                    if (written > 0 && written < (int)(sizeof(sync_packet) - sp_len)) {
                        sp_len += written;
                    }
                    
                    char *sp, *t = strtok_r(servers, ",", &sp);
                    while(t) {
                        hub_storage_update_entry(state, client->id, "s", t, now);
                        
                        written = snprintf(sync_packet + sp_len, sizeof(sync_packet) - sp_len, 
                                         "%s|s|%s|%ld\n", client->id, t, (long)now);
                        if (written > 0 && written < (int)(sizeof(sync_packet) - sp_len)) {
                            sp_len += written;
                        }
                        t = strtok_r(NULL, ",", &sp);
                    }
                    
                    t = strtok_r(chans, ",", &sp);
                    while(t) {
                        hub_storage_update_entry(state, client->id, "c", t, now);
                        
                        written = snprintf(sync_packet + sp_len, sizeof(sync_packet) - sp_len, 
                                         "%s|c|%s|%ld\n", client->id, t, (long)now);
                        if (written > 0 && written < (int)(sizeof(sync_packet) - sp_len)) {
                            sp_len += written;
                        }
                        t = strtok_r(NULL, ",", &sp);
                    }
                    
                    hub_config_write(state);
                    hub_broadcast_sync_to_peers(state, sync_packet, -1);
                }
            }
            break;
    }
}

// Final part of hub_logic.c - Main packet handler

bool hub_handle_client_data(hub_state_t *state, hub_client_t *client) {
    while (client->recv_len >= 4) {
        uint32_t net_len;
        memcpy(&net_len, client->recv_buf, 4);
        int packet_len = ntohl(net_len);
        
        // ADDED: Enhanced bounds checking
        if (packet_len < GCM_TAG_LEN + 5 || packet_len > (MAX_BUFFER - 4)) {
            hub_log("[ERROR] Invalid packet length %d from %s\n", packet_len, client->ip);
            hub_disconnect_client(state, client);
            return false;
        }
        
        if (client->recv_len < (4 + packet_len)) {
            return true; // Need more data
        }
        
        unsigned char *data = client->recv_buf + 4;
        
        if (!client->authenticated) {
            // Initial authentication uses RSA encryption (no GCM yet)
            unsigned char dec[512];
            int dec_len = evp_private_decrypt(state->priv_key, data, packet_len, dec);
            
            if (dec_len > 32) {
                memcpy(client->session_key, dec, 32);
                char *payload = (char*)dec + 32;
                dec[dec_len] = 0;
                
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
                        for(int p = 0; p < state->peer_count; p++) {
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
                        
                        // Send initial sync to peer
                        unsigned char plain[MAX_BUFFER], buffer[MAX_BUFFER], tag[GCM_TAG_LEN];
                        plain[0] = CMD_PEER_SYNC;
                        
                        hub_generate_sync_packet(state, (char*)plain + 5, MAX_BUFFER - 100);
                        
                        int payload_len = strlen((char*)plain + 5);
                        int total_plain = 1 + 4 + payload_len;
                        memcpy(&plain[1], &payload_len, 4);
                        
                        unsigned char aad[1] = { CMD_PEER_SYNC };
                        int cipher_len = aes_gcm_encrypt(plain, total_plain, client->session_key, 
                                                        buffer + 4, tag, aad, sizeof(aad));
                        
                        if (cipher_len > 0) {
                            memcpy(buffer + 4 + cipher_len, tag, GCM_TAG_LEN);
                            int pkt_len = cipher_len + GCM_TAG_LEN;
                            uint32_t nl = htonl(pkt_len);
                            memcpy(buffer, &nl, 4);
                            
                            if (write(client->fd, buffer, 4 + pkt_len) <= 0) {
                                hub_log("[MESH] Failed to send initial sync\n");
                            } else {
                                hub_log("[HUB] Peer connected: %s\n", client->ip);
                            }
                        }
                    } else {
                        hub_log("[HUB] Failed peer auth from %s\n", client->ip);
                        secure_wipe(dec, sizeof(dec));
                        hub_disconnect_client(state, client);
                        return false;
                    }
                }
                else {
                    // Bot authentication
                    bool auth = false;
                    for(int i = 0; i < state->bot_count; i++) {
                        if (strcmp(state->bots[i].uuid, payload) == 0) {
                            auth = true;
                            break;
                        }
                    }
                    
                    if (auth) {
                        client->type = CLIENT_BOT;
                        client->authenticated = true;
                        strncpy(client->id, payload, sizeof(client->id) - 1);
                        client->id[sizeof(client->id) - 1] = 0;
                        hub_log("[HUB] Bot Login: %s\n", client->id);
                    } else {
                        hub_log("[HUB] Unauthorized bot: %s from %s\n", payload, client->ip);
                        add_pending_bot(state, payload, client->ip);
                        secure_wipe(dec, sizeof(dec));
                        hub_disconnect_client(state, client);
                        return false;
                    }
                }
                
                // ADDED: Wipe decrypted auth data
                secure_wipe(dec, sizeof(dec));
            } else {
                hub_log("[HUB] Decryption failed from %s\n", client->ip);
                hub_disconnect_client(state, client);
                return false;
            }
        }
        else {
            // Authenticated client - process encrypted packet
            if (packet_len > GCM_TAG_LEN) {
                unsigned char plain[MAX_BUFFER], tag[GCM_TAG_LEN];
                
                memcpy(tag, data + packet_len - GCM_TAG_LEN, GCM_TAG_LEN);
                
                // NOTE: No AAD needed - command byte is encrypted
                int pl = aes_gcm_decrypt(data, packet_len - GCM_TAG_LEN, 
                                        client->session_key, plain, tag);
                
                if (pl > 0) {
                    unsigned char cmd = plain[0];
                    
                    if (cmd == CMD_PING) {
                        if (!send_pong(state, client)) {
                            return false;
                        }
                    }
                    else {
                        plain[pl] = 0;
                        
                        // Extract payload (skip cmd byte + 4-byte length)
                        char *payload_ptr = (char*)plain + 5;
                        
                        if (client->type == CLIENT_ADMIN) {
                            if (!handle_admin_command(state, client, cmd, payload_ptr)) {
                                return false;
                            }
                        }
                        else if (client->type == CLIENT_BOT) {
                            process_bot_command(state, client, cmd, payload_ptr);
                        }
                        else if (client->type == CLIENT_HUB) {
                            if (cmd == CMD_PEER_SYNC) {
                                process_peer_sync(state, payload_ptr, client->fd);
                            }
                            else if (cmd == CMD_MESH_STATE) {
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
