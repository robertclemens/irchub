#include "hub.h"
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/rand.h>
#include <strings.h>
#include <sys/select.h>

static void send_config_to_bot(hub_state_t *state, hub_client_t *client);
static void hub_broadcast_config_to_bots(hub_state_t *state, const char *config_line);

/* ==========================================================================
 * Mesh transport — per-peer outbound queue (docs/mesh.md Phase 1)
 *
 * Replaces the old "build packet → encrypt → send-or-drop on EAGAIN" model
 * with a per-client queue drained on POLLOUT.  Encryption happens at drain
 * time (so we can use the up-to-date session_key) and partial writes are
 * tracked via writing_buf/writing_offset.  Three priority lanes: URGENT
 * (op flow), DELTA (small per-key updates), BULK (anti-entropy/full sync).
 * ========================================================================== */

queued_msg_t *queued_msg_new(uint8_t cmd, lane_t lane,
                             const unsigned char *payload, int payload_len) {
  if (payload_len < 0 || payload_len > MAX_BUFFER - 64)
    return NULL;
  queued_msg_t *m = calloc(1, sizeof(*m));
  if (!m) return NULL;
  m->cmd = cmd;
  m->lane = lane;
  if (payload_len > 0) {
    m->payload = malloc((size_t)payload_len);
    if (!m->payload) { free(m); return NULL; }
    memcpy(m->payload, payload, (size_t)payload_len);
  }
  m->payload_len = payload_len;
  return m;
}

void queued_msg_set_coalesce(queued_msg_t *m, const char *origin_hub_uuid,
                             uint64_t lamport_seq, const char *coalesce_key) {
  if (origin_hub_uuid)
    snprintf(m->origin_hub_uuid, sizeof(m->origin_hub_uuid), "%s", origin_hub_uuid);
  m->lamport_seq = lamport_seq;
  if (coalesce_key)
    snprintf(m->coalesce_key, sizeof(m->coalesce_key), "%s", coalesce_key);
}

void queued_msg_free(queued_msg_t *m) {
  if (!m) return;
  if (m->payload) {
    /* Defensively wipe payload — it can carry hostmask / op-flow material. */
    secure_wipe(m->payload, (size_t)m->payload_len);
    free(m->payload);
  }
  free(m);
}

/* Atomically replace dst's payload/seq with src's (dst stays in place at the
 * same FIFO position). Used by coalescing.  Both lanes' byte counters must
 * be adjusted by the caller. */
static void queued_msg_replace_payload(queued_msg_t *dst, queued_msg_t *src) {
  if (dst->payload) { secure_wipe(dst->payload, (size_t)dst->payload_len); free(dst->payload); }
  dst->payload     = src->payload;
  dst->payload_len = src->payload_len;
  dst->lamport_seq = src->lamport_seq;
  /* Origin hub may differ if a peer's update overwrote a local-origin one;
   * the new origin "wins" because newer seq belongs to it. */
  snprintf(dst->origin_hub_uuid, sizeof(dst->origin_hub_uuid),
           "%s", src->origin_hub_uuid);
  src->payload = NULL;
  src->payload_len = 0;
  free(src);
}

bool peer_enqueue(hub_client_t *peer, queued_msg_t *m) {
  if (!peer || !m) return false;
  if (peer->fd < 0) { queued_msg_free(m); return false; }

  /* The lane index is taken from m->lane (populated by queued_msg_new). */
  int li = (int)m->lane;
  if (li < 0 || li >= LANE_COUNT) li = LANE_BULK;
  queue_lane_t *lane = &peer->out_lanes[li];

  /* ---- Coalescing (Phase 5; harmless in earlier phases when coalesce_key
   * is empty).  Walk the lane FIFO; if we find a same-key entry, replace its
   * payload in place and free the new msg. ---- */
  if (m->coalesce_key[0] != '\0') {
    for (queued_msg_t *cur = lane->head; cur; cur = cur->next) {
      if (cur->coalesce_key[0] != '\0' &&
          strcmp(cur->coalesce_key, m->coalesce_key) == 0) {
        int old_bytes = cur->payload_len;
        int new_bytes = m->payload_len;
        queued_msg_replace_payload(cur, m);
        lane->bytes        += (new_bytes - old_bytes);
        peer->out_total_bytes += (new_bytes - old_bytes);
        return true;
      }
    }
  }

  /* ---- Overflow handling.  URGENT must never be dropped; treat full
   * URGENT as a fatal peer condition (caller will disconnect). DELTA can
   * drop oldest non-coalesced entries. BULK drops oldest. ---- */
  if (lane->count >= MAX_QUEUE_PER_LANE ||
      peer->out_total_bytes + m->payload_len > MAX_QUEUED_BYTES_PER_PEER) {
    if (li == LANE_URGENT) {
      /* Caller will see false and decide whether to disconnect. */
      queued_msg_free(m);
      return false;
    }
    /* Drop oldest in this lane to make room.  For DELTA we lose one update
     * (the next anti-entropy will reconcile); for BULK we lose a full sync
     * (next anti-entropy fires within MESH_ANTI_ENTROPY_INTERVAL). */
    queued_msg_t *old = lane->head;
    if (old) {
      lane->head = old->next;
      if (!lane->head) lane->tail = NULL;
      lane->count--;
      lane->bytes        -= old->payload_len;
      peer->out_total_bytes -= old->payload_len;
      hub_log("[MESH] queue %s lane full — dropping oldest (peer fd=%d)\n",
              li == LANE_DELTA ? "DELTA" : "BULK", peer->fd);
      queued_msg_free(old);
    }
  }

  /* Append. */
  m->next = NULL;
  if (lane->tail) lane->tail->next = m;
  else            lane->head       = m;
  lane->tail = m;
  lane->count++;
  lane->bytes        += m->payload_len;
  peer->out_total_bytes += m->payload_len;
  return true;
}

bool peer_has_pending_writes(hub_client_t *peer) {
  if (!peer) return false;
  if (peer->writing_len > peer->writing_offset) return true;
  for (int i = 0; i < LANE_COUNT; i++)
    if (peer->out_lanes[i].count > 0) return true;
  return false;
}

void peer_queue_destroy(hub_client_t *peer) {
  if (!peer) return;
  for (int i = 0; i < LANE_COUNT; i++) {
    queued_msg_t *cur = peer->out_lanes[i].head;
    while (cur) {
      queued_msg_t *next = cur->next;
      queued_msg_free(cur);
      cur = next;
    }
    peer->out_lanes[i].head  = NULL;
    peer->out_lanes[i].tail  = NULL;
    peer->out_lanes[i].count = 0;
    peer->out_lanes[i].bytes = 0;
  }
  peer->out_total_bytes = 0;
  /* Also wipe any partially-written ciphertext. */
  secure_wipe(peer->writing_buf, (size_t)peer->writing_len);
  peer->writing_len    = 0;
  peer->writing_offset = 0;
}

/* Encrypt `m` using peer->session_key into peer->writing_buf.  Returns the
 * total wire length (4-byte length prefix + ciphertext + tag) or 0 on
 * failure. */
static int peer_encrypt_into_writing(hub_client_t *peer, queued_msg_t *m) {
  unsigned char plain[MAX_BUFFER];
  /* Wire envelope per existing protocol:
   *   plain[0]    = cmd
   *   plain[1..4] = (uint32_t) inner_len in HOST byte order (matches hub_logic
   *                 callers; bot side likewise).  This preserves wire
   *                 compatibility with all existing peers and bots.
   *   plain[5..]  = payload bytes
   *
   * Note: send_config_to_bot historically used network byte order for the
   * inner length to match bot's parser.  We honor that by stamping the
   * inner length here in HOST order for peer/admin packets and in NETWORK
   * order for CMD_CONFIG_DATA bot frames (the only opcode that requires it).
   */
  if (m->payload_len > MAX_BUFFER - 16) return 0;
  plain[0] = m->cmd;
  uint32_t inner_len_field;
  if (m->cmd == CMD_CONFIG_DATA) {
    inner_len_field = htonl((uint32_t)m->payload_len);
  } else {
    inner_len_field = (uint32_t)m->payload_len;
  }
  memcpy(&plain[1], &inner_len_field, 4);
  if (m->payload_len > 0)
    memcpy(&plain[5], m->payload, (size_t)m->payload_len);
  int total_plain = 5 + m->payload_len;

  unsigned char tag[GCM_TAG_LEN];
  int cipher_len = aes_gcm_encrypt(plain, total_plain, peer->session_key,
                                   peer->writing_buf + 4, tag);
  /* Wipe plaintext copy ASAP. */
  secure_wipe(plain, sizeof(plain));
  if (cipher_len <= 0) return 0;
  memcpy(peer->writing_buf + 4 + cipher_len, tag, GCM_TAG_LEN);
  int packet_len = cipher_len + GCM_TAG_LEN;
  uint32_t nl = htonl((uint32_t)packet_len);
  memcpy(peer->writing_buf, &nl, 4);
  return 4 + packet_len;
}

void peer_drain_writable(hub_state_t *state, hub_client_t *peer) {
  (void)state;
  if (!peer || peer->fd < 0) return;

  /* Step 1: finish any in-flight ciphertext. */
  while (peer->writing_offset < peer->writing_len) {
    int remain = peer->writing_len - peer->writing_offset;
    ssize_t s = send(peer->fd, peer->writing_buf + peer->writing_offset,
                     (size_t)remain, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (s > 0) {
      peer->writing_offset += (int)s;
      /* Account against bandwidth window. */
      time_t now = time(NULL);
      if (peer->bw_window_start != now) {
        peer->bw_window_start = now;
        peer->bw_bytes_in_window = 0;
      }
      peer->bw_bytes_in_window += (int)s;
      continue;
    }
    if (s < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
      return;  /* try again next POLLOUT */
    /* Hard send error — caller should disconnect.  We cannot do it here
     * safely (caller iterates the client list); signal by clearing fd. */
    hub_log("[MESH] send error to %s (fd=%d): %s\n", peer->ip, peer->fd,
            strerror(errno));
    /* Clear the in-flight buffer so next iteration of main loop will see
     * peer_has_pending_writes()==false and the recv side will reap on EOF. */
    peer->writing_len = peer->writing_offset = 0;
    return;
  }
  /* In-flight buffer fully sent; reset for reuse. */
  peer->writing_len = peer->writing_offset = 0;

  /* Step 2: drain lanes in priority order until we run out of messages or
   * the socket goes EAGAIN. */
  for (int li = 0; li < LANE_COUNT; li++) {
    queue_lane_t *lane = &peer->out_lanes[li];
    while (lane->count > 0) {
      /* Bandwidth budget enforcement (Phase 5; defaults are generous). */
      time_t now = time(NULL);
      if (peer->bw_window_start != now) {
        peer->bw_window_start = now;
        peer->bw_bytes_in_window = 0;
      }
      if (li == LANE_BULK &&
          peer->bw_bytes_in_window > BULK_SOFT_BUDGET_BPS) {
        return;  /* defer remaining BULK to next second */
      }
      if (li == LANE_DELTA &&
          peer->bw_bytes_in_window > DELTA_HARD_BUDGET_BPS) {
        return;  /* extreme case — let coalescing catch up */
      }

      queued_msg_t *m = lane->head;
      lane->head = m->next;
      if (!lane->head) lane->tail = NULL;
      lane->count--;
      lane->bytes        -= m->payload_len;
      peer->out_total_bytes -= m->payload_len;

      int wire_len = peer_encrypt_into_writing(peer, m);
      queued_msg_free(m);
      if (wire_len <= 0) {
        hub_log("[MESH] encrypt failed for peer %s lane %d\n", peer->ip, li);
        continue;  /* drop and move on */
      }
      peer->writing_len    = wire_len;
      peer->writing_offset = 0;

      /* Try to send immediately. */
      while (peer->writing_offset < peer->writing_len) {
        int remain = peer->writing_len - peer->writing_offset;
        ssize_t s = send(peer->fd, peer->writing_buf + peer->writing_offset,
                         (size_t)remain, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (s > 0) {
          peer->writing_offset    += (int)s;
          peer->bw_bytes_in_window += (int)s;
          continue;
        }
        if (s < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
          return;  /* socket buffer full — main loop will resume on POLLOUT */
        hub_log("[MESH] send error to %s (fd=%d): %s\n", peer->ip, peer->fd,
                strerror(errno));
        peer->writing_len = peer->writing_offset = 0;
        return;
      }
      peer->writing_len = peer->writing_offset = 0;
    }
  }
}

/* Convenience: enqueue a small hub→hub URGENT message.  Returns true on
 * success; false if the peer's URGENT queue is full (caller should
 * disconnect that peer).  `payload` is the raw string after the cmd byte
 * (plain[5..]).  Uses host byte order for inner_len (hub receivers ignore
 * it; only bots use ntohl which is handled separately). */
static bool peer_send_urgent(hub_state_t *state, hub_client_t *peer,
                              uint8_t cmd, const char *payload) {
  (void)state;
  int plen = payload ? (int)strlen(payload) : 0;
  queued_msg_t *m = queued_msg_new(cmd, LANE_URGENT,
                                   (const unsigned char *)payload, plen);
  if (!m) return false;
  if (!peer_enqueue(peer, m)) {
    hub_log("[URGENT] Queue full for peer %s — disconnecting\n", peer->ip);
    return false;  /* caller must hub_disconnect_client */
  }
  return true;
}

uint64_t hub_next_lamport_seq(hub_state_t *state) {
  /* Bump-then-return so first issued seq is 1, not 0. */
  state->next_lamport_seq++;
  return state->next_lamport_seq;
}

bool hub_delta_seen_check_and_update(hub_state_t *state,
                                     const char *origin_hub_uuid,
                                     const char *bot_uuid,
                                     uint64_t seq) {
  if (!state || !origin_hub_uuid || !bot_uuid) return true;
  if (origin_hub_uuid[0] == '\0' || bot_uuid[0] == '\0') return true;

  for (int i = 0; i < state->delta_seen_count; i++) {
    delta_seen_t *e = &state->delta_seen[i];
    if (strcmp(e->origin_hub_uuid, origin_hub_uuid) == 0 &&
        strcmp(e->bot_uuid, bot_uuid) == 0) {
      if (seq <= e->max_seq_seen) return false;
      e->max_seq_seen = seq;
      e->last_seen_at = time(NULL);
      return true;
    }
  }

  /* Insert new.  If full, LRU-evict oldest. */
  if (state->delta_seen_count >= MAX_DELTA_SEEN) {
    int oldest = 0;
    time_t oldest_at = state->delta_seen[0].last_seen_at;
    for (int i = 1; i < state->delta_seen_count; i++) {
      if (state->delta_seen[i].last_seen_at < oldest_at) {
        oldest = i;
        oldest_at = state->delta_seen[i].last_seen_at;
      }
    }
    /* Move-from-end into oldest slot (don't shift the array). */
    state->delta_seen[oldest] = state->delta_seen[state->delta_seen_count - 1];
    state->delta_seen_count--;
  }

  delta_seen_t *e = &state->delta_seen[state->delta_seen_count++];
  snprintf(e->origin_hub_uuid, sizeof(e->origin_hub_uuid), "%s", origin_hub_uuid);
  snprintf(e->bot_uuid,        sizeof(e->bot_uuid),        "%s", bot_uuid);
  e->max_seq_seen = seq;
  e->last_seen_at = time(NULL);
  return true;
}
/* ========================================================================== */


/* Read and process any immediately available data from connected peer sockets
 * for up to timeout_ms milliseconds. Used to collect fresh gossip before
 * building a peer-list response so the admin sees current mesh state. */

// --- Forward Declarations ---
static bool send_response(hub_state_t *state, hub_client_t *client,
                          const char *msg);
static bool send_pong(hub_state_t *state, hub_client_t *c);
static void add_pending_bot(hub_state_t *state, const char *uuid,
                            const char *ip);
static void remove_pending_bot(hub_state_t *state, const char *uuid);
static void broadcast_new_key(hub_state_t *state, const char *new_priv_key, const char *new_pub_key);
static void process_mesh_state(hub_state_t *state, hub_client_t *c,
                               char *payload);
static void process_peer_sync(hub_state_t *state, char *payload, int origin_fd);
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
static bool op_forward_seen_check_and_add(hub_state_t *state,
                                           const char *request_id);
static void forward_op_request_to_peers(hub_state_t *state,
                                         const char *request_id,
                                         const char *requester_uuid,
                                         const char *target_uuid,
                                         const char *channel,
                                         const char *requester_hostmask,
                                         int exclude_fd,
                                         time_t origin_ts);
static void process_forward_op_request(hub_state_t *state,
                                        hub_client_t *client, char *payload);
static void process_forward_op_grant(hub_state_t *state, hub_client_t *client,
                                      char *payload);
static void process_forward_op_failed(hub_state_t *state, hub_client_t *client,
                                       char *payload);

// --- Helper Functions ---

// Check if PURGE with this cutoff was recently seen (deduplication)
static bool is_purge_recent(hub_state_t *state, time_t cutoff) {
  time_t now = time(NULL);
  for (int i = 0; i < state->recent_purge_count; i++) {
    if (state->recent_purges[i].cutoff == cutoff) {
      // Check if still within dedup window
      if (now - state->recent_purges[i].received_at < PURGE_DEDUP_WINDOW) {
        return true;  // This PURGE was recently processed, skip it
      }
    }
  }
  return false;
}

// Record a recently processed PURGE
static void record_recent_purge(hub_state_t *state, time_t cutoff) {
  time_t now = time(NULL);

  // Check if already exists (update timestamp)
  for (int i = 0; i < state->recent_purge_count; i++) {
    if (state->recent_purges[i].cutoff == cutoff) {
      state->recent_purges[i].received_at = now;
      return;
    }
  }

  // Add new entry (circular buffer)
  if (state->recent_purge_count < MAX_RECENT_PURGES) {
    state->recent_purges[state->recent_purge_count].cutoff = cutoff;
    state->recent_purges[state->recent_purge_count].received_at = now;
    state->recent_purge_count++;
  } else {
    // Overwrite oldest entry
    state->recent_purges[0].cutoff = cutoff;
    state->recent_purges[0].received_at = now;
  }
}

// Check if this hub should initiate scheduled purges (leader election)
// Strategy: The hub with the lexicographically smallest UUID leads
bool hub_should_initiate_scheduled_purge(hub_state_t *state) {
  for (int i = 0; i < state->client_count; i++) {
    if (state->clients[i]->type == CLIENT_HUB && state->clients[i]->authenticated) {
      // If any peer has a UUID less than ours, they should lead
      if (strcmp(state->clients[i]->id, state->hub_uuid) < 0) {
        return false;
      }
    }
  }
  // Either no peers, or we have the smallest UUID
  return true;
}

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
        snprintf(entry->ip, sizeof(entry->ip), "%s", ip);
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
    /* Loopback is trusted — skip all rate limiting */
    if (strcmp(ip, "127.0.0.1") == 0 || strcmp(ip, "::1") == 0) return true;

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
    if (strcmp(ip, "127.0.0.1") == 0 || strcmp(ip, "::1") == 0) return;
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
    char pattern_copy[MAX_MASK_LEN];
    snprintf(pattern_copy, sizeof(pattern_copy), "%s", pattern);

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
                snprintf(pattern, sizeof(pattern), "%.*s",
                         (int)(sizeof(pattern) - 1), state->global_entries[i].value);
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

// Load bot's combined 64-byte public key from hub config
static bool load_bot_combined_pub(hub_state_t *state, const char *uuid,
                                  unsigned char out[64]) {
  for (int i = 0; i < state->bot_count; i++) {
    if (strcmp(state->bots[i].uuid, uuid) != 0) continue;
    for (int j = 0; j < state->bots[i].entry_count; j++) {
      if (strcmp(state->bots[i].entries[j].key, "pub") != 0) continue;
      int dec_len = 0;
      unsigned char *dec = base64_decode(state->bots[i].entries[j].value, &dec_len);
      if (!dec) return false;
      if (dec_len != 64) { secure_wipe(dec, dec_len); free(dec); return false; }
      memcpy(out, dec, 64);
      secure_wipe(dec, 64);
      free(dec);
      return true;
    }
  }
  return false;
}

bool handle_bot_authentication(hub_state_t *state, hub_client_t *client,
                               unsigned char *data, int packet_len) {

  // PHASE 1: Receive UUID (plaintext)
  if (!client->authenticated && client->bot_auth_state == BOT_AUTH_IDLE) {
    if (packet_len < 1 || packet_len > 63) return false;
    char uuid[64];
    memcpy(uuid, data, packet_len);
    uuid[packet_len] = '\0';

    hub_log("[HUB] Bot auth attempt from %s with UUID: %s\n", client->ip, uuid);

    bool authorized = false;
    for (int i = 0; i < state->bot_count; i++) {
      if (strcmp(state->bots[i].uuid, uuid) == 0 &&
          state->bots[i].is_active) { authorized = true; break; }
    }

    if (!authorized) {
      hub_log("[HUB] Unauthorized bot UUID: %s from %s\n", uuid, client->ip);
      add_pending_bot(state, uuid, client->ip);
      record_failed_auth(state, client->ip);
      return false;
    }

    // Generate challenge + ephemeral X25519 keypair
    if (RAND_bytes(client->challenge, 32) != 1) {
      hub_log("[HUB][ERROR] Failed to generate challenge\n");
      return false;
    }

    unsigned char eph_pub[32];
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *pk = NULL;
    size_t len = 32;
    bool ok = ctx && EVP_PKEY_keygen_init(ctx) > 0
                  && EVP_PKEY_keygen(ctx, &pk) > 0
                  && EVP_PKEY_get_raw_private_key(pk, client->bot_eph_x25519_priv, &len) > 0
                  && len == 32
                  && EVP_PKEY_get_raw_public_key(pk, eph_pub, &len) > 0
                  && len == 32;
    if (pk)  EVP_PKEY_free(pk);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (!ok) { secure_wipe(client->bot_eph_x25519_priv, 32);
               hub_log("[HUB][ERROR] Ephemeral X25519 keygen failed\n"); return false; }
    client->bot_eph_priv_set = true;

    // Send: challenge_32 || eph_pub_32 (raw 64 bytes, length-prefixed)
    unsigned char out_buf[64];
    memcpy(out_buf,      client->challenge, 32);
    memcpy(out_buf + 32, eph_pub,           32);

    uint32_t nl = htonl(64);
    if (write(client->fd, &nl, 4) != 4 ||
        write(client->fd, out_buf, 64) != 64) {
      hub_log("[HUB][ERROR] Failed to send challenge to %s\n", uuid);
      return false;
    }

    snprintf(client->id, sizeof(client->id), "%s", uuid);
    client->bot_auth_state = BOT_AUTH_CHALLENGE_SENT;
    client->last_seen = time(NULL);

    hub_log("[HUB] Sent Curve25519 challenge to bot %s\n", uuid);
    return true;
  }

  // PHASE 2: Receive 64-byte Ed25519 signature
  if (!client->authenticated &&
      client->bot_auth_state == BOT_AUTH_CHALLENGE_SENT) {
    hub_log("[HUB] Received signature from bot %s (%d bytes)\n", client->id, packet_len);

    if (packet_len != 64 || !client->bot_eph_priv_set) {
      hub_log("[HUB][ERROR] Bad signature size or state from %s\n", client->id);
      return false;
    }

    unsigned char bot_combined[64], bot_ed_pub[32], bot_x_pub[32];
    if (!load_bot_combined_pub(state, client->id, bot_combined)) {
      hub_log("[HUB][ERROR] No public key for bot %s\n", client->id);
      return false;
    }
    hub_crypto_split_combined(bot_combined, bot_ed_pub, bot_x_pub);

    if (!hub_crypto_ed25519_verify(bot_ed_pub, client->challenge, 32, data)) {
      hub_log("[HUB][ERROR] Invalid signature from bot %s\n", client->id);
      record_failed_auth(state, client->ip);
      secure_wipe(bot_combined, 64);
      return false;
    }

    unsigned char shared[32];
    if (!hub_crypto_x25519_derive(client->bot_eph_x25519_priv, bot_x_pub, shared)) {
      hub_log("[HUB][ERROR] X25519 derive failed for %s\n", client->id);
      secure_wipe(bot_combined, 64);
      return false;
    }

    unsigned char info[96];
    int info_len = snprintf((char *)info, sizeof(info),
                            "irchub-bot-session-v1|%s", client->id);
    bool ok = hub_crypto_hkdf_sha256(shared, 32,
                                     client->challenge, 32,
                                     info, (size_t)info_len,
                                     client->session_key, 32);
    secure_wipe(shared, 32);
    secure_wipe(client->bot_eph_x25519_priv, 32);
    client->bot_eph_priv_set = false;
    secure_wipe(bot_combined, 64);
    if (!ok) {
      hub_log("[HUB][ERROR] HKDF failed for %s\n", client->id);
      return false;
    }

    // Send 1-byte ACK
    unsigned char ack = 0x01;
    uint32_t nl = htonl(1);
    if (write(client->fd, &nl, 4) != 4 ||
        write(client->fd, &ack, 1) != 1) {
      hub_log("[HUB][ERROR] Failed to send ACK to %s\n", client->id);
      return false;
    }

    client->type = CLIENT_BOT;
    client->authenticated = true;
    client->bot_auth_state = BOT_AUTH_COMPLETE;
    client->last_seen = time(NULL);

    hub_storage_update_entry(state, client->id, "seen", "", "", "", client->last_seen);

    hub_log("[HUB] Bot %s authenticated (Curve25519)\n", client->id);
    return true;
  }

  return false;
}

// Sealed-box open: eph_pub(32) || IV(GCM_IV_LEN) || ct(N) || tag(GCM_TAG_LEN)
static int hub_seal_open(hub_state_t *state,
                         const unsigned char *in, int in_len,
                         const unsigned char *info, size_t info_len,
                         unsigned char *plain_out, int plain_max,
                         unsigned char session_key_out[32]) {
    if (in_len < 32 + GCM_IV_LEN + GCM_TAG_LEN) return -1;
    const unsigned char *eph_pub = in;
    const unsigned char *iv      = in + 32;
    const unsigned char *ct      = in + 32 + GCM_IV_LEN;
    int ct_len                   = in_len - 32 - GCM_IV_LEN - GCM_TAG_LEN;
    const unsigned char *tag_ptr = in + in_len - GCM_TAG_LEN;
    if (ct_len < 0 || ct_len > plain_max) return -1;

    unsigned char shared[32], session_key[32];
    if (!hub_crypto_x25519_derive(state->hub_x25519_priv, eph_pub, shared)) return -1;
    bool ok = hub_crypto_hkdf_sha256(shared, 32, eph_pub, 32,
                                     info, info_len, session_key, 32);
    secure_wipe(shared, 32);
    if (!ok) return -1;

    unsigned char tmp[MAX_BUFFER];
    if (GCM_IV_LEN + ct_len > (int)sizeof(tmp)) { secure_wipe(session_key, 32); return -1; }
    memcpy(tmp,              iv, GCM_IV_LEN);
    memcpy(tmp + GCM_IV_LEN, ct, ct_len);

    unsigned char tag_buf[GCM_TAG_LEN];
    memcpy(tag_buf, tag_ptr, GCM_TAG_LEN);
    int pl = aes_gcm_decrypt(tmp, GCM_IV_LEN + ct_len,
                             session_key, plain_out, tag_buf);
    secure_wipe(tmp, GCM_IV_LEN + ct_len);
    if (pl <= 0) { secure_wipe(session_key, 32); return -1; }

    memcpy(session_key_out, session_key, 32);
    secure_wipe(session_key, 32);
    return pl;
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

  snprintf(p->nick, sizeof(p->nick), "Unknown");
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

        if (write(c->fd, buffer, 4 + packet_len) == (ssize_t)(4 + packet_len)) {
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
    snprintf(b->uuid, sizeof(b->uuid), "%s", uuid);
    b->last_sync_time = 0;

    time_t now = time(NULL);
    hub_storage_update_entry(state, uuid, "n", nick, "", "", now);
    hub_storage_update_entry(state, uuid, "pub", pub_key, "", "", now);
    hub_storage_update_entry(state, uuid, "seen", "", "", "", now);
  }
}

// FIXED: Added comprehensive bounds checking for CMD_ADMIN_LIST_PEERS
void hub_broadcast_mesh_state(hub_state_t *state) {
  char *payload = malloc(MAX_BUFFER);
  char *work_buf = malloc(MAX_BUFFER);

  if (!payload || !work_buf) {
      free(payload);
      free(work_buf);
      return;
  }
  
  memset(payload, 0, MAX_BUFFER);
  int offset = 0;
  int written;

  // Format: bind_ip:port:uuid:friendly_name|
  written = snprintf(payload + offset, MAX_BUFFER - offset, "%s:%d:%s:%s|",
                     state->bind_ip, state->port,
                     state->hub_uuid[0] ? state->hub_uuid : "-",
                     state->hub_friendly_name[0] ? state->hub_friendly_name : "-");
  if (written < 0 || written >= MAX_BUFFER - offset) {
    free(payload); free(work_buf);
    return;
  }
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

      memset(work_buf, 0, MAX_BUFFER);
      snprintf(work_buf, MAX_BUFFER, "%.*s", MAX_BUFFER - 1, body + 1);

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

  char final_packet[MAX_BUFFER];

  written = snprintf(final_packet, sizeof(final_packet), "%d:%d:%d:%s|%s",
                     connected_peers, state->peer_count, active_bots,
                     bot_uuid_list[0] ? bot_uuid_list : "-", payload);
  if (written < 0 || written >= (int)sizeof(final_packet)) {
    free(payload); free(work_buf);
    return;
  }

  int payload_len = strlen(final_packet);
  if (payload_len > MAX_BUFFER - 100) {
    payload_len = MAX_BUFFER - 100;
  }

  /* Mesh-state gossip is best-effort and goes through the BULK lane.  A
   * single coalesce key per (origin_hub_uuid, "mesh") collapses repeated
   * 5-second gossip into the most recent payload if a peer is briefly
   * backed up, so we never queue stale snapshots ahead of fresh ones. */
  char coalesce[80];
  snprintf(coalesce, sizeof(coalesce), "%s|mesh_state", state->hub_uuid);

  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type == CLIENT_HUB && c->authenticated) {
      queued_msg_t *m = queued_msg_new(CMD_MESH_STATE, LANE_BULK,
                                       (const unsigned char *)final_packet,
                                       payload_len);
      if (!m) continue;
      queued_msg_set_coalesce(m, state->hub_uuid,
                              hub_next_lamport_seq(state), coalesce);
      peer_enqueue(c, m);
    }
  }
  free(payload);
  free(work_buf);
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
            state->config_dirty = true;
          }
        }
        return;
      }
    }
  }
}

void hub_broadcast_sync_to_peers(hub_state_t *state, const char *payload,
                                 int exclude_fd) {
  /* Routes through the per-peer queue.  Lane heuristic:
   *  - Single-line CMD_PEER_SYNC payloads originating from a delta forward
   *    (typical: one trailing newline) are short — < 1 KB — and time-
   *    sensitive; treat as DELTA so they're not throttled by the BULK budget.
   *  - Larger payloads (multi-line, e.g. anti-entropy full sync) ride BULK.
   *
   * Phase 2 will add explicit lane parameters to the various callers.  This
   * heuristic is a conservative default that matches existing call patterns
   * (most callers in hub_logic.c send a single line). */
  int payload_len = (int)strlen(payload);
  if (payload_len > (MAX_BUFFER - 10))
    return;

  lane_t lane = (payload_len > 1024) ? LANE_BULK : LANE_DELTA;

  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type == CLIENT_HUB && c->authenticated && c->fd != exclude_fd) {
      queued_msg_t *m = queued_msg_new(CMD_PEER_SYNC, lane,
                                       (const unsigned char *)payload,
                                       payload_len);
      if (!m) continue;
      if (!peer_enqueue(c, m)) {
        /* Only URGENT can fail here; PEER_SYNC is DELTA/BULK so this is
         * effectively unreachable, but be safe. */
        hub_log("[MESH] enqueue failed for peer %s\n", c->ip);
      }
    }
  }
}

// NEW FUNCTION: Broadcast full config to all connected bots to ensure
// consistency
static void hub_request_sync_from_peers(hub_state_t *state) {
  int sent = 0;
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type == CLIENT_HUB && c->authenticated) {
      if (peer_send_urgent(state, c, CMD_SYNC_REQUEST, ""))
        sent++;
    }
  }
  if (sent > 0)
    hub_log("[MESH] Sent sync request to %d peer(s)\n", sent);
}

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
  snprintf(work_buf, sizeof(work_buf), "%s", payload);

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
      // Channel: c|#chan|key|modes|add|timestamp (new) or c|#chan|key|add|timestamp (old)
      char chan[MAX_CHAN], key[MAX_KEY], op[8];
      long ts;
      int modes_val = 0;
      int parsed;

      /* Try new 5-field: chan|key|modes|op|ts */
      parsed = sscanf(data, "%64[^|]|%30[^|]|%d|%7[^|]|%ld",
                      chan, key, &modes_val, op, &ts);
      if (parsed < 5) {
        /* Try new 5-field without key: chan||modes|op|ts */
        modes_val = 0;
        parsed = sscanf(data, "%64[^|]||%d|%7[^|]|%ld",
                        chan, &modes_val, op, &ts);
        if (parsed >= 4) {
          key[0] = '\0';
        } else {
          /* Old 4-field: chan|key|op|ts */
          modes_val = 0;
          parsed = sscanf(data, "%64[^|]|%30[^|]|%7[^|]|%ld",
                          chan, key, op, &ts);
          if (parsed < 3) {
            parsed = sscanf(data, "%64[^|]||%7[^|]|%ld", chan, op, &ts);
            key[0] = '\0';
          }
        }
      }

      if (parsed >= 3) {
        /* Build extra as "key|modes" so storage value = "chan|key|modes|op" */
        char extra[80];
        if (key[0])
          snprintf(extra, sizeof(extra), "%s|%d", key, modes_val);
        else
          snprintf(extra, sizeof(extra), "|%d", modes_val);

        bool accepted = hub_storage_update_global_entry(state, "c", chan, extra, op, ts);
        hub_log("[HUB-DEBUG] Channel %s: ts=%ld op=%s modes=%d -> %s\n",
                chan, ts, op, modes_val, accepted ? "ACCEPTED" : "REJECTED");
        if (accepted) {
          updates++;
          /* Sync buffer: include modes for peer hubs */
          int w = snprintf(
              sync_buffer + sync_offset, sizeof(sync_buffer) - sync_offset,
              "b|%s|c|%s|%s|%d|%s|%ld\n",
              client->id, chan, key, modes_val, op, ts);
          if (w > 0)
            sync_offset += w;
        }
      }
    } else if (type == 'm') {
      /* New format: uuid|mask|add/del|last_used|timestamp
       * Old format: mask|add/del|timestamp (legacy, ignored — hub drives config) */
      char first[40] = {0};
      char *pf = strchr(data, '|');
      if (pf) { size_t fl = (size_t)(pf-data); if (fl<sizeof(first)){memcpy(first,data,fl);first[fl]=0;} }
      bool is_new_m = (strlen(first)==36 && first[8]=='-' && first[13]=='-' && first[18]=='-' && first[23]=='-');
      if (is_new_m) {
        char *p1=strchr(data,'|'), *p2=p1?strchr(p1+1,'|'):NULL;
        char *p3=p2?strchr(p2+1,'|'):NULL, *p4=p3?strchr(p3+1,'|'):NULL;
        if (p1&&p2&&p3&&p4) {
          char uuid[37], mask_s[MAX_MASK_LEN], act[8];
          long last_used, ts;
          snprintf(uuid,   sizeof(uuid),   "%.*s",(int)(p1-data),data);
          snprintf(mask_s, sizeof(mask_s), "%.*s",(int)(p2-p1-1),p1+1);
          snprintf(act,    sizeof(act),    "%.*s",(int)(p3-p2-1),p2+1);
          last_used = atol(p3+1);
          ts        = atol(p4+1);
          bool is_active = (strncmp(act,"add",3)==0);
          /* Find or create mask record */
          hub_mask_record_t *found_m = NULL;
          for (int mi=0; mi<state->mask_record_count; mi++) {
            if (strcmp(state->mask_records[mi].uuid,uuid)==0 &&
                strcasecmp(state->mask_records[mi].mask,mask_s)==0) {
              found_m = &state->mask_records[mi]; break;
            }
          }
          if (!found_m && state->mask_record_count < MAX_HUB_USER_MASKS) {
            found_m = &state->mask_records[state->mask_record_count++];
            memset(found_m,0,sizeof(*found_m));
            snprintf(found_m->uuid,sizeof(found_m->uuid),"%s",uuid);
            snprintf(found_m->mask,sizeof(found_m->mask),"%s",mask_s);
          }
          if (found_m && ts > found_m->timestamp) {
            found_m->is_active = is_active;
            if (last_used > found_m->last_used) found_m->last_used = last_used;
            found_m->timestamp = ts;
            state->config_dirty = true;
            updates++;
            int w = snprintf(sync_buffer+sync_offset, sizeof(sync_buffer)-sync_offset,
                             "m|%s|%s|%s|%ld|%ld\n", uuid, mask_s, act, last_used, ts);
            if (w>0) sync_offset += w;
          }
        }
      }
    } else if (type == 'o' || type == 'a') {
      /* New format: uuid|name|password|add/del|last_seen|timestamp
       * Old single-password format is ignored (hub is authoritative) */
      char first_ao[40] = {0};
      char *pfao = strchr(data, '|');
      if (pfao) { size_t fl=(size_t)(pfao-data); if(fl<sizeof(first_ao)){memcpy(first_ao,data,fl);first_ao[fl]=0;} }
      bool is_new_ao = (strlen(first_ao)==36 && first_ao[8]=='-' && first_ao[13]=='-' && first_ao[18]=='-' && first_ao[23]=='-');
      if (is_new_ao) {
        char *p1=strchr(data,'|'), *p2=p1?strchr(p1+1,'|'):NULL;
        char *p3=p2?strchr(p2+1,'|'):NULL, *p4=p3?strchr(p3+1,'|'):NULL;
        char *p5=p4?strchr(p4+1,'|'):NULL;
        if (p1&&p2&&p3&&p4&&p5) {
          char uuid[37], uname[64], upass[MAX_PASS], act[8];
          long last_seen, ts;
          snprintf(uuid,  sizeof(uuid),  "%.*s",(int)(p1-data),data);
          snprintf(uname, sizeof(uname), "%.*s",(int)(p2-p1-1),p1+1);
          snprintf(upass, sizeof(upass), "%.*s",(int)(p3-p2-1),p2+1);
          snprintf(act,   sizeof(act),   "%.*s",(int)(p4-p3-1),p3+1);
          last_seen = atol(p4+1); ts = atol(p5+1);
          bool is_active = (strncmp(act,"add",3)==0);
          hub_user_record_t *found_u = NULL;
          for (int ui=0; ui<state->user_record_count; ui++) {
            if (strcmp(state->user_records[ui].uuid,uuid)==0) {
              found_u = &state->user_records[ui]; break;
            }
          }
          if (!found_u && state->user_record_count < MAX_HUB_USER_RECORDS) {
            found_u = &state->user_records[state->user_record_count++];
            memset(found_u,0,sizeof(*found_u));
            snprintf(found_u->uuid,sizeof(found_u->uuid),"%s",uuid);
          }
          /* If no UUID match, check for name collision before creating new record */
          if (!found_u) {
            for (int ui2=0; ui2<state->user_record_count; ui2++) {
              if (state->user_records[ui2].type == type &&
                  strcasecmp(state->user_records[ui2].name, uname) == 0) {
                found_u = &state->user_records[ui2]; /* merge into existing */
                break;
              }
            }
            /* If still not found, allocate new slot */
            if (!found_u && state->user_record_count < MAX_HUB_USER_RECORDS) {
              found_u = &state->user_records[state->user_record_count++];
              memset(found_u,0,sizeof(*found_u));
              snprintf(found_u->uuid,sizeof(found_u->uuid),"%s",uuid);
            }
          }
          if (found_u && ts > found_u->timestamp) {
            snprintf(found_u->name,     sizeof(found_u->name),     "%s",uname);
            snprintf(found_u->password, sizeof(found_u->password), "%s",upass);
            found_u->type      = type;
            found_u->is_active = is_active;
            if (last_seen > found_u->last_seen) found_u->last_seen = last_seen;
            found_u->timestamp = ts;
            state->config_dirty = true;
            updates++;
            int w = snprintf(sync_buffer+sync_offset, sizeof(sync_buffer)-sync_offset,
                             "%c|%s|%s|%s|%s|%ld|%ld\n",
                             type, uuid, uname, upass, act, last_seen, ts);
            if (w>0) sync_offset += w;
          }
        }
      }
    } else if (type == 'p') {
      // Bot password: p|password|timestamp
      char pass[MAX_PASS];
      long ts = 0;
      int parsed = sscanf(data, "%127[^|]|%ld", pass, &ts);
      if (parsed < 1) {
        // Fallback: no delimiter found, treat entire data as password
        snprintf(pass, MAX_PASS, "%s", data);
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

    state->config_dirty = true;

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
    /* Skip local-only and entries now handled via typed arrays */
    if (strcmp(e->key, "h") == 0 || strcmp(e->key, "n") == 0 ||
        strcmp(e->key, "w") == 0 || strcmp(e->key, "x") == 0 ||
        strcmp(e->key, "a") == 0 || strcmp(e->key, "o") == 0 ||
        strcmp(e->key, "m") == 0)
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

  /* Include new-format user records so peer hubs share admin/oper records */
  for (int i = 0; i < state->user_record_count; i++) {
    hub_user_record_t *u = &state->user_records[i];
    if (max_len - offset <= 1) break;
    written = snprintf(buffer + offset, max_len - offset,
                       "%c|%s|%s|%s|%s|%ld|%ld\n",
                       u->type, u->uuid, u->name, u->password,
                       u->is_active ? "add" : "del",
                       (long)u->last_seen, (long)u->timestamp);
    if (written < 0 || written >= (max_len - offset)) break;
    offset += written;
  }
  /* Include new-format mask records */
  for (int i = 0; i < state->mask_record_count; i++) {
    hub_mask_record_t *m = &state->mask_records[i];
    if (max_len - offset <= 1) break;
    written = snprintf(buffer + offset, max_len - offset,
                       "m|%s|%s|%s|%ld|%ld\n",
                       m->uuid, m->mask,
                       m->is_active ? "add" : "del",
                       (long)m->last_used, (long)m->timestamp);
    if (written < 0 || written >= (max_len - offset)) break;
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
      char stored_first[1024], incoming_first[1024];
      const char *pipe = strchr(state->global_entries[i].value, '|');
      if (pipe) {
        size_t len = pipe - state->global_entries[i].value;
        if (len >= sizeof(stored_first))
          len = sizeof(stored_first) - 1;
        memcpy(stored_first, state->global_entries[i].value, len);
        stored_first[len] = 0;
      } else {
        snprintf(stored_first, sizeof(stored_first), "%s",
                 state->global_entries[i].value);
      }
      const char *incoming_pipe = strchr(value, '|');
      if (incoming_pipe) {
        size_t len = incoming_pipe - value;
        if (len >= sizeof(incoming_first))
          len = sizeof(incoming_first) - 1;
        memcpy(incoming_first, value, len);
        incoming_first[len] = 0;
      } else {
        snprintf(incoming_first, sizeof(incoming_first), "%s", value);
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
  int bot_push_updates = 0; /* only keys bots actually consume; gates full config push */
  char forward_buf[MAX_BUFFER];
  int fwd_offset = 0;
  forward_buf[0] = 0;

  while (line) {
    // Check for PURGE command
    if (strncmp(line, "PURGE|", 6) == 0) {
      long cutoff_val;
      if (sscanf(line + 6, "%ld", &cutoff_val) == 1) {
        time_t cutoff = (time_t)cutoff_val;
        hub_log("[MESH] Received PURGE from peer: cutoff=%ld\n", (long)cutoff);

        // DEDUPLICATION: Check if this PURGE was recently seen
        if (is_purge_recent(state, cutoff)) {
          hub_log("[MESH] PURGE cutoff=%ld already processed recently, skipping to prevent loop\n",
                  (long)cutoff);
        } else {
          // Record this PURGE and process it
          record_recent_purge(state, cutoff);

          char purge_log[MAX_BUFFER];
          int purged = hub_execute_purge(state, cutoff,
                                         purge_log, sizeof(purge_log));
          if (purged > 0) {
            hub_log("[MESH] Purged %d entries from peer sync\n", purged);
            updates += purged;
          }

          // Forward to all other peers (exclude sender to prevent immediate
          // echo; combined with deduplication prevents feedback loops).
          if (origin_fd != -1) {
            hub_broadcast_sync_to_peers(state, line, origin_fd);
          }
        }
      }
      line = strtok_r(NULL, "\n", &saveptr);
      continue;
    }

    /* Peer-forwarded invite request: invite|nick|#channel */
    if (strncmp(line, "invite|", 7) == 0) {
      char inv_nick[64], inv_chan[64];
      if (sscanf(line + 7, "%63[^|]|%63s", inv_nick, inv_chan) == 2) {
        hub_log("[MESH] Forwarded INVITE_REQUEST: invite %s into %s\n",
                inv_nick, inv_chan);
        /* Broadcast CMD_INVITE_REQUEST to our connected bots */
        unsigned char plain[MAX_BUFFER], inv_buf[MAX_BUFFER];
        unsigned char inv_tag[GCM_TAG_LEN];
        char inv_payload[160];
        int inv_pay_len = snprintf(inv_payload, sizeof(inv_payload),
                                   "%s|%s", inv_nick, inv_chan);
        plain[0] = (unsigned char)CMD_INVITE_REQUEST;
        uint32_t inv_net_pay = htonl((uint32_t)inv_pay_len);
        memcpy(&plain[1], &inv_net_pay, 4);
        memcpy(&plain[5], inv_payload, inv_pay_len);
        for (int i = 0; i < state->client_count; i++) {
          hub_client_t *bc = state->clients[i];
          if (bc->type == CLIENT_BOT && bc->authenticated) {
            int enc_len = aes_gcm_encrypt(plain, 5 + inv_pay_len,
                                          bc->session_key, inv_buf + 4,
                                          inv_tag);
            if (enc_len > 0) {
              memcpy(inv_buf + 4 + enc_len, inv_tag, GCM_TAG_LEN);
              uint32_t net_len = htonl((uint32_t)(enc_len + GCM_TAG_LEN));
              memcpy(inv_buf, &net_len, 4);
              if (write(bc->fd, inv_buf, 4 + enc_len + GCM_TAG_LEN) <= 0) {
                // write failed, continue to next client
              }
            }
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
            /* Detect new-format user/mask records by UUID in first value field.
             * New: a|uuid|name|pass|add/del|last_seen|ts  (7 pipe-fields)
             *      o|uuid|name|pass|add/del|last_seen|ts
             *      m|uuid|mask|add/del|last_used|ts        (6 pipe-fields)
             * Route these to typed arrays; old-format goes to global_entries. */
            bool is_user_key = (key[0]=='a' || key[0]=='o') && key[1]=='\0';
            bool is_mask_key = key[0]=='m' && key[1]=='\0';

            if (is_user_key || is_mask_key) {
              /* Check if first value field looks like a UUID */
              char *vstart = p1 + 1;
              char *vp1 = strchr(vstart, '|');
              char first_f[40] = {0};
              if (vp1) {
                size_t fl = (size_t)(vp1 - vstart);
                if (fl < sizeof(first_f)) { memcpy(first_f, vstart, fl); first_f[fl]=0; }
              }
              bool is_new_fmt = (strlen(first_f)==36 && first_f[8]=='-' &&
                                 first_f[13]=='-' && first_f[18]=='-' && first_f[23]=='-');

              if (is_new_fmt && is_user_key) {
                /* Parse: uuid|name|pass|add/del|last_seen|ts */
                char *pp1=vp1, *pp2=pp1?strchr(pp1+1,'|'):NULL;
                char *pp3=pp2?strchr(pp2+1,'|'):NULL, *pp4=pp3?strchr(pp3+1,'|'):NULL;
                char *pp5=pp4?strchr(pp4+1,'|'):NULL;
                if (pp1&&pp2&&pp3&&pp4&&pp5) {
                  char uuid[37], uname[64], upass[MAX_PASS], act[8];
                  long last_seen, ts;
                  snprintf(uuid,  sizeof(uuid),  "%.*s",(int)(pp1-vstart),vstart);
                  snprintf(uname, sizeof(uname), "%.*s",(int)(pp2-pp1-1),pp1+1);
                  snprintf(upass, sizeof(upass), "%.*s",(int)(pp3-pp2-1),pp2+1);
                  snprintf(act,   sizeof(act),   "%.*s",(int)(pp4-pp3-1),pp3+1);
                  last_seen = atol(pp4+1); ts = atol(pp5+1);
                  bool is_active = (strncmp(act,"add",3)==0);
                  hub_user_record_t *found_u = NULL;
                  for (int ui=0; ui<state->user_record_count; ui++)
                    if (strcmp(state->user_records[ui].uuid,uuid)==0)
                      { found_u=&state->user_records[ui]; break; }
                  bool discard_incoming = false;
                  if (!found_u) {
                    /* No UUID match — check for name collision before inserting */
                    for (int ni=0; ni<state->user_record_count; ni++) {
                      hub_user_record_t *ex = &state->user_records[ni];
                      if (ex->type == key[0] && strcasecmp(ex->name, uname) == 0) {
                        bool incoming_wins = (last_seen > ex->last_seen) ||
                            (last_seen == ex->last_seen && ts > ex->timestamp) ||
                            (last_seen == ex->last_seen && ts == ex->timestamp &&
                             strcmp(uuid, ex->uuid) < 0);
                        if (incoming_wins) {
                          hub_log("[MESH] Dedup: '%s' (%c) UUID collision resolved, adopting %s\n",
                                  uname, key[0], uuid);
                          /* Remap existing record's masks to the incoming UUID */
                          for (int mi=0; mi<state->mask_record_count; mi++)
                            if (strcmp(state->mask_records[mi].uuid, ex->uuid) == 0)
                              snprintf(state->mask_records[mi].uuid, 37, "%s", uuid);
                          /* Update the user record's own UUID so the next sync
                           * finds it by UUID lookup and skips the name collision path */
                          snprintf(ex->uuid, sizeof(ex->uuid), "%s", uuid);
                          state->config_dirty = true;
                          found_u = ex;
                        } else {
                          discard_incoming = true;
                        }
                        break;
                      }
                    }
                  }
                  if (!found_u && !discard_incoming &&
                      state->user_record_count < MAX_HUB_USER_RECORDS) {
                    found_u=&state->user_records[state->user_record_count++];
                    memset(found_u,0,sizeof(*found_u));
                    snprintf(found_u->uuid,sizeof(found_u->uuid),"%s",uuid);
                  }
                  if (!discard_incoming && found_u && ts > found_u->timestamp) {
                    snprintf(found_u->name,     sizeof(found_u->name),    "%s",uname);
                    snprintf(found_u->password, sizeof(found_u->password),"%s",upass);
                    found_u->type      = key[0];
                    found_u->is_active = is_active;
                    if (last_seen > found_u->last_seen) found_u->last_seen = last_seen;
                    found_u->timestamp = ts;
                    state->config_dirty = true;
                    updates++;
                    bot_push_updates++; /* admin/oper name change — bots need this */
                    if (fwd_offset < (int)sizeof(forward_buf) - 200) {
                      int w = snprintf(forward_buf+fwd_offset,
                                       sizeof(forward_buf)-fwd_offset,
                                       "%s\n", line);
                      if (w>0) fwd_offset += w;
                    }
                  }
                }
                line = strtok_r(NULL, "\n", &saveptr);
                continue;
              }

              if (is_new_fmt && is_mask_key) {
                /* Parse: uuid|mask|add/del|last_used|ts */
                char *pp1=vp1, *pp2=pp1?strchr(pp1+1,'|'):NULL;
                char *pp3=pp2?strchr(pp2+1,'|'):NULL, *pp4=pp3?strchr(pp3+1,'|'):NULL;
                if (pp1&&pp2&&pp3&&pp4) {
                  char uuid[37], mask_s[MAX_MASK_LEN], act[8];
                  long last_used, ts;
                  snprintf(uuid,   sizeof(uuid),   "%.*s",(int)(pp1-vstart),vstart);
                  snprintf(mask_s, sizeof(mask_s), "%.*s",(int)(pp2-pp1-1),pp1+1);
                  snprintf(act,    sizeof(act),    "%.*s",(int)(pp3-pp2-1),pp2+1);
                  last_used = atol(pp3+1); ts = atol(pp4+1);
                  bool is_active = (strncmp(act,"add",3)==0);
                  /* Reject masks for unknown user UUIDs */
                  bool uuid_known = false;
                  for (int ui=0; ui<state->user_record_count; ui++)
                    if (strcmp(state->user_records[ui].uuid,uuid)==0)
                      { uuid_known=true; break; }
                  if (!uuid_known) {
                    line = strtok_r(NULL, "\n", &saveptr);
                    continue;
                  }
                  hub_mask_record_t *found_m = NULL;
                  for (int mi=0; mi<state->mask_record_count; mi++)
                    if (strcmp(state->mask_records[mi].uuid,uuid)==0 &&
                        strcasecmp(state->mask_records[mi].mask,mask_s)==0)
                      { found_m=&state->mask_records[mi]; break; }
                  if (!found_m && state->mask_record_count < MAX_HUB_USER_MASKS) {
                    found_m=&state->mask_records[state->mask_record_count++];
                    memset(found_m,0,sizeof(*found_m));
                    snprintf(found_m->uuid,sizeof(found_m->uuid),"%s",uuid);
                    snprintf(found_m->mask,sizeof(found_m->mask),"%s",mask_s);
                  }
                  if (found_m && ts > found_m->timestamp) {
                    found_m->is_active = is_active;
                    if (last_used > found_m->last_used) found_m->last_used = last_used;
                    found_m->timestamp = ts;
                    state->config_dirty = true;
                    updates++;
                    bot_push_updates++; /* mask record — bots need this */
                    if (fwd_offset < (int)sizeof(forward_buf) - 200) {
                      int w = snprintf(forward_buf+fwd_offset,
                                       sizeof(forward_buf)-fwd_offset,
                                       "%s\n", line);
                      if (w>0) fwd_offset += w;
                    }
                  }
                }
                line = strtok_r(NULL, "\n", &saveptr);
                continue;
              }
            }

            /* Old-format or non-user global key: store in global_entries */
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
                  bot_push_updates++; /* channel/password/global — bots need this */
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
        /* seen/t entries are 3-field: b|uuid|key|timestamp (no value).
         * When p3 is NULL the timestamp sits at p2+1 and value is empty. */
        if (!p3 && (strcmp(p1 + 1, "seen") == 0 || strcmp(p1 + 1, "t") == 0)) {
          snprintf(uuid, sizeof(uuid), "%s", ptr);
          snprintf(key,  sizeof(key),  "%s", p1 + 1);
          val[0] = '\0';
          ts = atol(p2 + 1);
          if (hub_storage_update_entry(state, uuid, key, "", "", "", ts)) {
            updates++;
            if (sizeof(forward_buf) - fwd_offset > 200) {
              int w = snprintf(forward_buf + fwd_offset,
                               sizeof(forward_buf) - fwd_offset,
                               "b|%s|%s|%ld\n", uuid, key, ts);
              if (w > 0 && w < (int)(sizeof(forward_buf) - fwd_offset))
                fwd_offset += w;
            }
          }
          line = strtok_r(NULL, "\n", &saveptr);
          continue;
        }
        if (p3) {
          *p3 = 0;
          snprintf(uuid, sizeof(uuid), "%s", ptr);
          snprintf(key, sizeof(key), "%s", p1 + 1);
          snprintf(val, sizeof(val), "%s", p2 + 1);
          ts = atol(p3 + 1);

          // For c/m/o keys, parse the combined value format
          char parsed_val[512] = "", parsed_extra[256] = "", parsed_op[16] = "";
          if (strcmp(key, "c") == 0 || strcmp(key, "o") == 0) {
            /* Format: chan|key[|modes]|op  (3 or 4 fields)
             * Use first pipe for chan, last pipe for op, middle = extra */
            char *vp1 = strchr(val, '|');
            if (vp1) {
              *vp1 = 0;
              size_t len = strlen(val);
              if (len >= sizeof(parsed_val)) len = sizeof(parsed_val) - 1;
              memcpy(parsed_val, val, len);
              parsed_val[len] = 0;
              /* last pipe gives op (add/del), everything between = extra */
              char *last = strrchr(vp1 + 1, '|');
              if (last) {
                *last = 0;
                len = strlen(last + 1);
                if (len >= sizeof(parsed_op)) len = sizeof(parsed_op) - 1;
                memcpy(parsed_op, last + 1, len);
                parsed_op[len] = 0;
                /* extra = "key" or "key|modes" */
                len = strlen(vp1 + 1);
                if (len >= sizeof(parsed_extra)) len = sizeof(parsed_extra) - 1;
                memcpy(parsed_extra, vp1 + 1, len);
                parsed_extra[len] = 0;
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
            /* seen/t are hub-side metadata; bots don't consume them */
            if (strcmp(key, "seen") != 0 && strcmp(key, "t") != 0)
              bot_push_updates++;

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
    state->config_dirty = true;
    hub_log("[MESH] Synced %d entries from Peer (%d bot-relevant).\n",
            updates, bot_push_updates);

    if (fwd_offset > 0)
      hub_broadcast_sync_to_peers(state, forward_buf, origin_fd);

    if (bot_push_updates > 0)
      broadcast_full_config_to_all_bots(state);
  }
}

static bool send_response(hub_state_t *state, hub_client_t *client,
                          const char *msg) {
  int len = (int)strlen(msg);
  /* Allocate exactly what the wire frame needs: 4-byte length prefix +
   * GCM_IV_LEN-prefix ciphertext (same size as plaintext) + GCM tag.
   * Using the stack here caused overflows for large admin responses
   * (e.g. CMD_ADMIN_LIST_PEERS builds up to 65536-byte strings). */
  int buf_size = 4 + GCM_IV_LEN + len + GCM_TAG_LEN;
  unsigned char *buffer = malloc((size_t)buf_size);
  if (!buffer) {
    hub_disconnect_client(state, client);
    return false;
  }

  unsigned char tag[GCM_TAG_LEN];
  int enc_len = aes_gcm_encrypt((unsigned char *)msg, len, client->session_key,
                                buffer + 4, tag);
  if (enc_len <= 0) {
    free(buffer);
    hub_disconnect_client(state, client);
    return false;
  }
  memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
  uint32_t net_len = htonl((uint32_t)(enc_len + GCM_TAG_LEN));
  memcpy(buffer, &net_len, 4);
  bool ok = (write(client->fd, buffer, (size_t)(4 + enc_len + GCM_TAG_LEN)) ==
             (ssize_t)(4 + enc_len + GCM_TAG_LEN));
  free(buffer);
  if (!ok) {
    hub_disconnect_client(state, client);
    return false;
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
        (ssize_t)(4 + enc_len + GCM_TAG_LEN)) {
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

// Execute tombstone purge locally.
// cutoff == 0: purge all tombstones regardless of age.
// cutoff  > 0: purge tombstones whose timestamp is older than cutoff.
// Peer-hub propagation is the caller's responsibility.
int hub_execute_purge(hub_state_t *state, time_t cutoff,
                      char *log_out, int log_max_len) {
  int purged_count = 0;
  int log_offset = 0;

  if (log_out && log_max_len > 0) {
    log_out[0] = '\0';
  }

  // --- Purge tombstoned global entries (channels, admin masks, oper masks) ---
  config_entry_t new_entries[MAX_BOT_ENTRIES];
  int new_count = 0;

  for (int i = 0; i < state->global_entry_count; i++) {
    bool is_tombstone = false;

    if (strcmp(state->global_entries[i].key, "c") == 0 ||
        strcmp(state->global_entries[i].key, "m") == 0 ||
        strcmp(state->global_entries[i].key, "o") == 0) {
      const char *last_pipe = strrchr(state->global_entries[i].value, '|');
      if (last_pipe && strcmp(last_pipe + 1, "del") == 0) {
        is_tombstone = true;
      }
    }

    if (is_tombstone &&
        (cutoff == 0 || state->global_entries[i].timestamp < cutoff)) {
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
      if (new_count < MAX_BOT_ENTRIES) {
        memcpy(&new_entries[new_count++], &state->global_entries[i],
               sizeof(config_entry_t));
      }
    }
  }

  memcpy(state->global_entries, new_entries,
         sizeof(config_entry_t) * new_count);
  state->global_entry_count = new_count;

  // --- Purge tombstoned user_records (admins/opers) ---
  hub_user_record_t new_users[MAX_HUB_USER_RECORDS];
  int new_user_count = 0;
  for (int i = 0; i < state->user_record_count; i++) {
    if (!state->user_records[i].is_active &&
        (cutoff == 0 || state->user_records[i].timestamp < cutoff)) {
      purged_count++;
    } else {
      if (new_user_count < MAX_HUB_USER_RECORDS)
        new_users[new_user_count++] = state->user_records[i];
    }
  }
  memcpy(state->user_records, new_users, sizeof(hub_user_record_t) * new_user_count);
  state->user_record_count = new_user_count;

  // --- Purge tombstoned mask_records ---
  hub_mask_record_t new_masks[MAX_HUB_USER_MASKS];
  int new_mask_count = 0;
  for (int i = 0; i < state->mask_record_count; i++) {
    if (!state->mask_records[i].is_active &&
        (cutoff == 0 || state->mask_records[i].timestamp < cutoff)) {
      purged_count++;
    } else {
      if (new_mask_count < MAX_HUB_USER_MASKS)
        new_masks[new_mask_count++] = state->mask_records[i];
    }
  }
  memcpy(state->mask_records, new_masks, sizeof(hub_mask_record_t) * new_mask_count);
  state->mask_record_count = new_mask_count;

  // --- Purge tombstoned bots (d=1 entry present, regardless of is_active) ---
  // Heap-allocated: bot_config_t[MAX_BOTS] is ~6.8 MB, too large for the stack.
  bot_config_t *new_bots = malloc(sizeof(bot_config_t) * MAX_BOTS);
  if (!new_bots) {
    hub_log("[PURGE] malloc failed for new_bots\n");
    goto write_and_notify;
  }
  int new_bot_count = 0;

  for (int i = 0; i < state->bot_count; i++) {
    bot_config_t *b = &state->bots[i];
    bool purge_bot = false;

    time_t del_ts = 0;
    bool found_d1 = false;
    for (int j = 0; j < b->entry_count; j++) {
      if (strcmp(b->entries[j].key, "d") == 0 &&
          strcmp(b->entries[j].value, "1") == 0) {
        found_d1 = true;
        del_ts = b->entries[j].timestamp;
        break;
      }
    }
    if (found_d1 && (cutoff == 0 || (del_ts > 0 && del_ts < cutoff))) {
      purge_bot = true;
    }

    if (purge_bot) {
      purged_count++;
      if (log_out && log_max_len > 0) {
        char bot_nick[32] = "";
        for (int j = 0; j < b->entry_count; j++) {
          if (strcmp(b->entries[j].key, "n") == 0) {
            snprintf(bot_nick, sizeof(bot_nick), "%.*s",
                     (int)(sizeof(bot_nick) - 1), b->entries[j].value);
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
    } else {
      if (new_bot_count < MAX_BOTS) {
        memcpy(&new_bots[new_bot_count++], b, sizeof(bot_config_t));
      }
    }
  }

  memcpy(state->bots, new_bots, sizeof(bot_config_t) * new_bot_count);
  state->bot_count = new_bot_count;
  free(new_bots);

write_and_notify:
  state->config_dirty = true;

  // Notify locally-connected bots so they can purge their own lists.
  char purge_msg[64];
  snprintf(purge_msg, sizeof(purge_msg), "PURGE|%ld\n", (long)cutoff);
  hub_broadcast_config_to_bots(state, purge_msg);

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
          snprintf(nick, sizeof(nick), "%.*s",
                   (int)(sizeof(nick) - 1), bot->entries[i].value);
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
        state->config_dirty = true;

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
                            /* Use the peer's tracked fd directly — more reliable
                             * than IP matching which can fail with NAT/loopback. */
                            if (state->peers[p].fd > 0) {
                              remote_peer_fd = state->peers[p].fd;
                            } else {
                              /* Fallback: find client by IP */
                              for (int c = 0; c < state->client_count; c++) {
                                if (state->clients[c]->type == CLIENT_HUB &&
                                    state->clients[c]->authenticated &&
                                    strcmp(state->clients[c]->ip, state->peers[p].ip) == 0) {
                                  remote_peer_fd = state->clients[c]->fd;
                                  break;
                                }
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
        // Massive buffer needed for CMD_ADMIN_LIST_PEERS and LIST_BOTS matrices
        char *response = malloc(65536);
        if (!response) return send_response(state, client, "ERROR: Memory allocation failed");
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
              snprintf(response, 65536,
                       "SUCCESS|%s|AUTO-UPDATED (bot was connected)", nick);
            } else {
              hub_log("[ADMIN] Failed to send key to bot %s, falling back to manual\n", payload);
              hub_disconnect_client(state, bot_client);
              snprintf(response, 65536, "SUCCESS|%s|%s", nick, new_priv_b64);
            }
          } else {
            hub_log("[ADMIN] Encryption failed, falling back to manual key update\n");
            hub_disconnect_client(state, bot_client);
            snprintf(response, 65536, "SUCCESS|%s|%s", nick, new_priv_b64);
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
            snprintf(response, 65536, "SUCCESS|%s|%s", nick, new_priv_b64);
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
              /* Route rekey forward through URGENT (admin-initiated, time-sensitive). */
              (void)forward_plain; (void)forward_buffer; (void)forward_tag;
              if (peer_send_urgent(state, peer_hub, CMD_PEER_REKEY_BOT, forward_payload)) {
                hub_log("[ADMIN] Queued PEER_REKEY_BOT URGENT to peer hub for bot %s\n", payload);
                snprintf(response, 65536,
                         "SUCCESS|%s|AUTO-UPDATED (bot connected to peer hub)", nick);
              } else {
                hub_log("[ADMIN] Failed to queue rekey to peer, falling back to manual\n");
                snprintf(response, 65536, "SUCCESS|%s|%s", nick, new_priv_b64);
              }
            } else {
              hub_log("[ADMIN] Could not find peer hub client\n");
              snprintf(response, 65536, "SUCCESS|%s|%s", nick, new_priv_b64);
            }
          }
        } else {
          // Bot is not connected - return key for manual update
          hub_log("[ADMIN] Bot %s not connected, manual key update required\n", payload);
          snprintf(response, 65536, "SUCCESS|%s|%s", nick, new_priv_b64);
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
        free(response);

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

  case CMD_ADMIN_LIST_FULL: {
    /* Up to MAX_BOTS (100) entries × ~250 bytes each = ~25 KB; use 65536 to
     * be safe and consistent with other large-response admin commands. */
    const int LIST_FULL_SZ = 65536;
    char *response = malloc((size_t)LIST_FULL_SZ);
    if (!response) return send_response(state, client, "ERROR: OOM");
    int offset = 0;
    int written;

    int active_count = 0;
    for (int i = 0; i < state->bot_count; i++) {
      if (state->bots[i].is_active)
        active_count++;
    }

    written = snprintf(response + offset, LIST_FULL_SZ - offset,
                       "--- Registered Bots (%d) ---\n", active_count);
    if (written >= LIST_FULL_SZ - offset) {
      free(response);
      return send_response(state, client, "ERROR: Buffer overflow");
    }
    offset += written;

    for (int i = 0; i < state->bot_count; i++) {
      bot_config_t *b = &state->bots[i];
      if (!b->is_active)
        continue;

      // Get nickname
      char nick[32] = "Unknown";
      for (int k = 0; k < b->entry_count; k++) {
        if (strcmp(b->entries[k].key, "n") == 0) {
          snprintf(nick, sizeof(nick), "%.*s",
                   (int)(sizeof(nick) - 1), b->entries[k].value);
          break;
        }
      }

      // Check if bot is currently connected
      bool is_connected = false;
      char connected_to[128] = "N/A";

      /* Use "seen" entry timestamp as base — it's sync'd between hubs and
       * represents the most recent time this bot authenticated anywhere. */
      time_t last_seen = b->last_sync_time;
      for (int k = 0; k < b->entry_count; k++) {
        if (strcmp(b->entries[k].key, "seen") == 0) {
          if (b->entries[k].timestamp > last_seen)
            last_seen = b->entries[k].timestamp;
          break;
        }
      }

      for (int c = 0; c < state->client_count; c++) {
        if (state->clients[c]->type == CLIENT_BOT &&
            strcmp(state->clients[c]->id, b->uuid) == 0) {
          is_connected = true;
          snprintf(connected_to, sizeof(connected_to), "LOCAL (%s:%d)",
                   state->bind_ip, state->port);
          /* Live client value is the freshest source */
          if (state->clients[c]->last_seen > last_seen)
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
          snprintf(response + offset, LIST_FULL_SZ - offset,
                   "[%s] %-15s | Status: %-10s | Peer: %-20s | Last: %s\n",
                   b->uuid, nick, is_connected ? "CONNECTED" : "OFFLINE",
                   is_connected ? connected_to : "N/A", time_buf);

      if (written >= LIST_FULL_SZ - offset)
        break;
      offset += written;

      if (offset >= LIST_FULL_SZ - 100)
        break;
    }

    bool list_full_ret = send_response(state, client, response);
    free(response);
    return list_full_ret;
  }
  case CMD_ADMIN_APPROVE:
    if (payload && strlen(payload) > 0) {
      char target_uuid[64] = {0};

      if (strlen(payload) < 4) {
        int idx = atoi(payload);
        if (idx > 0 && idx <= state->pending_count) {
          snprintf(target_uuid, sizeof(target_uuid), "%s",
                   state->pending[idx - 1].uuid);
        } else {
          return send_response(state, client, "ERROR: Invalid Index.");
        }
      } else {
        snprintf(target_uuid, sizeof(target_uuid), "%s", payload);
      }

      if (target_uuid[0]) {
        time_t now = time(NULL);
        hub_storage_update_entry(state, target_uuid, "t", "", "", "", now);
        state->config_dirty = true;
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
      state->config_dirty = true;

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
      snprintf(nick, sizeof(nick), "%s", payload);
    } else {
      snprintf(nick, sizeof(nick), "UnnamedBot");
    }

    char *uuid = NULL, *priv_key = NULL, *pub_key = NULL;

    if (hub_crypto_generate_bot_creds(&uuid, &priv_key, &pub_key)) {
      hub_state_add_bot_memory(state, uuid, nick, pub_key);
      state->config_dirty = true;

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
    unsigned char priv64[64], pub64[64];
    if (hub_crypto_generate_combined_keypair(priv64, pub64)) {
      char *priv_b64 = base64_encode(priv64, 64);
      char *pub_b64  = base64_encode(pub64,  64);
      secure_wipe(priv64, 64);

      if (!priv_b64 || !pub_b64) {
        if (priv_b64) { secure_wipe(priv_b64, strlen(priv_b64)); free(priv_b64); }
        if (pub_b64)  free(pub_b64);
        return send_response(state, client, "ERROR: Base64 encoding failed.");
      }

      // Update in-memory state directly from the generated keys (priv64/pub64
      // are still available here; only the encoded base64 copies were made)
      hub_crypto_split_combined(pub64, state->hub_ed25519_pub, state->hub_x25519_pub);
      {
        unsigned char priv_raw[64];
        int dec_len = 0;
        unsigned char *dec = base64_decode(priv_b64, &dec_len);
        if (dec && dec_len == 64) {
          hub_crypto_split_combined(dec, state->hub_ed25519_priv, state->hub_x25519_priv);
          secure_wipe(dec, 64);
        }
        if (dec) free(dec);
        secure_wipe(priv_raw, 64);
      }
      state->hub_keys_loaded = true;

      broadcast_new_key(state, priv_b64, pub_b64);
      state->config_dirty = true;

      // Disconnect peer hubs so they reconnect with new key
      for (int i = 0; i < state->client_count; i++) {
        if (state->clients[i]->type == CLIENT_HUB) {
          hub_disconnect_client(state, state->clients[i]);
          i--;
        }
      }

      time_t now = time(NULL);
      struct tm *t = localtime(&now);
      char f[64];
      strftime(f, sizeof(f), "%Y%m%d%H%M_pub.b64", t);
      FILE *fp = fopen(f, "w");
      if (fp) { fprintf(fp, "%s", pub_b64); fclose(fp); }

      bool ok = send_response(state, client, pub_b64);
      secure_wipe(priv_b64, strlen(priv_b64));
      free(priv_b64); free(pub_b64);
      return ok;
    }
    return send_response(state, client, "ERROR: Key generation failed.");
  }

  case CMD_ADMIN_GET_PUBKEY: {
    if (!state->hub_keys_loaded)
      return send_response(state, client, "ERROR: No Key Available.");
    unsigned char pub64[64];
    memcpy(pub64,      state->hub_ed25519_pub, 32);
    memcpy(pub64 + 32, state->hub_x25519_pub,  32);
    char *pub_b64 = base64_encode(pub64, 64);
    if (!pub_b64) return send_response(state, client, "ERROR: Encoding failed.");
    bool ok = send_response(state, client, pub_b64);
    free(pub_b64);
    return ok;
  }

  case CMD_ADMIN_SET_PRIVKEY:
    if (payload && strlen(payload) >= COMBINED_KEY_B64) {
      int dec_len = 0;
      unsigned char *dec = base64_decode(payload, &dec_len);
      if (!dec || dec_len != 64) {
        if (dec) free(dec);
        return send_response(state, client, "ERROR: Invalid Curve25519 key (need 64-byte base64).");
      }
      // Validate: try loading each half
      EVP_PKEY *ep = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, dec, 32);
      EVP_PKEY *xp = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, dec + 32, 32);
      if (!ep || !xp) {
        if (ep) EVP_PKEY_free(ep);
        if (xp) EVP_PKEY_free(xp);
        secure_wipe(dec, 64); free(dec);
        return send_response(state, client, "ERROR: Invalid key material.");
      }
      EVP_PKEY_free(ep); EVP_PKEY_free(xp);
      hub_crypto_split_combined(dec, state->hub_ed25519_priv, state->hub_x25519_priv);

      // Derive public keys from private
      unsigned char pub64[64];
      size_t len = 32;
      EVP_PKEY *e2 = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, dec, 32);
      EVP_PKEY *x2 = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, dec + 32, 32);
      if (e2 && x2) {
        EVP_PKEY_get_raw_public_key(e2, pub64, &len);
        len = 32;
        EVP_PKEY_get_raw_public_key(x2, pub64 + 32, &len);
        memcpy(state->hub_ed25519_pub, pub64, 32);
        memcpy(state->hub_x25519_pub,  pub64 + 32, 32);
      }
      if (e2) EVP_PKEY_free(e2);
      if (x2) EVP_PKEY_free(x2);
      secure_wipe(dec, 64); free(dec);
      state->hub_keys_loaded = true;
      state->config_dirty = true;
      return send_response(state, client, "SUCCESS: Private Key Imported & Saved.");
    }
    return send_response(state, client, "ERROR: Empty or short payload.");

  case CMD_ADMIN_GET_PRIVKEY:
    if (state->hub_keys_loaded) {
      unsigned char priv64[64];
      memcpy(priv64,      state->hub_ed25519_priv, 32);
      memcpy(priv64 + 32, state->hub_x25519_priv,  32);
      char *priv_b64 = base64_encode(priv64, 64);
      secure_wipe(priv64, 64);
      if (!priv_b64) return send_response(state, client, "ERROR: Encoding failed.");
      bool ok = send_response(state, client, priv_b64);
      secure_wipe(priv_b64, strlen(priv_b64));
      free(priv_b64);
      return ok;
    }
    return send_response(state, client, "ERROR: No Private Key in Memory.");

  case CMD_ADMIN_SET_PUBKEY:
    if (payload && strlen(payload) >= COMBINED_KEY_B64) {
      int dec_len = 0;
      unsigned char *dec = base64_decode(payload, &dec_len);
      if (!dec || dec_len != 64) {
        if (dec) free(dec);
        return send_response(state, client, "ERROR: Invalid Curve25519 public key.");
      }
      hub_crypto_split_combined(dec, state->hub_ed25519_pub, state->hub_x25519_pub);
      free(dec);
      state->config_dirty = true;
      return send_response(state, client, "SUCCESS: Public Key Imported & Saved.");
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
          state->config_dirty = true;
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
        state->config_dirty = true;
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
    char *response_ptr = malloc(65536);
    if (!response_ptr) return send_response(state, client, "ERROR: Memory allocation failed");
    
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

    for (int i = 0; i < state->peer_count && count < 64; i++) {
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
              if (owner_uuid[0] && all_peers[k].uuid[0] &&
                  strcmp(all_peers[k].uuid, owner_uuid) == 0) {
                exists = true;
                break;
              }
              // Always also check IP:port — catches truncated/mismatched UUIDs
              if (all_peers[k].port == o_port &&
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
                    if (t_uuid[0] && all_peers[k].uuid[0] &&
                        strcmp(all_peers[k].uuid, t_uuid) == 0) {
                      t_exists = true;
                      break;
                    }
                    // Always also check IP:port — catches truncated/mismatched UUIDs
                    if (all_peers[k].port == t_port &&
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
        response_ptr + offset, 65536 - offset,
        "\n [M] MESH CONNECTION MATRIX        You are connected to peer 1\n");
    if (written < 0 || written >= (int)(65536 - offset)) {
      free(response_ptr);
      return send_response(state, client, "ERROR: Response buffer overflow");
    }
    offset += written;

    // Add 25 for the IP:Port column (21 chars + " | " = 24)
    int line_len = peer_col_width + 3 + 24 + (count * 5) + 15 + 10;

    for (int k = 0; k < line_len && offset < 65534; k++)
      response_ptr[offset++] = '-';
    if (offset >= 65534) {
      free(response_ptr);
      return send_response(state, client, "ERROR: Response buffer overflow");
    }
    response_ptr[offset++] = '\n';
    response_ptr[offset] = '\0';

    written = snprintf(response_ptr + offset, 65536 - offset, " %-*s | %-21s |",
                       peer_col_width, "Peer", "IP:Port");
    if (written < 0 || written >= (int)(65536 - offset)) {
      free(response_ptr);
      return send_response(state, client, "ERROR: Response buffer overflow");
    }
    offset += written;

    for (int i = 0; i < count; i++) {
      // CRITICAL FIX: Add overflow check in loop
      written = snprintf(response_ptr + offset, 65536 - offset,
                         " %-2d |", i + 1);
      if (written < 0 || written >= (int)(65536 - offset))
        break;
      offset += written;
    }

    // CRITICAL FIX: Add overflow check
    written = snprintf(response_ptr + offset, 65536 - offset,
                       " Mesh State    | Bots |\n");
    if (written < 0 || written >= (int)(65536 - offset)) {
      free(response_ptr);
      return send_response(state, client, "ERROR: Response buffer overflow");
    }
    offset += written;

    // CRITICAL FIX: Bounds check for line drawing
    for (int k = 0; k < line_len && offset < 65535; k++) {
      response_ptr[offset++] = '-';
    }
    if (offset >= 65535) {
      free(response_ptr);
      return send_response(state, client, "ERROR: Response buffer overflow");
    }
    response_ptr[offset++] = '\n';
    response_ptr[offset] = '\0';

    int issues = 0;
    char issue_log[MAX_BUFFER];
    memset(issue_log, 0, sizeof(issue_log));
    int issue_off = 0;
    
    // Allocate exactly what we need on the heap to avoid a 1MB Stack Overflow
    typedef char mismatch_string[MAX_BUFFER];
    mismatch_string *reported_mismatches = calloc(64, sizeof(mismatch_string));
    if (!reported_mismatches) {
        free(response_ptr);
        return send_response(state, client, "ERROR: Memory allocation failed for mismatches");
    }
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
      written = snprintf(response_ptr + offset, 65536 - offset,
                         " %d. %-*s | %-21s |", row + 1, peer_col_width - 3, peer_str, ip_port_str);
      if (written < 0 || written >= (int)(65536 - offset)) {
        free(response_ptr);
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

        written = snprintf(response_ptr + offset, 65536 - offset, " %s |", cell);
        if (written < 0 || written >= (int)(65536 - offset)) {
          free(reported_mismatches);
          free(response_ptr);
          return send_response(state, client, "ERROR: Matrix too large for buffer");
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
          written = snprintf(response_ptr + offset, 65536 - offset,
                             " %d/%d Connected |", row_connected, row_total);
        } else {
          // Show as "Offline" only if not directly connected
          if (directly_connected) {
            // CRITICAL FIX: Add overflow check
            written = snprintf(response_ptr + offset, 65536 - offset,
                               " 0/%d Partial   |", row_total);
          } else {
            // CRITICAL FIX: Add overflow check
            written = snprintf(response_ptr + offset, 65536 - offset,
                               " \033[31mOffline\033[0m       |");
            is_offline = true;
            issues++;
          }
        }
      } else {
        if (all_peers[row].is_me) {
          // CRITICAL FIX: Add overflow check
          written = snprintf(response_ptr + offset, 65536 - offset,
                             " ---          |");
        } else if (directly_connected) {
          // Directly connected but no peer mesh info yet
          // CRITICAL FIX: Add overflow check
          written = snprintf(response_ptr + offset, 65536 - offset,
                             " Connected     |");
        } else {
          // CRITICAL FIX: Add overflow check
          written = snprintf(response_ptr + offset, 65536 - offset,
                             " \033[31mOffline\033[0m       |");
          is_offline = true;
          issues++;
        }
      }

      // CRITICAL FIX: Check the write result
      if (written < 0 || written >= (int)(65536 - offset)) {
        free(response_ptr);
        return send_response(state, client,
                             "ERROR: Matrix too large for buffer");
      }
      offset += written;

      if (is_offline) {
        // CRITICAL FIX: Add overflow check
        written =
            snprintf(response_ptr + offset, 65536 - offset, " ??   |\n");
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
        written = snprintf(response_ptr + offset, 65536 - offset,
                           " %-4d |\n", bot_cnt);
      }

      if (written < 0 || written >= (int)(65536 - offset)) {
        free(reported_mismatches);
        free(response_ptr);
        return send_response(state, client, "ERROR: Matrix too large for buffer");
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

    for (int k = 0; k < line_len && offset < 65534; k++)
      response_ptr[offset++] = '-';
    if (offset >= 65534) {
      free(reported_mismatches);
      free(response_ptr);
      return send_response(state, client, "ERROR: Response buffer overflow");
    }
    response_ptr[offset++] = '\n';
    response_ptr[offset] = '\0';

    char status_str[128];
    if (issues == 0) {
      // Show HEALTHY if no issues, regardless of peer count
      snprintf(status_str, 64, "\033[32mHEALTHY\033[0m");
    } else {
      snprintf(status_str, 64, "\033[33mDEGRADED (%d ISSUES)\033[0m", issues);
    }

    written = snprintf(response_ptr + offset, 65536 - offset,
                       " [i] MESH STATUS: %s\n [Legend: -- = Self, UP = "
                       "Connected, DN = Down, ?? = Unknown/Not Configured]\n",
                       status_str);
    if (written < 0 || written >= (int)(65536 - offset)) {
      free(reported_mismatches);
      free(response_ptr);
      return send_response(state, client, "ERROR: Response buffer overflow");
    }
    offset += written;

    if (issues > 0) {
      // CRITICAL FIX: Add overflow check
      written = snprintf(response_ptr + offset, 65536 - offset,
                         " --- Mesh Diagnostics ---\n%s", issue_log);
      if (written < 0 || written >= (int)(65536 - offset)) {
        free(reported_mismatches);
        free(response_ptr);
        return send_response(state, client, "ERROR: Response buffer overflow");
      }
      offset += written;
    }

    bool result = send_response(state, client, response_ptr);
    free(reported_mismatches);
    free(response_ptr);
    return result;
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
        state->config_dirty = true;

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
      state->config_dirty = true;

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
      state->config_dirty = true;

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
      state->config_dirty = true;

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
        state->config_dirty = true;

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
      state->config_dirty = true;

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
      state->config_dirty = true;

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
      state->config_dirty = true;

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
        /* Stamp origin_ts now and mark seen locally so any loop-back is dropped. */
        time_t admin_origin_ts = time(NULL);
        op_forward_seen_check_and_add(state, request_id);
        forward_op_request_to_peers(state, request_id, "ADMIN", "ANY", admin_payload, "", -1, admin_origin_ts);

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
    // Payload: "immediate" -> cutoff=0 (purge all)
    //          "<N>" (days)  -> cutoff = now - N*86400
    time_t now = time(NULL);
    time_t cutoff = 0; // default: purge everything
    int days_label = 0;

    if (payload && strlen(payload) > 0 && strcmp(payload, "immediate") != 0) {
      int days = atoi(payload);
      if (days > 0) {
        cutoff = now - ((time_t)days * 86400);
        days_label = days;
      }
    }

    char purge_log[MAX_BUFFER / 2];
    int purged_count = hub_execute_purge(state, cutoff,
                                          purge_log, sizeof(purge_log));

    // Broadcast PURGE|<cutoff> to all peer hubs.
    char peer_purge_msg[64];
    snprintf(peer_purge_msg, sizeof(peer_purge_msg), "PURGE|%ld\n", (long)cutoff);
    hub_broadcast_sync_to_peers(state, peer_purge_msg, -1);

    // Report what happened locally; peers purge asynchronously.
    if (purged_count > 0) {
      snprintf(response, sizeof(response),
               "SUCCESS: Purged %d local tombstone(s), purge broadcast sent to peers\n%.*s",
               purged_count, (int)(sizeof(response) - 100), purge_log);
    } else if (days_label > 0) {
      snprintf(response, sizeof(response),
               "SUCCESS: No local tombstones older than %d days found, purge broadcast sent to peers",
               days_label);
    } else {
      snprintf(response, sizeof(response),
               "SUCCESS: No local tombstones found, purge broadcast sent to peers");
    }

    return send_response(state, client, response);
  }

  case CMD_ADMIN_SET_PURGE_DAYS: {
    if (payload && strlen(payload) > 0) {
      int days = atoi(payload);
      if (days < 0) days = 0;  // 0 = disabled

      state->purge_days_setting = days;
      state->config_dirty = true;

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
      snprintf(state->bind_ip, sizeof(state->bind_ip), "%s", payload);

      // Save to config
      state->config_dirty = true;

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
      snprintf(state->hub_friendly_name, sizeof(state->hub_friendly_name), "%s", payload);

      // Save to config
      state->config_dirty = true;

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
      state->config_dirty = true;

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
                snprintf(pattern, sizeof(pattern), "%.*s",
                         (int)(sizeof(pattern) - 1), state->global_entries[i].value);
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
        state->config_dirty = true;

        // NOTE: Allowlist is local-only, do not broadcast to peers

        return send_response(state, client, "SUCCESS: IP added to allowlist.");
    }
    return send_response(state, client, "ERROR: Missing IP pattern.");
  }

  case CMD_ADMIN_DEL_ALLOWLIST: {
    if (payload && strlen(payload) > 0) {
        time_t now = time(NULL);
        hub_storage_update_global_entry(state, "w", payload, "", "del", now);
        state->config_dirty = true;

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
                snprintf(pattern, sizeof(pattern), "%.*s",
                         (int)(sizeof(pattern) - 1), state->global_entries[i].value);
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
        state->config_dirty = true;

        // NOTE: Denylist is local-only, do not broadcast to peers

        return send_response(state, client, "SUCCESS: IP added to denylist.");
    }
    return send_response(state, client, "ERROR: Missing IP pattern.");
  }

  case CMD_ADMIN_DEL_DENYLIST: {
    if (payload && strlen(payload) > 0) {
        time_t now = time(NULL);
        hub_storage_update_global_entry(state, "x", payload, "", "del", now);
        state->config_dirty = true;

        // NOTE: Denylist is local-only, do not broadcast to peers

        return send_response(state, client, "SUCCESS: IP removed from denylist.");
    }
    return send_response(state, client, "ERROR: Missing IP pattern.");
  }

        case CMD_ADMIN_SET_LOG_LEVEL: {
            size_t len = payload ? strlen(payload) : 0;
            if (len < 1) {
                send_response(state, client, "ERR:invalid payload");
                break;
            }
            int level = (unsigned char)payload[0];
            if (level > LOG_DEBUG) level = LOG_DEBUG;
            if (level < LOG_NONE) level = LOG_NONE;
            state->log_level = level;
            char msg[64];
            snprintf(msg, sizeof(msg), "OK:log_level set to %d", level);
            send_response(state, client, msg);
            break;
        }

        case CMD_ADMIN_SET_LOG_SIZE: {
            size_t len = payload ? strlen(payload) : 0;
            if (len < 4) {
                send_response(state, client, "ERR:invalid payload");
                break;
            }
            // Payload: 4 bytes in network byte order (big-endian)
            uint32_t size;
            memcpy(&size, payload, 4);
            size = ntohl(size);
            if (size < 1024) size = 1024;  // Minimum 1KB
            if (size > 1024*1024*1024) size = 1024*1024*1024;  // Maximum 1GB
            state->log_max_size = (int)size;
            char msg[64];
            snprintf(msg, sizeof(msg), "OK:log_size set to %d", state->log_max_size);
            send_response(state, client, msg);
            break;
        }

  /* ================================================================
   * Named Admin/Oper/Usermask commands (v2)
   * ================================================================ */

  case CMD_ADMIN_LIST_ADMINS:
  case CMD_ADMIN_LIST_OPERS_V2: {
    char type_ch = (cmd == CMD_ADMIN_LIST_ADMINS) ? 'a' : 'o';
    const char *label = (cmd == CMD_ADMIN_LIST_ADMINS) ? "admins" : "opers";
    char buf[8192];
    int off = 0;
    int name_w = 8;
    for (int i = 0; i < state->user_record_count; i++) {
      hub_user_record_t *u = &state->user_records[i];
      if (u->type != type_ch || !u->is_active) continue;
      int nl = (int)strlen(u->name);
      if (nl > name_w) name_w = nl;
    }
    off += snprintf(buf + off, sizeof(buf) - off,
                    "| irchub %s\n+%s\n",
                    label,
                    "----------------------------------------------------------------------------");
    int shown = 0;
    for (int i = 0; i < state->user_record_count; i++) {
      hub_user_record_t *u = &state->user_records[i];
      if (u->type != type_ch || !u->is_active) continue;
      char ts_buf[48];
      if (u->last_seen == 0) {
        snprintf(ts_buf, sizeof(ts_buf), "never");
      } else {
        struct tm *t = gmtime(&u->last_seen);
        strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S UTC", t);
      }
      off += snprintf(buf + off, sizeof(buf) - off,
                      "| %-*s  (last seen: %s)\n", name_w, u->name, ts_buf);
      /* List active masks */
      for (int j = 0; j < state->mask_record_count; j++) {
        hub_mask_record_t *m = &state->mask_records[j];
        if (strcmp(m->uuid, u->uuid) != 0 || !m->is_active) continue;
        off += snprintf(buf + off, sizeof(buf) - off,
                        "|   %s\n", m->mask);
        if (off >= (int)sizeof(buf) - 128) break;
      }
      shown++;
      if (off >= (int)sizeof(buf) - 128) break;
    }
    if (shown == 0)
      off += snprintf(buf + off, sizeof(buf) - off, "| (none)\n");
    off += snprintf(buf + off, sizeof(buf) - off,
                    "`%s",
                    "----------------------------------------------------------------------------");
    return send_response(state, client, buf);
  }

  case CMD_ADMIN_ADD_ADMIN:
  case CMD_ADMIN_ADD_OPER_RECORD: {
    if (!payload || !*payload)
      return send_response(state, client, "ERR:missing payload");
    char pname[64], ppass[MAX_PASS], pmask[MAX_MASK_LEN];
    if (sscanf(payload, "%63[^|]|%127[^|]|%255s", pname, ppass, pmask) < 3)
      return send_response(state, client, "ERR:syntax name|password|mask");
    /* Validate name: no pipes, printable, reasonable length */
    if (!pname[0] || strchr(pname,'|'))
      return send_response(state, client, "ERR:invalid name");
    /* Validate mask format */
    if (!strchr(pmask,'!') || !strchr(pmask,'@'))
      return send_response(state, client, "ERR:mask must contain ! and @");
    /* Check name uniqueness across all a|/o| records */
    for (int i = 0; i < state->user_record_count; i++) {
      if (state->user_records[i].is_active &&
          strcasecmp(state->user_records[i].name, pname) == 0)
        return send_response(state, client, "ERR:name already exists");
    }
    if (state->user_record_count >= MAX_HUB_USER_RECORDS)
      return send_response(state, client, "ERR:user record table full");
    if (state->mask_record_count >= MAX_HUB_USER_MASKS)
      return send_response(state, client, "ERR:mask record table full");
    time_t now = time(NULL);
    char new_uuid[37];
    generate_uuid_v4(new_uuid, sizeof(new_uuid));
    hub_user_record_t *u = &state->user_records[state->user_record_count++];
    memset(u, 0, sizeof(*u));
    snprintf(u->uuid,     sizeof(u->uuid),     "%s", new_uuid);
    snprintf(u->name,     sizeof(u->name),     "%s", pname);
    snprintf(u->password, sizeof(u->password), "%s", ppass);
    u->type      = (cmd == CMD_ADMIN_ADD_ADMIN) ? 'a' : 'o';
    u->is_active = true;
    u->last_seen = 0;
    u->timestamp = now;
    hub_mask_record_t *m = &state->mask_records[state->mask_record_count++];
    memset(m, 0, sizeof(*m));
    snprintf(m->uuid, sizeof(m->uuid), "%s", new_uuid);
    snprintf(m->mask, sizeof(m->mask), "%s", pmask);
    m->is_active = true;
    m->last_used = 0;
    m->timestamp = now;
    state->config_dirty = true;
    /* Broadcast new records to bots */
    char sync[MAX_BUFFER];
    snprintf(sync, sizeof(sync), "%c|%s|%s|%s|add|0|%ld\n",
             u->type, u->uuid, u->name, u->password, (long)now);
    hub_broadcast_config_to_bots(state, sync);
    hub_broadcast_sync_to_peers(state, sync, -1);
    snprintf(sync, sizeof(sync), "m|%s|%s|add|0|%ld\n",
             m->uuid, m->mask, (long)now);
    hub_broadcast_config_to_bots(state, sync);
    hub_broadcast_sync_to_peers(state, sync, -1);
    char resp[512];
    snprintf(resp, sizeof(resp), "SUCCESS: %s %s added with mask %s",
             (u->type == 'a') ? "Admin" : "Oper", pname, pmask);
    return send_response(state, client, resp);
  }

  case CMD_ADMIN_DEL_ADMIN:
  case CMD_ADMIN_DEL_OPER_RECORD: {
    if (!payload || !*payload)
      return send_response(state, client, "ERR:missing name");
    hub_user_record_t *target = NULL;
    for (int i = 0; i < state->user_record_count; i++) {
      if (state->user_records[i].is_active &&
          strcasecmp(state->user_records[i].name, payload) == 0) {
        target = &state->user_records[i];
        break;
      }
    }
    if (!target)
      return send_response(state, client, "ERR:user not found");
    time_t now = time(NULL);
    target->is_active = false;
    /* Soft-delete all masks owned by this uuid */
    for (int i = 0; i < state->mask_record_count; i++) {
      if (strcmp(state->mask_records[i].uuid, target->uuid) == 0)
        state->mask_records[i].is_active = false;
    }
    state->config_dirty = true;
    /* Broadcast tombstone */
    char sync[MAX_BUFFER];
    snprintf(sync, sizeof(sync), "%c|%s|%s|%s|del|%ld|%ld\n",
             target->type, target->uuid, target->name, target->password,
             (long)target->last_seen, (long)now);
    hub_broadcast_config_to_bots(state, sync);
    hub_broadcast_sync_to_peers(state, sync, -1);
    char resp[512];
    snprintf(resp, sizeof(resp), "SUCCESS: %s removed", payload);
    return send_response(state, client, resp);
  }

  case CMD_ADMIN_ADD_USERMASK: {
    if (!payload || !*payload)
      return send_response(state, client, "ERR:missing payload");
    char pname[64], pmask[MAX_MASK_LEN];
    if (sscanf(payload, "%63[^|]|%255s", pname, pmask) < 2)
      return send_response(state, client, "ERR:syntax name|mask");
    if (!strchr(pmask,'!') || !strchr(pmask,'@'))
      return send_response(state, client, "ERR:mask must contain ! and @");
    hub_user_record_t *target = NULL;
    for (int i = 0; i < state->user_record_count; i++) {
      if (state->user_records[i].is_active &&
          strcasecmp(state->user_records[i].name, pname) == 0) {
        target = &state->user_records[i];
        break;
      }
    }
    if (!target)
      return send_response(state, client, "ERR:user not found");
    /* Check for duplicate active mask */
    for (int i = 0; i < state->mask_record_count; i++) {
      if (state->mask_records[i].is_active &&
          strcmp(state->mask_records[i].uuid, target->uuid) == 0 &&
          strcasecmp(state->mask_records[i].mask, pmask) == 0)
        return send_response(state, client, "ERR:mask already exists");
    }
    if (state->mask_record_count >= MAX_HUB_USER_MASKS)
      return send_response(state, client, "ERR:mask table full");
    time_t now = time(NULL);
    char tuuid_add[37];
    snprintf(tuuid_add, sizeof(tuuid_add), "%s", target->uuid);
    hub_mask_record_t *m = &state->mask_records[state->mask_record_count++];
    memset(m, 0, sizeof(*m));
    snprintf(m->uuid, sizeof(m->uuid), "%s", tuuid_add);
    snprintf(m->mask, sizeof(m->mask), "%s", pmask);
    m->is_active = true;
    m->last_used = 0;
    m->timestamp = now;
    state->config_dirty = true;
    char sync[MAX_BUFFER];
    snprintf(sync, sizeof(sync), "m|%s|%s|add|0|%ld\n", m->uuid, m->mask, (long)now);
    hub_broadcast_config_to_bots(state, sync);
    hub_broadcast_sync_to_peers(state, sync, -1);
    char resp[512];
    snprintf(resp, sizeof(resp), "SUCCESS: mask %s added to %s", pmask, pname);
    return send_response(state, client, resp);
  }

  case CMD_ADMIN_DEL_USERMASK: {
    if (!payload || !*payload)
      return send_response(state, client, "ERR:missing payload");
    char pname[64], pmask[MAX_MASK_LEN];
    if (sscanf(payload, "%63[^|]|%255s", pname, pmask) < 2)
      return send_response(state, client, "ERR:syntax name|mask");
    hub_user_record_t *target = NULL;
    for (int i = 0; i < state->user_record_count; i++) {
      if (state->user_records[i].is_active &&
          strcasecmp(state->user_records[i].name, pname) == 0) {
        target = &state->user_records[i];
        break;
      }
    }
    if (!target)
      return send_response(state, client, "ERR:user not found");
    hub_mask_record_t *found = NULL;
    for (int i = 0; i < state->mask_record_count; i++) {
      if (state->mask_records[i].is_active &&
          strcmp(state->mask_records[i].uuid, target->uuid) == 0 &&
          strcasecmp(state->mask_records[i].mask, pmask) == 0) {
        found = &state->mask_records[i];
        break;
      }
    }
    if (!found)
      return send_response(state, client, "ERR:mask not found");
    time_t now = time(NULL);
    found->is_active = false;
    state->config_dirty = true;
    char sync[MAX_BUFFER];
    snprintf(sync, sizeof(sync), "m|%s|%s|del|%ld|%ld\n",
             found->uuid, found->mask, (long)found->last_used, (long)now);
    hub_broadcast_config_to_bots(state, sync);
    hub_broadcast_sync_to_peers(state, sync, -1);
    char resp[512];
    snprintf(resp, sizeof(resp), "SUCCESS: mask %s removed from %s", pmask, pname);
    return send_response(state, client, resp);
  }

  case CMD_ADMIN_SET_USERPASS: {
    if (!payload || !*payload)
      return send_response(state, client, "ERR:missing payload");
    char pname[64], ppass[MAX_PASS];
    if (sscanf(payload, "%63[^|]|%127s", pname, ppass) < 2)
      return send_response(state, client, "ERR:syntax name|newpassword");
    hub_user_record_t *target = NULL;
    for (int i = 0; i < state->user_record_count; i++) {
      if (state->user_records[i].is_active &&
          strcasecmp(state->user_records[i].name, pname) == 0) {
        target = &state->user_records[i];
        break;
      }
    }
    if (!target)
      return send_response(state, client, "ERR:user not found");
    snprintf(target->password, sizeof(target->password), "%s", ppass);
    state->config_dirty = true;
    /* Push updated record to bots — copy fields first to avoid restrict alias */
    char sync[MAX_BUFFER];
    char ttype = target->type, tuuid[37], tname[64], tpass[MAX_PASS];
    snprintf(tuuid,  sizeof(tuuid),  "%s", target->uuid);
    snprintf(tname,  sizeof(tname),  "%s", target->name);
    snprintf(tpass,  sizeof(tpass),  "%s", target->password);
    snprintf(sync, sizeof(sync), "%c|%s|%s|%s|%s|%ld|%ld\n",
             ttype, tuuid, tname, tpass,
             target->is_active ? "add" : "del",
             (long)target->last_seen, (long)target->timestamp);
    hub_broadcast_config_to_bots(state, sync);
    hub_broadcast_sync_to_peers(state, sync, -1);
    char resp[512];
    snprintf(resp, sizeof(resp), "SUCCESS: password changed for %s", pname);
    return send_response(state, client, resp);
  }

  case CMD_ADMIN_MATCH: {
    if (!payload || !*payload)
      return send_response(state, client, "ERR:missing name");
    bool match_all = (strcmp(payload, "*") == 0);
    char buf[MAX_BUFFER];
    int off = 0;
    int name_w = 8;
    for (int i = 0; i < state->user_record_count; i++) {
      hub_user_record_t *u = &state->user_records[i];
      if (!u->is_active) continue;
      if (!match_all && strcasecmp(u->name, payload) != 0) continue;
      int nl = (int)strlen(u->name);
      if (nl > name_w) name_w = nl;
    }
    off += snprintf(buf + off, sizeof(buf) - off,
                    "| irchub match%s\n+%s\n",
                    match_all ? " *" : "",
                    "----------------------------------------------------------------------------");
    int shown = 0;
    for (int i = 0; i < state->user_record_count; i++) {
      hub_user_record_t *u = &state->user_records[i];
      if (!u->is_active) continue;
      if (!match_all && strcasecmp(u->name, payload) != 0) continue;
      char ts_buf[48];
      if (u->last_seen == 0) {
        snprintf(ts_buf, sizeof(ts_buf), "never");
      } else {
        struct tm *t = gmtime(&u->last_seen);
        strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S UTC", t);
      }
      off += snprintf(buf + off, sizeof(buf) - off,
                      "| [%c] %-*s  (last seen: %s)\n",
                      u->type, name_w, u->name, ts_buf);
      for (int j = 0; j < state->mask_record_count; j++) {
        hub_mask_record_t *m = &state->mask_records[j];
        if (strcmp(m->uuid, u->uuid) != 0 || !m->is_active) continue;
        char used_buf[48];
        if (m->last_used == 0) {
          snprintf(used_buf, sizeof(used_buf), "never");
        } else {
          struct tm *tu = gmtime(&m->last_used);
          strftime(used_buf, sizeof(used_buf), "%Y-%m-%d %H:%M:%S UTC", tu);
        }
        off += snprintf(buf + off, sizeof(buf) - off,
                        "|   %s  (last used: %s)\n", m->mask, used_buf);
        if (off >= (int)sizeof(buf) - 128) break;
      }
      shown++;
      if (off >= (int)sizeof(buf) - 128) break;
    }
    if (shown == 0)
      off += snprintf(buf + off, sizeof(buf) - off, "| unknown user\n");
    off += snprintf(buf + off, sizeof(buf) - off,
                    "`%s",
                    "----------------------------------------------------------------------------");
    return send_response(state, client, buf);
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

/* Check if we have already processed this OP_FORWARD request_id.
 * Returns true (already seen — caller should drop the packet).
 * Returns false (first time — inserts into the LRU ring and caller processes).
 * Thread-safety: single-threaded event loop, no lock needed. */
static bool op_forward_seen_check_and_add(hub_state_t *state,
                                           const char *request_id) {
  /* Scan for existing entry. */
  for (int i = 0; i < MAX_SEEN_FORWARD_IDS; i++) {
    if (state->seen_forwards[i].request_id[0] != '\0' &&
        strcmp(state->seen_forwards[i].request_id, request_id) == 0) {
      return true; /* already seen */
    }
  }
  /* Not found — insert at ring head position and advance. */
  int slot = state->seen_forward_head;
  snprintf(state->seen_forwards[slot].request_id,
           sizeof(state->seen_forwards[slot].request_id), "%s", request_id);
  state->seen_forwards[slot].seen_at = time(NULL);
  state->seen_forward_head = (slot + 1) % MAX_SEEN_FORWARD_IDS;
  return false; /* first time seeing this */
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
                                         const char *channel,
                                         const char *requester_hostmask,
                                         int exclude_fd,
                                         time_t origin_ts) {
  /* Payload format (6 fields):
   *   request_id|requester_uuid|target_uuid|channel|requester_hostmask|origin_ts
   * The trailing origin_ts field is new; old hub peers parse sscanf with a
   * fixed count and will simply ignore it — wire-backwards-compatible. */
  char forward_payload[680];
  snprintf(forward_payload, sizeof(forward_payload), "%s|%s|%s|%s|%s|%ld",
           request_id, requester_uuid, target_uuid, channel,
           requester_hostmask ? requester_hostmask : "",
           (long)(origin_ts > 0 ? origin_ts : time(NULL)));

  int queued_count = 0;
  /* Route through URGENT lane — op grants must not be delayed by BULK sync. */
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type == CLIENT_HUB && c->authenticated && c->fd != exclude_fd) {
      if (!peer_send_urgent(state, c, CMD_OP_FORWARD_REQUEST, forward_payload)) {
        hub_log("[HUB] URGENT queue full forwarding OP_REQUEST to peer fd=%d — disconnecting\n",
                c->fd);
        hub_disconnect_client(state, c);
        i--;
        continue;
      }
      queued_count++;
      if (state->log_level >= LOG_DEBUG)
        hub_log("[DEBUG] [HUB] Queued OP_FORWARD_REQUEST (id:%s) URGENT to peer fd=%d\n",
              request_id, c->fd);
    }
  }
  if (queued_count > 0)
    hub_log("[HUB] Forwarded OP_FORWARD_REQUEST (id:%s) to %d peer(s)\n",
            request_id, queued_count);
}

// ========== End OP Request Forwarding Helper Functions ==========

// ========== Handlers for Forwarded OP Commands from Peer Hubs ==========

static void process_forward_op_request(hub_state_t *state,
                                        hub_client_t *client, char *payload) {
  /* Payload format (6 fields, 6th is new and optional for old senders):
   *   request_id|requester_uuid|target_uuid|channel|requester_hostmask|origin_ts */
  char request_id[64], requester_uuid[64], target_uuid[64], channel[MAX_CHAN];
  char carried_hostmask[MAX_MASK_LEN] = "";
  long origin_ts = 0;

  int parsed = sscanf(payload,
                      "%63[^|]|%63[^|]|%63[^|]|%64[^|]|%255[^|]|%ld",
                      request_id, requester_uuid, target_uuid, channel,
                      carried_hostmask, &origin_ts);
  if (parsed < 4) {
    hub_log("[HUB] Invalid OP_FORWARD_REQUEST payload from peer fd=%d\n",
            client->fd);
    return;
  }

  /* ================================================================
   * DUPLICATE / STORM GUARD
   * Check TTL first (cheap), then seen-set (LRU ring scan).
   * Both checks are O(MAX_SEEN_FORWARD_IDS) = O(256) — negligible.
   * ================================================================ */

  /* 1. TTL: drop requests that are too old to be worth servicing. */
  if (origin_ts > 0) {
    long age = (long)(time(NULL) - (time_t)origin_ts);
    if (age > OP_FORWARD_TTL_SECONDS) {
      if (state->log_level >= LOG_DEBUG)
        hub_log("[DEBUG] [HUB] Dropping expired OP_FORWARD_REQUEST (id:%s, age=%lds > %ds TTL)\n",
                request_id, age, OP_FORWARD_TTL_SECONDS);
      return;
    }
  }

  /* 2. Dedup: drop if we have already processed this exact request_id.
   *    This is the primary defense against infinite re-broadcast storms:
   *    each hub processes a given request at most once, regardless of how
   *    many peers flood copies of it back. */
  if (op_forward_seen_check_and_add(state, request_id)) {
    if (state->log_level >= LOG_DEBUG)
      hub_log("[DEBUG] [HUB] Dropping duplicate OP_FORWARD_REQUEST (id:%s) -- already processed\n",
                  request_id);
    return;
  }

  hub_log("[HUB] Received OP_FORWARD_REQUEST (id:%s) from peer fd=%d target=%s channel=%s\n",
          request_id, client->fd, target_uuid, channel);

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

      /* Forward to other peer hubs so they can deliver to their local bots.
       * The seen-set on each receiving hub ensures they process it only once
       * even if multiple peers forward copies. */
      forward_op_request_to_peers(state, request_id, requester_uuid, target_uuid,
                                  channel, "", client->fd, (time_t)origin_ts);
      hub_log("[HUB] Admin OP_REQUEST delivered to %d local bot(s), forwarding to peers\n",
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
    // Use hostmask carried in the forwarded payload; fall back to local storage.
    char requester_hostmask[MAX_MASK_LEN] = "";
    if (carried_hostmask[0] != '\0') {
      snprintf(requester_hostmask, sizeof(requester_hostmask), "%s",
               carried_hostmask);
    } else {
      for (int i = 0; i < state->bot_count; i++) {
        if (strcmp(state->bots[i].uuid, requester_uuid) == 0) {
          for (int j = 0; j < state->bots[i].entry_count; j++) {
            if (strcmp(state->bots[i].entries[j].key, "h") == 0) {
              snprintf(requester_hostmask, sizeof(requester_hostmask), "%.*s",
                       (int)(sizeof(requester_hostmask) - 1),
                       state->bots[i].entries[j].value);
              break;
            }
          }
          break;
        }
      }
    }

    if (requester_hostmask[0] == '\0') {
      hub_log("[HUB] No hostmask for requester %s (not in payload or storage)\n",
              requester_uuid);
      char fail_payload[256];
      snprintf(fail_payload, sizeof(fail_payload), "%s|No hostmask found",
               request_id);
      peer_send_urgent(state, client, CMD_OP_FORWARD_FAILED, fail_payload);
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
        /* Forward grant confirmation back to origin peer via URGENT. */
        peer_send_urgent(state, client, CMD_OP_FORWARD_GRANT, request_id);
        hub_log("[HUB] Queued OP_FORWARD_GRANT URGENT back to peer for id:%s\n",
                request_id);
      }
    }
  } else {
    // Target not found locally - forward to other peers (exclude origin)
    hub_log("[HUB] Target bot %s not found locally, forwarding to %d peer(s)\n",
            target_uuid, state->client_count);
    forward_op_request_to_peers(state, request_id, requester_uuid, target_uuid,
                                 channel, carried_hostmask, client->fd, (time_t)origin_ts);
  }
}

static void process_forward_op_grant(hub_state_t *state, hub_client_t *client,
                                      char *payload) {
  (void)client; // Not used - response goes to original requester
  // Payload format: request_id
  char request_id[64];
  if (strlen(payload) >= sizeof(request_id)) {
    hub_log("[HUB] OP_FORWARD_GRANT: oversized request_id, ignoring\n");
    return;
  }
  snprintf(request_id, sizeof(request_id), "%s", payload);

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
    hub_log("[HUB] OP_FORWARD_GRANT acknowledged for id:%s — requester learns via IRC MODE\n",
            request_id);
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

  case CMD_BOT_DELTA: {
    /* Payload: key|value|ts
     * Update one entry for this bot and forward a single DELTA to each peer
     * with Lamport seq and coalesce key — replaces the old full-config push
     * for single-field changes (hostmask, nick, etc.).
     * Wire format forwarded to peers: b|<bot_uuid>|<key>|<value>|<ts>
     * with two trailing fields |<origin_hub_uuid>|<lamport_seq> for the
     * seen-set. We compose that into the payload for CMD_PEER_SYNC DELTA. */
    char key[32], val[1024];
    long ts;
    if (sscanf(payload, "%31[^|]|%1023[^|]|%ld", key, val, &ts) < 2) {
      hub_log("[HUB] Invalid CMD_BOT_DELTA from %s — ignoring\n", client->id);
      break;
    }
    if (ts == 0) ts = (long)time(NULL);

    hub_log("[HUB] BOT_DELTA from %s: key=%s val=%.40s ts=%ld\n",
            client->id, key, val, ts);

    bool accepted = hub_storage_update_entry(state, client->id, key,
                                             val, "", "", (time_t)ts);
    if (!accepted) break;

    state->config_dirty = true;

    /* Build the delta line forwarded to peers.
     * Format: b|<bot_uuid>|<key>|<value>|<ts>   — the existing process_peer_sync
     * wire format, compatible with strrchr-based timestamp parsing.
     * The Lamport seq lives in the queued_msg_t coalesce metadata ONLY; it must
     * NOT be embedded in the payload content because process_peer_sync uses
     * strrchr (last pipe = timestamp) and extra trailing fields corrupt the
     * stored value. */
    uint64_t seq = hub_next_lamport_seq(state);
    char delta_line[MAX_BUFFER];
    int dlen = snprintf(delta_line, sizeof(delta_line),
                        "b|%s|%s|%s|%ld\n",
                        client->id, key, val, ts);
    if (dlen <= 0 || dlen >= (int)sizeof(delta_line)) break;

    /* Forward as a single DELTA message to every peer hub.
     * The coalesce key and Lamport seq on the queued_msg_t handle dedup. */
    char coalesce[160];
    snprintf(coalesce, sizeof(coalesce), "%s|%s|%s",
             state->hub_uuid, client->id, key);

    for (int i = 0; i < state->client_count; i++) {
      hub_client_t *c = state->clients[i];
      if (c->type != CLIENT_HUB || !c->authenticated) continue;
      queued_msg_t *m = queued_msg_new(CMD_PEER_SYNC, LANE_DELTA,
                                       (const unsigned char *)delta_line, dlen);
      if (!m) continue;
      queued_msg_set_coalesce(m, state->hub_uuid, seq, coalesce);
      if (!peer_enqueue(c, m)) {
        hub_log("[HUB] BOT_DELTA enqueue failed for peer fd=%d\n", c->fd);
      }
    }

    /* Also push fresh config to locally connected bots so they learn the
     * new hostmask / nick immediately without waiting for anti-entropy. */
    for (int i = 0; i < state->client_count; i++) {
      hub_client_t *c = state->clients[i];
      if (c->type == CLIENT_BOT && c->authenticated &&
          strcmp(c->id, client->id) != 0) {
        send_config_to_bot(state, c);
      }
    }
    break;
  }

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
        // Resolve requester's hostmask here (home hub always has it)
        char req_hostmask[MAX_MASK_LEN] = "";
        for (int i = 0; i < state->bot_count; i++) {
          if (strcmp(state->bots[i].uuid, client->id) == 0) {
            for (int j = 0; j < state->bots[i].entry_count; j++) {
              if (strcmp(state->bots[i].entries[j].key, "h") == 0) {
                snprintf(req_hostmask, sizeof(req_hostmask), "%.*s",
                         (int)(sizeof(req_hostmask) - 1),
                         state->bots[i].entries[j].value);
                break;
              }
            }
            break;
          }
        }
        if (req_hostmask[0] == '\0') {
          hub_log("[HUB] No hostmask for requester %s — cannot forward OP_REQUEST\n",
                  client->id);
          peer_count = 0; // fall through to OP_FAILED
        }

        char request_id[64];
        generate_request_id(request_id, sizeof(request_id));

        if (peer_count > 0 &&
            add_pending_op_request(state, request_id, client->id, target_uuid,
                                    channel, client->fd) >= 0) {
          /* Stamp origin_ts and mark this request_id as seen on the originating
           * hub so any loop-back copy arriving from other hubs is dropped. */
          time_t op_origin_ts = time(NULL);
          op_forward_seen_check_and_add(state, request_id);
          forward_op_request_to_peers(state, request_id, client->id,
                                       target_uuid, channel, req_hostmask, -1, op_origin_ts);
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
            snprintf(requester_hostmask, sizeof(requester_hostmask), "%.*s",
                     (int)(sizeof(requester_hostmask) - 1),
                     state->bots[i].entries[j].value);
            break;
          }
        }
        break;
      }
    }

    if (requester_hostmask[0] == '\0') {
      hub_log("[HUB] No hostmask stored for requesting bot %s\n", client->id);
      unsigned char plain[MAX_BUFFER], buffer[MAX_BUFFER], tag[GCM_TAG_LEN];
      plain[0] = CMD_OP_FAILED;
      const char *reason = "Hostmask not yet stored";
      int rlen = strlen(reason);
      uint32_t nlen = htonl(rlen);
      memcpy(&plain[1], &nlen, 4);
      memcpy(&plain[5], reason, rlen);
      int enc_len = aes_gcm_encrypt(plain, 5 + rlen, client->session_key, buffer + 4, tag);
      if (enc_len > 0) {
        memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
        uint32_t net_len = htonl(enc_len + GCM_TAG_LEN);
        memcpy(buffer, &net_len, 4);
        if (write(client->fd, buffer, 4 + enc_len + GCM_TAG_LEN) < 0)
          hub_log("[HUB] Failed to send OP_FAILED to bot %s\n", client->id);
      }
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

  case CMD_INVITE_REQUEST: {
    /* Payload: nick|#channel — broadcast to all other bots, forward to peers */
    char inv_nick[64], inv_chan[64];
    if (sscanf(payload, "%63[^|]|%63s", inv_nick, inv_chan) != 2) {
      hub_log("[HUB] Invalid INVITE_REQUEST payload from %s\n", client->id);
      break;
    }
    hub_log("[HUB] INVITE_REQUEST from %s: invite %s into %s\n",
            client->id, inv_nick, inv_chan);

    /* Broadcast to all other connected bots */
    unsigned char plain[MAX_BUFFER], inv_buf[MAX_BUFFER], inv_tag[GCM_TAG_LEN];
    int inv_pay_len = (int)strlen(payload);
    plain[0] = (unsigned char)CMD_INVITE_REQUEST;
    uint32_t inv_net_pay = htonl((uint32_t)inv_pay_len);
    memcpy(&plain[1], &inv_net_pay, 4);
    memcpy(&plain[5], payload, inv_pay_len);

    for (int i = 0; i < state->client_count; i++) {
      hub_client_t *bc = state->clients[i];
      if (bc->type == CLIENT_BOT && bc->authenticated &&
          bc->fd != client->fd) {
        int enc_len = aes_gcm_encrypt(plain, 5 + inv_pay_len,
                                      bc->session_key, inv_buf + 4, inv_tag);
        if (enc_len > 0) {
          memcpy(inv_buf + 4 + enc_len, inv_tag, GCM_TAG_LEN);
          uint32_t net_len = htonl((uint32_t)(enc_len + GCM_TAG_LEN));
          memcpy(inv_buf, &net_len, 4);
          if (write(bc->fd, inv_buf, 4 + enc_len + GCM_TAG_LEN) <= 0) {
            hub_log("[HUB] Failed to forward INVITE_REQUEST to bot %s\n",
                    bc->id);
          }
        }
      }
    }

    /* Forward to peer hubs via mesh sync */
    char peer_inv[192];
    snprintf(peer_inv, sizeof(peer_inv), "invite|%s|%s", inv_nick, inv_chan);
    hub_broadcast_sync_to_peers(state, peer_inv, client->fd);
  } break;

  case CMD_BOT_RELAY: {
    /* Payload: target_uuid|cipher:tag — forward cipher:tag to the target bot */
    char target_uuid[64], relay_payload[MAX_BUFFER];
    char *pipe = strchr(payload, '|');
    if (!pipe) {
      hub_log("[HUB] Invalid CMD_BOT_RELAY payload from %s\n", client->id);
      break;
    }
    size_t uuid_len = (size_t)(pipe - payload);
    if (uuid_len == 0 || uuid_len >= sizeof(target_uuid)) {
      hub_log("[HUB] CMD_BOT_RELAY bad UUID len from %s\n", client->id);
      break;
    }
    memcpy(target_uuid, payload, uuid_len);
    target_uuid[uuid_len] = '\0';
    snprintf(relay_payload, sizeof(relay_payload), "%s", pipe + 1);

    hub_log("[HUB] CMD_BOT_RELAY from %s to %s\n", client->id, target_uuid);

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
      hub_log("[HUB] CMD_BOT_RELAY: target %s not connected\n", target_uuid);
      break;
    }

    int relay_len = (int)strlen(relay_payload);
    unsigned char msg_plain[MAX_BUFFER], msg_buf[MAX_BUFFER], msg_tag[GCM_TAG_LEN];
    msg_plain[0] = (unsigned char)CMD_BOT_MSG;
    uint32_t msg_net_pay = htonl((uint32_t)relay_len);
    memcpy(&msg_plain[1], &msg_net_pay, 4);
    memcpy(&msg_plain[5], relay_payload, relay_len);

    int enc_len = aes_gcm_encrypt(msg_plain, 5 + relay_len,
                                  target->session_key, msg_buf + 4, msg_tag);
    if (enc_len > 0) {
      memcpy(msg_buf + 4 + enc_len, msg_tag, GCM_TAG_LEN);
      uint32_t net_len = htonl((uint32_t)(enc_len + GCM_TAG_LEN));
      memcpy(msg_buf, &net_len, 4);
      if (write(target->fd, msg_buf, 4 + enc_len + GCM_TAG_LEN) <= 0)
        hub_log("[HUB] CMD_BOT_RELAY: write to %s failed\n", target_uuid);
      else
        hub_log("[HUB] CMD_BOT_RELAY: forwarded to %s (%d bytes)\n",
                target_uuid, relay_len);
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

  int len = strlen(payload);
  if (len == 0) {
    hub_log("[HUB] No config to send to %s\n", client->id);
    return;
  }

  hub_log("[HUB-SYNC] Queueing config to %s (%d bytes)\n", client->id, len);

  /* Bot config push goes through the bot-client's BULK lane.  The encrypt
   * path knows to apply htonl() to the inner length only for CMD_CONFIG_DATA
   * so the bot's parser still decodes correctly.  Coalesce on a per-bot key
   * so a burst of broadcast_full_config_to_all_bots calls collapses to one
   * per bot per drain cycle. */
  char coalesce[160];
  snprintf(coalesce, sizeof(coalesce), "%s|cfg_data|%s",
           state->hub_uuid, client->id);

  queued_msg_t *m = queued_msg_new(CMD_CONFIG_DATA, LANE_BULK,
                                   (const unsigned char *)payload, len);
  if (!m) return;
  queued_msg_set_coalesce(m, state->hub_uuid,
                          hub_next_lamport_seq(state), coalesce);
  peer_enqueue(client, m);
}

bool hub_handle_client_data(hub_state_t *state, hub_client_t *client) {
  // Process at most 8 packets per call so the event loop stays fair across
  // connections — prevents one backlogged peer from starving bot auth.
  int packets_this_call = 0;
  while (client->recv_len >= 4 && packets_this_call < 8) {
    packets_this_call++;
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
      // Detect packet type: Bot UUID (plaintext, 36 chars, hex+hyphens)
      // or mid-handshake bot packet (64-byte sig or eph_pub response)
      bool looks_like_uuid = false;
      if (packet_len >= 36 && packet_len <= 36) {
        looks_like_uuid = true;
        for (int i = 0; i < packet_len && looks_like_uuid; i++) {
          char c = data[i];
          if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                (c >= 'A' && c <= 'F') || c == '-')) {
            looks_like_uuid = false;
          }
        }
      }

      // Route to bot auth handler (UUID or mid-handshake)
      if (looks_like_uuid || client->bot_auth_state != BOT_AUTH_IDLE) {
        if (!handle_bot_authentication(state, client, data, packet_len)) {
          hub_disconnect_client(state, client);
          return false;
        }
        goto packet_consumed;
      }

      // Sealed-box decrypt for ADMIN and HUB peer auth
      // Packet layout: eph_pub(32) || IV(GCM_IV_LEN) || ct(N) || tag(GCM_TAG_LEN)
      if (packet_len >= 32 + GCM_IV_LEN + GCM_TAG_LEN && packet_len <= MAX_BUFFER) {
        static const unsigned char ADMIN_INFO[] = "irchub-admin-session-v1";
        static const unsigned char PEER_INFO[]  = "irchub-peer-session-v1";

        unsigned char plain[MAX_BUFFER];
        unsigned char session_key[32];

        int pl = hub_seal_open(state, data, packet_len,
                               ADMIN_INFO, sizeof(ADMIN_INFO) - 1,
                               plain, sizeof(plain) - 1, session_key);
        bool tried_admin = (pl > 0 && pl >= 5 && memcmp(plain, "ADMIN", 5) == 0);

        if (pl <= 0 || !tried_admin) {
          // Retry under PEER_INFO
          secure_wipe(session_key, 32);
          int pl2 = hub_seal_open(state, data, packet_len,
                                  PEER_INFO, sizeof(PEER_INFO) - 1,
                                  plain, sizeof(plain) - 1, session_key);
          if (pl2 > 0) pl = pl2;
          else if (!tried_admin) pl = -1;
        }

        if (pl > 0) {
          memcpy(client->session_key, session_key, 32);
          secure_wipe(session_key, 32);
          plain[pl] = 0;
          char *payload = (char *)plain;

          // ADMIN Authentication
          if (strncmp(payload, "ADMIN", 5) == 0) {
            char *pipe = strchr(payload + 6, '|');
            char pass_buf[128];
            int pass_len;

            if (pipe) {
              pass_len = pipe - (payload + 6);
              if (pass_len >= (int)sizeof(pass_buf)) pass_len = sizeof(pass_buf) - 1;
              memcpy(pass_buf, payload + 6, pass_len);
              pass_buf[pass_len] = '\0';
            } else {
              if (strlen(payload + 6) >= sizeof(pass_buf)) {
                pass_len = 0; pass_buf[0] = '\0';
              } else {
                snprintf(pass_buf, sizeof(pass_buf), "%s", payload + 6);
              }
            }

            if (strcmp(pass_buf, state->admin_password) == 0) {
              client->type = CLIENT_ADMIN;
              client->authenticated = true;
              snprintf(client->id, sizeof(client->id), "ADMIN");

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

              hub_log("[HUB] Admin Login (Curve25519): %s\n", client->ip);

              /* Kick off an immediate bidirectional mesh sync on admin connect:
               * push our state to peers and ask them to send back their state,
               * then refresh all locally-connected bots now. */
              state->anti_entropy_due = true;
              hub_request_sync_from_peers(state);
              broadcast_full_config_to_all_bots(state);
            } else {
              hub_log("[HUB] Failed admin auth from %s\n", client->ip);
              record_failed_auth(state, client->ip);
              secure_wipe(plain, sizeof(plain));
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

            int args = sscanf(payload + 4, "%127s %d %63s %63s %63s",
                              pass, &claimed_port, peer_uuid, peer_name, peer_bind_ip);

            if (args >= 1 && strcmp(pass, state->admin_password) == 0) {
              client->type = CLIENT_HUB;

              bool is_authorized_peer = false;
              int peer_idx = -1;

              for (int p = 0; p < state->peer_count; p++) {
                if (args >= 3 && peer_uuid[0] && state->peers[p].uuid[0]) {
                  if (strcmp(state->peers[p].uuid, peer_uuid) == 0) {
                    peer_idx = p; is_authorized_peer = true; break;
                  }
                } else {
                  bool ip_match = (strcmp(state->peers[p].ip, client->ip) == 0 ||
                                   strcmp(state->bind_ip, client->ip) == 0);
                  if (ip_match && claimed_port > 0 && state->peers[p].port == claimed_port) {
                    peer_idx = p; is_authorized_peer = true; break;
                  }
                }
              }

              if (!is_authorized_peer) {
                hub_log("[HUB] Unauthorized peer from %s (UUID: %s)\n",
                        client->ip, peer_uuid[0] ? peer_uuid : "none");
                secure_wipe(plain, sizeof(plain));
                hub_disconnect_client(state, client);
                return false;
              }

              if (args >= 3 && peer_uuid[0] && state->peers[peer_idx].uuid[0]) {
                if (strcmp(state->peers[peer_idx].uuid, peer_uuid) != 0) {
                  hub_log("[HUB] UUID mismatch for peer %s\n", client->ip);
                  secure_wipe(plain, sizeof(plain));
                  hub_disconnect_client(state, client);
                  return false;
                }
              }

              client->authenticated = true;
              state->peers[peer_idx].connected = true;
              state->peers[peer_idx].fd = client->fd;
              snprintf(state->peers[peer_idx].remote_ip,
                       sizeof(state->peers[peer_idx].remote_ip), "%s", client->ip);

              if (!state->peers[peer_idx].friendly_name[0] && args >= 4 && peer_name[0]) {
                snprintf(state->peers[peer_idx].friendly_name,
                         sizeof(state->peers[peer_idx].friendly_name), "%s", peer_name);
              }

              snprintf(client->id, sizeof(client->id), "%s",
                       state->peers[peer_idx].friendly_name[0] ?
                       state->peers[peer_idx].friendly_name :
                       (peer_name[0] ? peer_name : "HUB-PEER"));
              client->id[sizeof(client->id) - 1] = 0;

              hub_log("[HUB] Peer connected (Curve25519): %s (%s)\n",
                      peer_name[0] ? peer_name : client->ip,
                      peer_uuid[0] ? peer_uuid : "no-uuid");

              /* Send our full state to the newly authenticated peer so it
               * receives channels, user records, and mask records immediately
               * rather than waiting for the next change-triggered sync. */
              {
                char *init_sync = malloc(MAX_BUFFER);
                if (init_sync) {
                  hub_generate_sync_packet(state, init_sync, MAX_BUFFER - 100);
                  int slen = (int)strlen(init_sync);
                  if (slen > 0) {
                    queued_msg_t *sm = queued_msg_new(CMD_PEER_SYNC, LANE_BULK,
                                                     (const unsigned char *)init_sync, slen);
                    if (sm) peer_enqueue(client, sm);
                  }
                  free(init_sync);
                }
              }
            } else {
              hub_log("[HUB] Failed peer auth from %s\n", client->ip);
              record_failed_auth(state, client->ip);
              secure_wipe(plain, sizeof(plain));
              hub_disconnect_client(state, client);
              return false;
            }
          } else {
            secure_wipe(plain, sizeof(plain));
            hub_disconnect_client(state, client);
            return false;
          }

          secure_wipe(plain, sizeof(plain));
        } else {
          secure_wipe(session_key, 32);
          // Sealed-box failed — fall through to bot auth
          if (!handle_bot_authentication(state, client, data, packet_len)) {
            hub_disconnect_client(state, client);
            return false;
          }
        }
      } else {
        // Short packet — must be bot UUID or mid-handshake
        if (!handle_bot_authentication(state, client, data, packet_len)) {
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

        if (pl <= 0) {
          hub_log("[HUB] GCM tag verification failed from authenticated client %s\n",
                  client->ip);
        }

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
              } else if (cmd == CMD_SYNC_REQUEST) {
                /* Peer is asking us for our full state immediately.
                 * Send our full sync packet to just this requesting peer. */
                hub_log("[MESH] Sync request from peer %s — sending full state\n",
                        client->ip);
                char reply_sync[MAX_BUFFER];
                hub_generate_sync_packet(state, reply_sync, sizeof(reply_sync));
                if (reply_sync[0] != '\0') {
                  int reply_len = (int)strlen(reply_sync);
                  queued_msg_t *sm = queued_msg_new(CMD_PEER_SYNC, LANE_BULK,
                                                    (const unsigned char *)reply_sync,
                                                    reply_len);
                  if (sm) peer_enqueue(client, sm);
                }
              } else if (cmd == CMD_UPDATE_PUBKEY) {
                // Peer hub sent new shared keypair: "<priv_b64>|||<pub_b64>"
                if (payload_ptr && strlen(payload_ptr) > 0) {
                  hub_log("[HUB] Received Curve25519 key update from peer %s\n", client->ip);
                  char *sep = strstr(payload_ptr, "|||");
                  if (sep) {
                    size_t priv_b64_len = sep - payload_ptr;
                    char priv_b64[128] = {0};
                    char pub_b64[128]  = {0};
                    if (priv_b64_len < sizeof(priv_b64) && strlen(sep + 3) < sizeof(pub_b64)) {
                      memcpy(priv_b64, payload_ptr, priv_b64_len);
                      snprintf(pub_b64, sizeof(pub_b64), "%s", sep + 3);

                      int pl = 0, publ = 0;
                      unsigned char *pd = base64_decode(priv_b64, &pl);
                      unsigned char *pubp = base64_decode(pub_b64, &publ);
                      if (pd && pl == 64 && pubp && publ == 64) {
                        hub_crypto_split_combined(pd, state->hub_ed25519_priv, state->hub_x25519_priv);
                        hub_crypto_split_combined(pubp, state->hub_ed25519_pub, state->hub_x25519_pub);
                        state->hub_keys_loaded = true;
                        secure_wipe(pd, 64);
                        state->config_dirty = true;
                        hub_log("[HUB] Applied new Curve25519 mesh keypair from peer\n");
                        if (pd) free(pd);
                        if (pubp) free(pubp);
                        // Disconnect peers so they reconnect with new key
                        for (int i = 0; i < state->client_count; i++) {
                          if (state->clients[i]->type == CLIENT_HUB) {
                            hub_disconnect_client(state, state->clients[i]);
                            i--;
                          }
                        }
                        return false;
                      } else {
                        hub_log("[HUB] Invalid Curve25519 key update from peer %s\n", client->ip);
                      }
                      if (pd) { secure_wipe(pd, pl); free(pd); }
                      if (pubp) free(pubp);
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

    packet_consumed:;
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
