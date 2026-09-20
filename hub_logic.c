#include "hub.h"
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/crypto.h>
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
  /* Change 5: bulk lanes (CONFIG_DATA / PEER_SYNC full-state) may be far larger
   * than MAX_BUFFER; bound by the bulk-payload ceiling instead. */
  if (payload_len < 0 || payload_len > MAX_BULK_PAYLOAD)
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

bool hub_client_has_buffered_frame(const hub_client_t *c) {
  if (!c || c->fd <= 0 || !c->recv_buf || c->recv_len < 4) return false;
  uint32_t net_len;
  memcpy(&net_len, c->recv_buf, 4);
  int packet_len = (int)ntohl(net_len);
  /* An out-of-range prefix counts: the pump refuses it and drops the client
   * rather than leaving it parked on a length that can never complete. */
  if (packet_len < 0 || packet_len > c->recv_cap - 4) return true;
  return c->recv_len >= 4 + packet_len;
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
  /* Change 5: heap the plaintext scratch — a bulk CONFIG_DATA/PEER_SYNC frame
   * (up to MAX_BULK_PAYLOAD) is far too large for the stack. */
  if (m->payload_len < 0 || m->payload_len > MAX_BULK_PAYLOAD) return 0;
  unsigned char *plain = malloc((size_t)m->payload_len + 5);
  if (!plain) return 0;
  size_t plain_alloc = (size_t)m->payload_len + 5;
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
  plain[0] = m->cmd;
  uint32_t inner_len_field;
  /* The bot's frame parser ntohl()s this field unconditionally, so every
   * BOT-destined opcode must be stamped in network order -- peers and admins
   * keep host order for wire compatibility.  CMD_BOT_TREE joined that list;
   * without it the bot computed a garbage length, failed its bounds check and
   * silently dropped every tree push. */
  if (m->cmd == CMD_CONFIG_DATA || m->cmd == CMD_BOT_TREE) {
    inner_len_field = htonl((uint32_t)m->payload_len);
  } else {
    inner_len_field = (uint32_t)m->payload_len;
  }
  memcpy(&plain[1], &inner_len_field, 4);
  if (m->payload_len > 0)
    memcpy(&plain[5], m->payload, (size_t)m->payload_len);
  int total_plain = 5 + m->payload_len;

  /* D2: writing_buf may be the small pre-auth buffer. Refuse to encrypt a
   * frame that would not fit (4-byte length prefix + ciphertext + tag).
   * AES-GCM ciphertext length equals the plaintext length. */
  if (4 + total_plain + GCM_TAG_LEN > peer->writing_cap) {
    secure_wipe(plain, plain_alloc);
    free(plain);
    return 0;
  }

  unsigned char tag[GCM_TAG_LEN];
  int cipher_len = aes_gcm_encrypt(plain, total_plain, peer->session_key,
                                   peer->writing_buf + 4, tag);
  /* Wipe plaintext copy ASAP. */
  secure_wipe(plain, plain_alloc);
  free(plain);
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
      if (!m) { lane->count = 0; break; }  /* count/head desync guard: never deref a NULL head */
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
static void process_mesh_state(hub_state_t *state, hub_client_t *c,
                               char *payload);
static void process_peer_sync(hub_state_t *state, char *payload, int origin_fd);
static bool handle_admin_command(hub_state_t *state, hub_client_t *client,
                                 int cmd, char *payload, int payload_len);
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

/* PURGE deduplication.  A purge is known by its cutoff plus the random id its
 * origin hub gave it.  Keyed on the cutoff alone, every "immediate" purge
 * (cutoff 0) looked like the previous one for PURGE_DEDUP_WINDOW seconds, and
 * peers skipped a second purge sent inside that window.  A line from a hub
 * that predates the id carries id "" and dedupes on its cutoff as before. */
static bool is_purge_recent(hub_state_t *state, time_t cutoff, const char *id) {
  time_t now = time(NULL);
  for (int i = 0; i < state->recent_purge_count; i++) {
    if (state->recent_purges[i].cutoff == cutoff &&
        strcmp(state->recent_purges[i].id, id) == 0 &&
        now - state->recent_purges[i].received_at < PURGE_DEDUP_WINDOW)
      return true;
  }
  return false;
}

// Record a recently processed PURGE
static void record_recent_purge(hub_state_t *state, time_t cutoff, const char *id) {
  time_t now = time(NULL);
  int slot = -1;

  for (int i = 0; i < state->recent_purge_count; i++) {
    if (state->recent_purges[i].cutoff == cutoff &&
        strcmp(state->recent_purges[i].id, id) == 0) {
      slot = i;
      break;
    }
  }
  if (slot < 0 && state->recent_purge_count < MAX_RECENT_PURGES)
    slot = state->recent_purge_count++;
  if (slot < 0) {
    // Full: overwrite the oldest entry (slot 0 used to be overwritten always)
    slot = 0;
    for (int i = 1; i < state->recent_purge_count; i++)
      if (state->recent_purges[i].received_at <
          state->recent_purges[slot].received_at)
        slot = i;
  }
  state->recent_purges[slot].cutoff = cutoff;
  snprintf(state->recent_purges[slot].id, sizeof(state->recent_purges[slot].id),
           "%s", id);
  state->recent_purges[slot].received_at = now;
}

/* "PURGE|<cutoff>" or "PURGE|<cutoff>|<id>", id 1..PURGE_ID_HEX hex digits.
 * False on anything else (the line is dropped, not forwarded). */
static bool parse_purge_line(const char *line, time_t *cutoff,
                             char id[PURGE_ID_HEX + 1]) {
  const char *p = line + 6; /* past "PURGE|" */
  char *end = NULL;
  if (*p < '0' || *p > '9')
    return false;
  errno = 0;
  long long v = strtoll(p, &end, 10);
  if (errno || v < 0)
    return false;
  id[0] = '\0';
  if (*end == '|') {
    const char *h = end + 1;
    size_t n = strspn(h, "0123456789abcdefABCDEF");
    if (n == 0 || n > PURGE_ID_HEX || h[n] != '\0')
      return false;
    memcpy(id, h, n);
    id[n] = '\0';
  } else if (*end != '\0') {
    return false;
  }
  *cutoff = (time_t)v;
  return true;
}

bool hub_broadcast_purge(hub_state_t *state, time_t cutoff) {
  unsigned char rnd[PURGE_ID_HEX / 2];
  char id[PURGE_ID_HEX + 1];
  if (RAND_bytes(rnd, sizeof(rnd)) != 1) {
    hub_log("[PURGE][ERROR] no random bytes for a purge id; purge not broadcast\n");
    return false;
  }
  for (size_t i = 0; i < sizeof(rnd); i++)
    snprintf(id + 2 * i, 3, "%02x", rnd[i]);
  /* Seen here too: the copies peers forward back are not run again. */
  record_recent_purge(state, cutoff, id);

  char msg[64];
  snprintf(msg, sizeof(msg), "PURGE|%lld|%s\n", (long long)cutoff, id);
  hub_broadcast_sync_to_peers(state, msg, -1);
  return true;
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
        entry->churn_window_start = entry->first_seen;
        entry->churn_count = 0;
        return entry;
    }

    return NULL;  // No space (shouldn't happen with large limit)
}

/* D2: allocate a client's recv/writing buffers. recv_buf is `size`; writing_buf
 * is `size + 64` to hold the 4-byte length prefix + GCM tag overhead. */
bool hub_client_alloc_buffers(hub_client_t *c, int size) {
    if (!c || size <= 0) return false;
    c->recv_buf    = malloc((size_t)size);
    c->writing_buf = malloc((size_t)size + 64);
    if (!c->recv_buf || !c->writing_buf) {
        free(c->recv_buf);    c->recv_buf = NULL;
        free(c->writing_buf); c->writing_buf = NULL;
        return false;
    }
    c->recv_cap    = size;
    c->writing_cap = size + 64;
    return true;
}

/* D2: grow a client's buffers on successful auth. Idempotent. realloc preserves
 * any already-buffered bytes (e.g. data pipelined behind the final handshake
 * frame). On OOM the existing buffers are left intact and the caller should
 * disconnect.
 *
 * Change 5: size by client type so bulk lanes never truncate.  Peers exchange
 * full-state anti-entropy sync both directions (MAX_SYNC_PAYLOAD); a bot
 * receives its full config on the hub->bot (writing) side (MAX_CONFIG_PAYLOAD)
 * but only ever pushes small config/deltas up (recv stays MAX_BUFFER).  Must be
 * called after c->type is set. */
bool hub_client_promote_buffers(hub_client_t *c) {
    if (!c) return false;

    int recv_target, write_target;
    if (c->type == CLIENT_HUB) {
        recv_target  = MAX_SYNC_PAYLOAD;
        write_target = MAX_SYNC_PAYLOAD;
    } else if (c->type == CLIENT_BOT) {
        recv_target  = MAX_BUFFER;          /* bot->hub pushes are small */
        write_target = MAX_CONFIG_PAYLOAD;  /* hub->bot full config */
    } else {
        recv_target  = MAX_BUFFER;          /* admin */
        write_target = MAX_BUFFER;
    }

    if (c->recv_cap < recv_target) {
        unsigned char *nr = realloc(c->recv_buf, (size_t)recv_target);
        if (!nr) return false;
        c->recv_buf = nr;
        c->recv_cap = recv_target;
    }
    if (c->writing_cap < write_target + 64) {
        unsigned char *nw = realloc(c->writing_buf, (size_t)write_target + 64);
        if (!nw) return false;  /* recv already grown; caller drops on failure */
        c->writing_buf = nw;
        c->writing_cap = write_target + 64;
    }
    return true;
}

bool is_ip_allowed(hub_state_t *state, const char *ip) {
    /* D3: loopback is exempt only when explicitly trusted. Default is to treat
     * 127.0.0.1/::1 like any other IP, so a local/SSRF/co-tenant source cannot
     * bypass per-IP limits. */
    if (state->trust_loopback &&
        (strcmp(ip, "127.0.0.1") == 0 || strcmp(ip, "::1") == 0)) return true;

    ip_rate_limit_t *entry = find_or_create_ip_limit(state, ip);
    if (!entry) return true;  // If can't track, allow (fail open)

    time_t now = time(NULL);

    // Check if temporarily blocked
    if (entry->blocked_until > 0 && now < entry->blocked_until) {
        hub_log("[RATE_LIMIT] IP %s is blocked until %ld\n",
                ip, (long)entry->blocked_until);
        return false;
    }

    // Reset block if expired
    if (entry->blocked_until > 0 && now >= entry->blocked_until) {
        entry->blocked_until = 0;
        entry->failed_auth_count = 0;
    }

    /* D1: churn-based throttle. is_ip_allowed() is the single per-accept gate,
     * so each call is exactly one new connection attempt. Count attempts in a
     * sliding window; a connect/close flood trips a temporary block here even
     * though it never exceeds the concurrency limit or fails auth. */
    if (now - entry->churn_window_start >= CHURN_WINDOW_SEC) {
        entry->churn_window_start = now;
        entry->churn_count = 0;
    }
    entry->churn_count++;
    if (entry->churn_count > CHURN_MAX_CONNS) {
        entry->blocked_until = now + CHURN_BLOCK_SEC;
        hub_log("[RATE_LIMIT] IP %s connection churn flood (%d conns/%ds) — "
                "blocked %ds\n", ip, entry->churn_count, CHURN_WINDOW_SEC,
                CHURN_BLOCK_SEC);
        return false;
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
    /* D3: only skip failed-auth tracking for loopback when it is trusted. */
    if (state->trust_loopback &&
        (strcmp(ip, "127.0.0.1") == 0 || strcmp(ip, "::1") == 0)) return;
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

bool hub_name_valid(const char *name) {
  if (!name) return false;
  size_t n = strnlen(name, 64);
  if (n == 0 || n > 63) return false;
  for (size_t i = 0; i < n; i++) {
    unsigned char ch = (unsigned char)name[i];
    if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
          (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-'))
      return false;
  }
  return true;
}

bool hub_parse_uint(const char *s, unsigned long max, unsigned long *out) {
    if (!s || !out) return false;
    size_t n = strnlen(s, 11);
    if (n == 0 || n > 10) return false;
    unsigned long v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return false;
        unsigned long d = (unsigned long)(s[i] - '0');
        if (v > (max - d) / 10) return false;  /* v*10 + d would pass max */
        v = v * 10 + d;
    }
    *out = v;
    return true;
}

bool hub_ip_acl_parse(const char *in, hub_ip_acl_t *out) {
    if (!in || !out) return false;
    size_t n = strnlen(in, IP_ACL_PATTERN_MAX);
    if (n == 0 || n >= IP_ACL_PATTERN_MAX) return false;

    char addr[IP_ACL_PATTERN_MAX];
    memcpy(addr, in, n + 1);
    int prefix = 32;
    char *slash = strchr(addr, '/');
    if (slash) {
        /* 1-2 decimal digits, no sign/space/leading zero: atoi() used to turn
         * "10.0.0.0/" or "/x" into prefix 0, which matches every address. */
        const char *p = slash + 1;
        size_t plen = strlen(p);
        bool d0 = plen >= 1 && p[0] >= '0' && p[0] <= '9';
        bool d1 = plen == 2 && p[1] >= '0' && p[1] <= '9';
        if (!d0 || plen > 2 || (plen == 2 && (!d1 || p[0] == '0')))
            return false;
        prefix = plen == 2 ? (p[0] - '0') * 10 + (p[1] - '0') : p[0] - '0';
        if (prefix > 32) return false;
        *slash = '\0';
    }

    struct in_addr a;  /* strict dotted quad: no short forms, octal or spaces */
    if (inet_pton(AF_INET, addr, &a) != 1) return false;

    uint32_t mask = prefix ? 0xFFFFFFFFu << (32 - prefix) : 0;
    out->net = ntohl(a.s_addr) & mask;
    out->mask = mask;
    out->added = 0;

    char buf[INET_ADDRSTRLEN];
    struct in_addr na = { .s_addr = htonl(out->net) };
    if (!inet_ntop(AF_INET, &na, buf, sizeof(buf))) return false;
    int w = prefix == 32
          ? snprintf(out->pattern, sizeof(out->pattern), "%s", buf)
          : snprintf(out->pattern, sizeof(out->pattern), "%s/%d", buf, prefix);
    return w > 0 && w < (int)sizeof(out->pattern);
}

static bool ip_acl_match(const hub_ip_acl_t *list, int count, uint32_t addr) {
    for (int i = 0; i < count; i++)
        if ((addr & list[i].mask) == list[i].net) return true;
    return false;
}

/* 0 = permitted, 1 = on the denylist, 2 = not on a non-empty allowlist. */
static int ip_acl_verdict(const hub_state_t *state, const char *ip) {
    struct in_addr a;
    bool parsed = ip && inet_pton(AF_INET, ip, &a) == 1;
    uint32_t addr = parsed ? ntohl(a.s_addr) : 0;

    if (state->ip_deny_count > 0 &&
        (!parsed || ip_acl_match(state->ip_deny, state->ip_deny_count, addr)))
        return 1;
    if (state->ip_allow_count > 0 &&
        (!parsed || !ip_acl_match(state->ip_allow, state->ip_allow_count, addr)))
        return 2;
    return 0;
}

bool hub_ip_acl_permits(const hub_state_t *state, const char *ip) {
    return ip_acl_verdict(state, ip) == 0;
}

bool check_ip_access_lists(hub_state_t *state, const char *ip) {
    int verdict = ip_acl_verdict(state, ip);
    if (verdict == 0) return true;
    hub_log("[ACCESS_CONTROL] IP %s denied (%s)\n", ip,
            verdict == 1 ? "denylist" : "not in allowlist");
    return false;
}

static hub_ip_acl_t *ip_acl_list(hub_state_t *state, char list, int **count) {
    if (list == 'w') { *count = &state->ip_allow_count; return state->ip_allow; }
    if (list == 'x') { *count = &state->ip_deny_count;  return state->ip_deny; }
    return NULL;
}

static int ip_acl_find(const hub_ip_acl_t *list, int count, const hub_ip_acl_t *e) {
    for (int i = 0; i < count; i++)
        if (list[i].net == e->net && list[i].mask == e->mask) return i;
    return -1;
}

ip_acl_add_t hub_ip_acl_add(hub_state_t *state, char list, const hub_ip_acl_t *e) {
    int *count;
    hub_ip_acl_t *l = ip_acl_list(state, list, &count);
    if (!l) return IP_ACL_BAD_LIST;
    if (ip_acl_find(l, *count, e) >= 0) return IP_ACL_DUPLICATE;
    if (*count >= MAX_IP_ACL_ENTRIES) return IP_ACL_FULL;
    l[(*count)++] = *e;
    return IP_ACL_ADDED;
}

bool hub_ip_acl_remove(hub_state_t *state, char list, const hub_ip_acl_t *e) {
    int *count;
    hub_ip_acl_t *l = ip_acl_list(state, list, &count);
    if (!l) return false;
    int i = ip_acl_find(l, *count, e);
    if (i < 0) return false;
    memmove(&l[i], &l[i + 1], sizeof(*l) * (size_t)(*count - i - 1));
    (*count)--;
    memset(&l[*count], 0, sizeof(*l));
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
    memcpy(client->bot_eph_x25519_pub, eph_pub, 32);

    /* v2 challenge: challenge(32) || eph_pub(32) || hub_sig(64)
     *
     * Signature commits to the bot UUID, challenge, and ephemeral pubkey so
     * a MITM cannot substitute its own eph_pub (the bot would derive a
     * usable session key against the MITM, but the signature wouldn't
     * verify under the legitimate hub's pubkey). */
    size_t uuid_len = strlen(uuid);
    size_t tlen = strlen("irchub-hub-auth-v2|") + uuid_len + 1 + 32 + 32;
    unsigned char *transcript = malloc(tlen);
    if (!transcript) {
      hub_log("[HUB][ERROR] transcript alloc failed\n");
      return false;
    }
    size_t off = 0;
    memcpy(transcript + off, "irchub-hub-auth-v2|", 19); off += 19;
    memcpy(transcript + off, uuid, uuid_len);            off += uuid_len;
    transcript[off++] = '|';
    memcpy(transcript + off, client->challenge, 32);     off += 32;
    memcpy(transcript + off, eph_pub, 32);               off += 32;

    unsigned char hub_sig[ED25519_SIG_LEN];
    if (!hub_crypto_ed25519_sign(state->hub_ed25519_priv,
                                 transcript, off, hub_sig)) {
      hub_log("[HUB][ERROR] Hub Ed25519 sign failed\n");
      secure_wipe(transcript, off);
      free(transcript);
      return false;
    }
    secure_wipe(transcript, off);
    free(transcript);

    unsigned char out_buf[128];
    memcpy(out_buf,       client->challenge, 32);
    memcpy(out_buf + 32,  eph_pub,           32);
    memcpy(out_buf + 64,  hub_sig,           64);

    uint32_t nl = htonl(128);
    if (write(client->fd, &nl, 4) != 4 ||
        write(client->fd, out_buf, 128) != 128) {
      hub_log("[HUB][ERROR] Failed to send v2 challenge to %s\n", uuid);
      return false;
    }

    snprintf(client->id, sizeof(client->id), "%s", uuid);
    client->bot_auth_state = BOT_AUTH_CHALLENGE_SENT;
    client->last_seen = time(NULL);

    hub_log("[HUB] Sent v2 signed Curve25519 challenge to bot %s\n", uuid);
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

    /* Domain-separated transcript: "irchub-bot-challenge-v1|UUID|" + eph_pub(32)
     * + challenge(32).  Mirrors ed25519_sign_challenge() in hub_client.c. */
    {
      size_t uuid_len = strlen(client->id);
      /* prefix = "irchub-bot-challenge-v1|" + uuid + "|" */
      size_t prefix_len = 24 + uuid_len + 1;
      size_t msg_len = prefix_len + 32 + 32;
      unsigned char *msg = malloc(msg_len);
      if (!msg) {
        hub_log("[HUB][ERROR] OOM building challenge transcript for %s\n",
                client->id);
        secure_wipe(bot_combined, 64);
        return false;
      }
      size_t off = 0;
      memcpy(msg + off, "irchub-bot-challenge-v1|", 24); off += 24;
      memcpy(msg + off, client->id, uuid_len);           off += uuid_len;
      msg[off++] = '|';
      memcpy(msg + off, client->bot_eph_x25519_pub, 32); off += 32;
      memcpy(msg + off, client->challenge, 32);          off += 32;

      bool sig_ok = hub_crypto_ed25519_verify(bot_ed_pub, msg, msg_len, data);
      secure_wipe(msg, msg_len);
      free(msg);

      if (!sig_ok) {
        hub_log("[HUB][ERROR] Invalid signature from bot %s\n", client->id);
        record_failed_auth(state, client->ip);
        secure_wipe(bot_combined, 64);
        return false;
      }
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

    /* Send GCM-encrypted 1-byte ACK so the bot can confirm the hub knows the
     * session key — without this, a MITM that proxied the v2 challenge could
     * still flip the bot into "authenticated" via a plaintext 0x01.
     *
     * aes_gcm_encrypt writes (iv || ciphertext) into the output buffer and
     * the tag into the separate `tag` argument. Wire format we send is:
     *   iv(GCM_IV_LEN=12) || ciphertext(1) || tag(GCM_TAG_LEN=16) = 29 bytes
     */
    unsigned char ack_plain = 0x01;
    unsigned char ack_wire[GCM_IV_LEN + 1 + GCM_TAG_LEN];
    unsigned char ack_tag[GCM_TAG_LEN];
    int enc_len = aes_gcm_encrypt(&ack_plain, 1,
                                  client->session_key, ack_wire, ack_tag);
    if (enc_len <= 0) {
      hub_log("[HUB][ERROR] ACK encrypt failed for %s\n", client->id);
      return false;
    }
    memcpy(ack_wire + enc_len, ack_tag, GCM_TAG_LEN);
    int ack_total = enc_len + GCM_TAG_LEN;

    uint32_t nl = htonl((uint32_t)ack_total);
    if (write(client->fd, &nl, 4) != 4 ||
        write(client->fd, ack_wire, ack_total) != ack_total) {
      hub_log("[HUB][ERROR] Failed to send v2 ACK to %s\n", client->id);
      return false;
    }

    client->type = CLIENT_BOT;
    client->authenticated = true;
    client->bot_auth_state = BOT_AUTH_COMPLETE;
    client->last_seen = time(NULL);

    /* D2: grow buffers to full size now that the bot is authenticated. */
    if (!hub_client_promote_buffers(client)) {
      hub_log("[HUB][ERROR] Buffer promotion OOM for %s — disconnecting\n",
              client->id);
      return false;
    }

    hub_storage_update_entry(state, client->id, "seen", "", "", "", client->last_seen);

    /* A new bot joins the tree: gossip and push on the next tick instead of
     * leaving it invisible to the mesh until the periodic refresh. */
    hub_roster_mark_dirty(state);
    state->last_presence_gossip = 0;

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

/* broadcast_new_key removed: independent per-hub keypairs mean private keys
 * must never travel between hubs.  Rekey is local-only — each hub regenerates
 * its own keypair and exports the new pubkey for peers to re-register. */

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
    /* A new registration is live.  is_active follows the 'd' entry alone,
     * so it must be set here (the memset leaves it false). */
    b->is_active = true;
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

          // Update friendly_name if it changed (and is a well-formed name:
          // it is written to our config and shown to operators)
          if (fields >= 4 && remote_name[0] && strcmp(remote_name, "-") != 0 &&
              hub_name_valid(remote_name)) {
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

/* ==========================================================================
 * Bot presence — the data behind the bot's 'bots' tree.
 *
 * Three hops, none of which touch the config store:
 *   1. bot  -> hub   CMD_BOT_PRESENCE  its version, IRC server, start time
 *   2. hub <-> hub   CMD_BOT_ROSTER    the bots connected to THIS hub
 *   3. hub  -> bot   CMD_BOT_TREE      the assembled tree, DFS pre-order
 *
 * Everything here is volatile and TTL'd.  A bot that disconnects stops being
 * reported and ages out; a hub that dies takes its whole branch with it.  The
 * only persisted data read is identity (nick) and 'seen', both already in the
 * config, used to list bots that are known but currently offline.
 * ========================================================================== */

/* Sanitize one field arriving from a bot or a peer before it is stored or
 * echoed into a tree row.  Presence text is attacker-controlled: it reaches
 * other operators' IRC clients, so '|' (our field separator), CR/LF and any
 * other control byte are dropped outright rather than escaped. */
static void roster_clean(char *dst, size_t cap, const char *src) {
  size_t o = 0;
  if (cap == 0) return;
  for (size_t i = 0; src && src[i] && o + 1 < cap; i++) {
    unsigned char ch = (unsigned char)src[i];
    if (ch < 0x20 || ch == 0x7f || ch == '|') continue;
    dst[o++] = (char)ch;
  }
  dst[o] = '\0';
}

void hub_roster_mark_dirty(hub_state_t *state) { state->tree_dirty = true; }

void hub_roster_expire(hub_state_t *state, time_t now) {
  for (int i = 0; i < state->roster_count;) {
    if (now - state->roster[i].reported_at > BOT_ROSTER_TTL) {
      hub_log("[PRESENCE] %s on hub %s aged out of the roster\n",
              state->roster[i].nick[0] ? state->roster[i].nick
                                       : state->roster[i].bot_uuid,
              state->roster[i].hub_name);
      state->roster[i] = state->roster[--state->roster_count];
      state->tree_dirty = true;
      continue; /* the swapped-in entry still needs checking */
    }
    i++;
  }
}

/* Upsert one reported bot.  Keyed on (reporting hub, bot) so the same bot
 * briefly reported by two hubs mid-migration shows up once per hub rather
 * than flapping — the stale one expires on its own. */
static void roster_upsert(hub_state_t *state, const bot_roster_t *in) {
  for (int i = 0; i < state->roster_count; i++) {
    bot_roster_t *e = &state->roster[i];
    if (strcmp(e->hub_uuid, in->hub_uuid) != 0 ||
        strcmp(e->bot_uuid, in->bot_uuid) != 0)
      continue;
    /* An unchanged report just refreshes the TTL; only a real change is worth
     * re-rendering every bot's tree for. */
    bool changed = strcmp(e->nick, in->nick) != 0 ||
                   strcmp(e->version, in->version) != 0 ||
                   strcmp(e->server, in->server) != 0 ||
                   e->connected_at != in->connected_at;
    *e = *in;
    if (changed) state->tree_dirty = true;
    return;
  }
  if (state->roster_count >= MAX_BOT_ROSTER) {
    hub_log("[PRESENCE] Roster full (%d) — dropping report for %s\n",
            MAX_BOT_ROSTER, in->bot_uuid);
    return;
  }
  state->roster[state->roster_count++] = *in;
  state->tree_dirty = true;
}

/* This bot just told us what it is running.  Per connection and volatile. */
static void process_bot_presence(hub_state_t *state, hub_client_t *client,
                                 const char *payload) {
  char version[ROSTER_VERSION_MAX + 1] = "";
  char server[ROSTER_SERVER_MAX + 1] = "";
  long long started = 0;

  /* "<version>|<server>|<started>" — a short, fixed shape.  Anything longer
   * than the field caps is truncated by roster_clean, never rejected, so a
   * newer bot advertising more never drops off the tree entirely. */
  char work[ROSTER_VERSION_MAX + ROSTER_SERVER_MAX + 64];
  snprintf(work, sizeof(work), "%s", payload ? payload : "");
  char *p1 = strchr(work, '|');
  if (p1) {
    *p1 = '\0';
    char *p2 = strchr(p1 + 1, '|');
    if (p2) {
      *p2 = '\0';
      started = atoll(p2 + 1);
    }
    roster_clean(server, sizeof(server), p1 + 1);
  }
  roster_clean(version, sizeof(version), work);

  /* A bot cannot claim to have started in the future, nor before the epoch of
   * this mesh; an out-of-range value just means "unknown uptime". */
  time_t now = time(NULL);
  if (started <= 0 || (time_t)started > now) started = 0;

  bool changed = strcmp(client->bot_version, version) != 0 ||
                 strcmp(client->bot_server, server) != 0 ||
                 client->bot_started != (time_t)started;
  snprintf(client->bot_version, sizeof(client->bot_version), "%s", version);
  snprintf(client->bot_server, sizeof(client->bot_server), "%s", server);
  client->bot_started = (time_t)started;

  if (changed) {
    hub_log("[PRESENCE] Bot %s: version %s on %s\n", client->id,
            version[0] ? version : "?", server[0] ? server : "(no server)");
    state->tree_dirty = true;
    state->last_presence_gossip = 0; /* gossip the change on the next tick */
  }
}

/* The nick the config knows this bot by (persisted 'n' key); empty if none. */
static void bot_nick_from_config(hub_state_t *state, const char *uuid,
                                 char *out, size_t cap) {
  if (cap) out[0] = '\0';
  for (int i = 0; i < state->bot_count; i++) {
    if (strcmp(state->bots[i].uuid, uuid) != 0) continue;
    for (int k = 0; k < state->bots[i].entry_count; k++) {
      if (strcmp(state->bots[i].entries[k].key, "n") == 0) {
        roster_clean(out, cap, state->bots[i].entries[k].value);
        return;
      }
    }
    return;
  }
}

/* One roster frame to every authenticated peer.  Deliberately NOT coalesced:
 * a large roster is chunked into several frames and coalescing on one key
 * would collapse them into whichever arrived last.  Best-effort on the BULK
 * lane — a dropped frame just means those bots refresh on the next tick. */
static void roster_send_to_peers(hub_state_t *state, const char *frame,
                                 int len) {
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type != CLIENT_HUB || !c->authenticated) continue;
    queued_msg_t *m = queued_msg_new(CMD_BOT_ROSTER, LANE_BULK,
                                     (const unsigned char *)frame, len);
    if (!m) continue;
    if (!peer_enqueue(c, m))
      hub_log("[PRESENCE] roster enqueue failed for peer %s\n", c->ip);
  }
}

/* Gossip the bots connected to THIS hub out to the peers.  Chunked to a byte
 * budget: each frame repeats the h| header and carries whole rows only, so a
 * receiver can apply any frame on its own without waiting for the rest. */
static void hub_gossip_bot_roster(hub_state_t *state) {
  if (state->peer_count == 0) return;

  char frame[ROSTER_FRAME_BUDGET];
  time_t now = time(NULL);
  int header_len = snprintf(frame, sizeof(frame), "h|%s|%s|%lld|%s\n",
                            state->hub_uuid[0] ? state->hub_uuid : "-",
                            state->hub_friendly_name[0]
                                ? state->hub_friendly_name : "-",
                            (long long)state->hub_started, HUB_VERSION);
  if (header_len <= 0 || header_len >= (int)sizeof(frame)) return;
  int offset = header_len, rows = 0, frames = 0;

  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type != CLIENT_BOT || !c->authenticated) continue;

    char nick[MAX_NICK];
    bot_nick_from_config(state, c->id, nick, sizeof(nick));
    char row[TREE_ROW_MAX];
    int rl = snprintf(row, sizeof(row), "b|%s|%s|%s|%s|%lld\n", c->id,
                      nick[0] ? nick : "-",
                      c->bot_version[0] ? c->bot_version : "-",
                      c->bot_server[0] ? c->bot_server : "-",
                      (long long)c->bot_started);
    if (rl <= 0 || rl >= (int)sizeof(row)) continue; /* unrepresentable row */

    if (offset + rl >= (int)sizeof(frame)) { /* full: flush, restart */
      roster_send_to_peers(state, frame, offset);
      frames++;
      offset = header_len;
      rows = 0;
    }
    if (offset + rl >= (int)sizeof(frame)) continue; /* still won't fit */
    memcpy(frame + offset, row, (size_t)rl);
    offset += rl;
    rows++;
  }

  /* Always send a final frame, even carrying no bots: the header doubles as
   * this hub's liveness and uptime beacon, which is what lets a peer show an
   * empty hub in the tree with a real uptime instead of a blank. */
  if (rows > 0 || frames == 0)
    roster_send_to_peers(state, frame, offset);
  state->last_presence_gossip = now;
}

/* A peer told us which bots are on it. */
static void process_bot_roster(hub_state_t *state, char *payload) {
  char hub_uuid[64] = "", hub_name[64] = "";
  time_t now = time(NULL);
  char *saveptr = NULL;

  for (char *line = strtok_r(payload, "\n", &saveptr); line;
       line = strtok_r(NULL, "\n", &saveptr)) {
    if (strncmp(line, "h|", 2) == 0) {
      char *f1 = strchr(line + 2, '|');
      if (!f1) continue;
      *f1 = '\0';
      char *f2 = strchr(f1 + 1, '|');
      long long started = 0;
      char hub_ver[ROSTER_VERSION_MAX + 1] = "";
      if (f2) {
        *f2 = '\0';
        char *f3 = strchr(f2 + 1, '|');
        if (f3) { *f3 = '\0'; roster_clean(hub_ver, sizeof(hub_ver), f3 + 1); }
        started = atoll(f2 + 1);
      }
      roster_clean(hub_uuid, sizeof(hub_uuid), line + 2);
      roster_clean(hub_name, sizeof(hub_name), f1 + 1);
      /* The header doubles as the remote hub's uptime and version beacon.
       * Clamp rather than trust: a peer's clock skew would render as a
       * negative uptime. */
      if (hub_uuid[0]) {
        for (int p = 0; p < state->peer_count; p++) {
          if (!state->peers[p].uuid[0] ||
              strcmp(state->peers[p].uuid, hub_uuid) != 0)
            continue;
          if (started > 0 && (time_t)started <= now &&
              state->peers[p].remote_started != (time_t)started) {
            state->peers[p].remote_started = (time_t)started;
            state->tree_dirty = true;
          }
          if (strcmp(state->peers[p].remote_version, hub_ver) != 0) {
            snprintf(state->peers[p].remote_version,
                     sizeof(state->peers[p].remote_version), "%s", hub_ver);
            state->tree_dirty = true;
          }
          break;
        }
      }
      continue;
    }
    if (strncmp(line, "b|", 2) != 0) continue;
    /* A row before its header has no hub to hang off — ignore it rather than
     * guess, so a malformed frame cannot graft bots onto the wrong branch. */
    if (!hub_uuid[0] || strcmp(hub_uuid, "-") == 0) continue;
    /* Never let a peer report bots as belonging to US: our own branch is
     * built from our live client list and nothing else. */
    if (state->hub_uuid[0] && strcmp(hub_uuid, state->hub_uuid) == 0) continue;

    char *fields[5] = {NULL, NULL, NULL, NULL, NULL};
    char *cur = line + 2;
    int n = 0;
    while (n < 5) {
      fields[n++] = cur;
      char *sep = strchr(cur, '|');
      if (!sep) break;
      *sep = '\0';
      cur = sep + 1;
    }
    if (n < 5 || !fields[0] || !fields[0][0]) continue;

    bot_roster_t e;
    memset(&e, 0, sizeof(e));
    snprintf(e.hub_uuid, sizeof(e.hub_uuid), "%s", hub_uuid);
    snprintf(e.hub_name, sizeof(e.hub_name), "%s",
             hub_name[0] ? hub_name : hub_uuid);
    roster_clean(e.bot_uuid, sizeof(e.bot_uuid), fields[0]);
    if (!e.bot_uuid[0]) continue;
    if (strcmp(fields[1], "-") != 0) roster_clean(e.nick, sizeof(e.nick), fields[1]);
    if (strcmp(fields[2], "-") != 0) roster_clean(e.version, sizeof(e.version), fields[2]);
    if (strcmp(fields[3], "-") != 0) roster_clean(e.server, sizeof(e.server), fields[3]);
    long long started = atoll(fields[4]);
    /* Clamp a peer's clock skew rather than trusting it: a future start time
     * would render as a negative uptime. */
    e.connected_at = (started > 0 && (time_t)started <= now) ? (time_t)started : 0;
    e.reported_at = now;
    roster_upsert(state, &e);
  }
}

/* Build the tree for the bots on THIS hub, in DFS pre-order.  Row shapes:
 *   H|<depth>|<name>|<uuid>|<online>|<uptime>
 *   B|<depth>|<nick>|<uuid>|<version>|<server>|<uptime>
 *   D|<nick>|<uuid>|<last_seen>            (offline; always the tail)
 * Depth plus pre-order is all a renderer needs to draw the connectors: a node
 * is the last child at its level when no later row shares its depth before a
 * shallower one appears.  The bot does the drawing (commands.c) so the glyphs
 * can change without a hub deploy.
 *
 * Rooted at this hub because that is the vantage point the asking bot has:
 * its own hub first, peer hubs beneath it.  The mesh is flat, so the same
 * network legitimately renders differently depending on which bot you ask. */
static int hub_build_tree(hub_state_t *state, char *buf, int max_len) {
  int offset = 0, written;
  time_t now = time(NULL);
  buf[0] = '\0';

  written = snprintf(buf, max_len, "H|0|%s|%s|1|%lld|%s\n",
                     state->hub_friendly_name[0] ? state->hub_friendly_name
                                                 : "hub",
                     state->hub_uuid[0] ? state->hub_uuid : "-",
                     (long long)(state->hub_started
                                     ? now - state->hub_started : 0),
                     HUB_VERSION);
  if (written < 0 || written >= max_len) return 0;
  offset += written;

  /* Our own bots, from the live client list — never from a peer's report. */
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type != CLIENT_BOT || !c->authenticated) continue;
    if (max_len - offset <= TREE_ROW_MAX) break;
    char nick[MAX_NICK];
    bot_nick_from_config(state, c->id, nick, sizeof(nick));
    written = snprintf(buf + offset, max_len - offset, "B|1|%s|%s|%s|%s|%lld\n",
                       nick[0] ? nick : "-", c->id,
                       c->bot_version[0] ? c->bot_version : "-",
                       c->bot_server[0] ? c->bot_server : "-",
                       (long long)(c->bot_started ? now - c->bot_started : 0));
    if (written < 0 || written >= max_len - offset) break;
    offset += written;
  }

  /* Peer hubs at depth 1, each followed by its bots at depth 2.  A peer we
   * have no roster for still gets its node — "linked, nothing reported yet"
   * is more useful than silently omitting a hub that is plainly there. */
  for (int p = 0; p < state->peer_count; p++) {
    hub_peer_config_t *peer = &state->peers[p];
    if (max_len - offset <= TREE_ROW_MAX) break;
    const char *puuid = peer->uuid[0] ? peer->uuid : "";
    bool online = false;
    for (int c = 0; c < state->client_count; c++) {
      if (state->clients[c]->type == CLIENT_HUB &&
          state->clients[c]->authenticated && peer->fd > 0 &&
          state->clients[c]->fd == peer->fd) { online = true; break; }
    }
    char pname[64];
    roster_clean(pname, sizeof(pname),
                 peer->friendly_name[0] ? peer->friendly_name : peer->ip);
    written = snprintf(buf + offset, max_len - offset, "H|1|%s|%s|%d|%lld|%s\n",
                       pname[0] ? pname : "peer", puuid[0] ? puuid : "-",
                       online ? 1 : 0,
                       (long long)(peer->remote_started
                                       ? now - peer->remote_started : 0),
                       peer->remote_version[0] ? peer->remote_version : "-");
    if (written < 0 || written >= max_len - offset) break;
    offset += written;

    if (!puuid[0]) continue;
    for (int r = 0; r < state->roster_count; r++) {
      bot_roster_t *e = &state->roster[r];
      if (strcmp(e->hub_uuid, puuid) != 0) continue;
      if (max_len - offset <= TREE_ROW_MAX) break;
      written = snprintf(buf + offset, max_len - offset,
                         "B|2|%s|%s|%s|%s|%lld\n",
                         e->nick[0] ? e->nick : "-", e->bot_uuid,
                         e->version[0] ? e->version : "-",
                         e->server[0] ? e->server : "-",
                         (long long)(e->connected_at ? now - e->connected_at
                                                     : 0));
      if (written < 0 || written >= max_len - offset) break;
      offset += written;
    }
  }

  /* Bots the config knows but nobody currently reports.  'seen' is already
   * persisted and replicated, so this needs no new storage — it is the one
   * place the tree reads the config store, and it reads it read-only. */
  for (int i = 0; i < state->bot_count; i++) {
    bot_config_t *b = &state->bots[i];
    if (!b->is_active) continue;
    if (max_len - offset <= TREE_ROW_MAX) break;

    bool live = false;
    for (int c = 0; c < state->client_count && !live; c++)
      if (state->clients[c]->type == CLIENT_BOT &&
          state->clients[c]->authenticated &&
          strcmp(state->clients[c]->id, b->uuid) == 0)
        live = true;
    for (int r = 0; r < state->roster_count && !live; r++)
      if (strcmp(state->roster[r].bot_uuid, b->uuid) == 0) live = true;
    if (live) continue;

    time_t last_seen = b->last_sync_time;
    char nick[MAX_NICK] = "";
    for (int k = 0; k < b->entry_count; k++) {
      if (strcmp(b->entries[k].key, "seen") == 0) {
        if (b->entries[k].timestamp > last_seen) last_seen = b->entries[k].timestamp;
      } else if (strcmp(b->entries[k].key, "n") == 0) {
        roster_clean(nick, sizeof(nick), b->entries[k].value);
      }
    }
    written = snprintf(buf + offset, max_len - offset, "D|%s|%s|%lld\n",
                       nick[0] ? nick : "-", b->uuid, (long long)last_seen);
    if (written < 0 || written >= max_len - offset) break;
    offset += written;
  }
  return offset;
}

/* Push the assembled tree to every connected bot.  Coalesced per bot so a
 * burst of roster changes collapses to one send per drain cycle. */
static void hub_push_tree_to_bots(hub_state_t *state) {
  int bots = 0;
  for (int i = 0; i < state->client_count; i++)
    if (state->clients[i]->type == CLIENT_BOT && state->clients[i]->authenticated)
      bots++;
  if (bots == 0) return;

  char *payload = malloc(MAX_TREE_PAYLOAD);
  if (!payload) {
    hub_log("[PRESENCE] OOM building bot tree\n");
    return;
  }
  int len = hub_build_tree(state, payload, MAX_TREE_PAYLOAD);
  if (len <= 0) { free(payload); return; }

  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type != CLIENT_BOT || !c->authenticated) continue;
    queued_msg_t *m = queued_msg_new(CMD_BOT_TREE, LANE_BULK,
                                     (const unsigned char *)payload, len);
    if (!m) continue;
    char coalesce[160];
    snprintf(coalesce, sizeof(coalesce), "%s|bot_tree|%s", state->hub_uuid,
             c->id);
    queued_msg_set_coalesce(m, state->hub_uuid, hub_next_lamport_seq(state),
                            coalesce);
    peer_enqueue(c, m);
  }
  free(payload);
}

void hub_presence_tick(hub_state_t *state, time_t now) {
  if (state->hub_started == 0) state->hub_started = now;

  hub_roster_expire(state, now);

  if (now - state->last_presence_gossip >= BOT_PRESENCE_INTERVAL)
    hub_gossip_bot_roster(state);

  /* Push on change, with an unconditional refresh so a bot that missed a
   * frame — or connected between changes — still converges. */
  if (state->tree_dirty || now - state->last_tree_push >= BOT_TREE_REFRESH) {
    state->tree_dirty = false;
    state->last_tree_push = now;
    hub_push_tree_to_bots(state);
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
  /* Change 5: a full-state anti-entropy sync can exceed MAX_BUFFER; bound by
   * the sync-payload ceiling so it is never silently dropped here. */
  if (payload_len > (MAX_SYNC_PAYLOAD - 10))
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

  /* opt 'h' (OPT_HUB_ONLY_MUTATIONS) enforcement point.  When the network is in
   * hub-only-mutation mode the hub is the SOLE authority for privileged record
   * types, and this is what makes the flag *binding* against a rogue or
   * malicious bot.  The matching bot-side guard (ircbot/commands.c:516) only
   * stops a well-behaved bot from issuing the command locally; a modified or
   * compromised bot can ignore it and push the record straight up this path.
   * Rejecting those pushes here ensures a bot cannot mutate admin/oper/usermask/
   * channel/password state under opt 'h'.  These map 1:1 to the bot-side
   * HUB_ONLY_CMDS list: a=+/-admin/chkey, o=+/-oper/chkey, m=+/-usermask,
   * c=join/part.  (p, the retired bot password, is ignored under every opt.)
   * The bot's own runtime identity (nick 'n', hostmask 'h') and its protocol
   * version 'v' are intrinsic state only the bot can report, so they stay
   * accepted.
   * Note: bots cannot clear this flag — 'opt|' updates arrive only via
   * CMD_PEER_SYNC (CLIENT_HUB) or CMD_ADMIN_SET_OPT_FLAGS (CLIENT_ADMIN);
   * the CLIENT_BOT dispatch never reaches process_peer_sync.  Combined with the
   * rejection below, once opt 'h' is set a bot can neither mutate privileged
   * records nor escalate to an admin record that would let it clear the flag. */
  const bool hub_only_mutations =
      (strchr(state->opt_flags, OPT_HUB_ONLY_MUTATIONS) != NULL);

  char work_buf[MAX_BUFFER];
  snprintf(work_buf, sizeof(work_buf), "%s", payload);

  char *saveptr;
  char *line = strtok_r(work_buf, "\n", &saveptr);
  int updates = 0;
  bool proto_upgraded = false;
  bool saw_proto = false;
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

    /* v|<proto>|<unused>: protocol capability (docs/passwordless.md §3.4).
     * Recorded on this connection only; the first v >= 2 earns a fresh
     * config in the new record shapes (below, after the loop). */
    if (type == 'v') {
      saw_proto = true;
      long v = strtol(data, NULL, 10);
      if (v >= BOT_PROTO_PASSWORDLESS && v < 1000 && client->bot_proto < v) {
        client->bot_proto = (int)v;
        proto_upgraded = true;
        hub_log("[HUB] Bot %s speaks protocol v%ld (passwordless)\n",
                client->id, v);
      }
      line = strtok_r(NULL, "\n", &saveptr);
      continue;
    }
    if (type == 'p') {
      hub_log("[HUB] Ignored retired bot-password line from %s "
              "(pre-passwordless bot)\n", client->id);
      line = strtok_r(NULL, "\n", &saveptr);
      continue;
    }

    /* Reject hub-authoritative record types from bots while opt 'h' is active. */
    if (hub_only_mutations &&
        (type == 'a' || type == 'o' || type == 'm' || type == 'c')) {
      hub_log("[HUB] opt 'h' active: REJECTED bot-pushed '%c' record from %s "
              "(hub-authoritative — mutation must originate from hub_admin)\n",
              type, client->id);
      line = strtok_r(NULL, "\n", &saveptr);
      continue;
    }

    // Special handling for different types
    if (type == 'c') {
      // Channel: c|#chan|key|modes|add|timestamp (new) or c|#chan|key|add|timestamp (old)
      char chan[MAX_CHAN], key[MAX_KEY], op[8];
      long long ts;
      int modes_val = 0;
      int parsed;

      /* Try new 5-field: chan|key|modes|op|ts */
      parsed = sscanf(data, "%64[^|]|%30[^|]|%d|%7[^|]|%lld",
                      chan, key, &modes_val, op, &ts);
      if (parsed < 5) {
        /* Try new 5-field without key: chan||modes|op|ts */
        modes_val = 0;
        parsed = sscanf(data, "%64[^|]||%d|%7[^|]|%lld",
                        chan, &modes_val, op, &ts);
        if (parsed >= 4) {
          key[0] = '\0';
        } else {
          /* Old 4-field: chan|key|op|ts */
          modes_val = 0;
          parsed = sscanf(data, "%64[^|]|%30[^|]|%7[^|]|%lld",
                          chan, key, op, &ts);
          if (parsed < 3) {
            parsed = sscanf(data, "%64[^|]||%7[^|]|%lld", chan, op, &ts);
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
        hub_log("[HUB-DEBUG] Channel %s: ts=%lld op=%s modes=%d -> %s\n",
                chan, ts, op, modes_val, accepted ? "ACCEPTED" : "REJECTED");
        if (accepted) {
          updates++;
          /* Sync buffer: include modes for peer hubs */
          int w = snprintf(
              sync_buffer + sync_offset, sizeof(sync_buffer) - sync_offset,
              "b|%s|c|%s|%s|%d|%s|%lld\n",
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
          long long last_used, ts;
          snprintf(uuid,   sizeof(uuid),   "%.*s",(int)(p1-data),data);
          snprintf(mask_s, sizeof(mask_s), "%.*s",(int)(p2-p1-1),p1+1);
          snprintf(act,    sizeof(act),    "%.*s",(int)(p3-p2-1),p2+1);
          last_used = atoll(p3+1);
          ts        = atoll(p4+1);
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
          if (found_m && hub_lww_accepts(ts, is_active, found_m->timestamp,
                                         found_m->is_active)) {
            found_m->is_active = is_active;
            if (last_used > found_m->last_used) found_m->last_used = last_used;
            found_m->timestamp = ts;
            state->config_dirty = true;
            updates++;
            int w = snprintf(sync_buffer+sync_offset, sizeof(sync_buffer)-sync_offset,
                             "m|%s|%s|%s|%lld|%lld\n", uuid, mask_s, act, last_used, ts);
            if (w>0) sync_offset += w;
          }
        }
      }
    } else if (type == 'o' || type == 'a') {
      /* hub_parse_user_record: uuid|name|pubkey|act|seen|ts| (or a legacy
       * password shape, password dropped).  LWW by timestamp.  Outside opt
       * 'h' the network lets bots create/re-key users (+admin/+oper/chkey);
       * a keyless push never erases a key the hub already holds. */
      hub_user_record_t in;
      if (hub_parse_user_record(data, type, &in, NULL)) {
        hub_user_record_t *found_u = NULL;
        for (int ui = 0; ui < state->user_record_count; ui++) {
          if (strcmp(state->user_records[ui].uuid, in.uuid) == 0) {
            found_u = &state->user_records[ui]; break;
          }
        }
        if (!found_u && state->user_record_count < MAX_HUB_USER_RECORDS) {
          found_u = &state->user_records[state->user_record_count++];
          memset(found_u, 0, sizeof(*found_u));
          snprintf(found_u->uuid, sizeof(found_u->uuid), "%s", in.uuid);
        }
        if (found_u && hub_lww_accepts(in.timestamp, in.is_active,
                                       found_u->timestamp, found_u->is_active)) {
          snprintf(found_u->name, sizeof(found_u->name), "%s", in.name);
          found_u->type      = type;
          found_u->is_active = in.is_active;
          if (in.last_seen > found_u->last_seen) found_u->last_seen = in.last_seen;
          found_u->timestamp = in.timestamp;
          if (in.has_pubkey) {
            snprintf(found_u->pubkey_b64, sizeof(found_u->pubkey_b64), "%s",
                     in.pubkey_b64);
            found_u->has_pubkey = true;
          }
          state->config_dirty = true;
          updates++;
          char uline[USER_LINE_MAX];
          int w = hub_format_user_record(found_u, false, uline, sizeof(uline));
          if (w > 0 && w < (int)sizeof(uline) &&
              w < (int)sizeof(sync_buffer) - sync_offset) {
            memcpy(sync_buffer + sync_offset, uline, (size_t)w);
            sync_offset += w;
            sync_buffer[sync_offset] = '\0';
          }
        }
      }
    } else if (type == 'h') {
      // Hostmask: h|nick!user@host|timestamp
      char hostmask[256];
      long long ts;
      if (sscanf(data, "%255[^|]|%lld", hostmask, &ts) == 2) {
        bool accepted = hub_storage_update_entry(state, client->id, "h", hostmask, "", "", ts);
        hub_log("[HUB-DEBUG] Hostmask %s: ts=%lld -> %s\n", hostmask, ts, accepted ? "ACCEPTED" : "REJECTED");
        if (accepted) {
          updates++;
          // Broadcast in bot entry format: b|uuid|h|hostmask|timestamp
          int w = snprintf(sync_buffer + sync_offset,
                           sizeof(sync_buffer) - sync_offset, "b|%s|h|%s|%lld\n",
                           client->id, hostmask, ts);
          if (w > 0)
            sync_offset += w;
        }
      }
    } else if (type == 'n') {
      // Nick: n|nickname|timestamp
      char nick[MAX_NICK];
      long long ts;
      /* %31 not %32: a 32-char field + NUL would write 33 bytes into nick[32]
       * (1-byte stack overflow).  Reachable by any authenticated bot via an
       * 'n|' config-push record. */
      if (sscanf(data, "%31[^|]|%lld", nick, &ts) == 2) {
        bool accepted = hub_storage_update_entry(state, client->id, "n", nick, "", "", ts);
        hub_log("[HUB-DEBUG] Nick %s: ts=%lld -> %s\n", nick, ts, accepted ? "ACCEPTED" : "REJECTED");
        if (accepted) {
          updates++;
          // Broadcast in bot entry format: b|uuid|n|nickname|timestamp
          int w = snprintf(sync_buffer + sync_offset,
                           sizeof(sync_buffer) - sync_offset, "b|%s|n|%s|%lld\n",
                           client->id, nick, ts);
          if (w > 0)
            sync_offset += w;
        }
      }
    }

    line = strtok_r(NULL, "\n", &saveptr);
  }

  /* Every passwordless bot puts v| in each push, so its absence marks an old
   * build.  Say so once per connection, and sync it right away (below): its
   * first config replaces every password it still holds with an empty slot,
   * so it must not wait for the next periodic broadcast (§3.4, §9). */
  bool legacy_first = false;
  if (!saw_proto && client->bot_proto == 0) {
    client->bot_proto = 1;
    legacy_first = true;
    hub_log("[HUB] Bot %s is a pre-passwordless build (no v|2): it gets "
            "legacy records with empty password slots; upgrade it\n",
            client->id);
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
  } else if (proto_upgraded || legacy_first) {
    /* proto_upgraded: this connection just proved it is passwordless-capable
     * — replace the legacy-shaped config it may hold (no b| keys) right away.
     * legacy_first: an old build — empty its stored passwords right away. */
    send_config_to_bot(state, client);
  }
}

void hub_generate_sync_packet(hub_state_t *state, char *buffer, int max_len) {
  int offset = 0;
  int written;
  buffer[0] = 0;

  // 1. Include global entries (c, m, o, a, p)
  // Note: h/n/w/x are hub-only local metadata and never belong here
  // - h/n: hub name/bind settings (shouldn't exist in global_entries)
  // - w/x: allowlist/denylist, kept in ip_allow/ip_deny (local-only)
  // Bot-specific h/n (like b|uuid|h|..., b|uuid|n|...) are synced in the bot loop below
  for (int i = 0; i < state->global_entry_count; i++) {
    config_entry_t *e = &state->global_entries[i];
    /* Skip local-only and entries now handled via typed arrays */
    if (strcmp(e->key, "h") == 0 || strcmp(e->key, "n") == 0 ||
        strcmp(e->key, "w") == 0 || strcmp(e->key, "x") == 0 ||
        strcmp(e->key, "a") == 0 || strcmp(e->key, "o") == 0 ||
        strcmp(e->key, "m") == 0 || strcmp(e->key, "p") == 0)
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

  /* User records so peer hubs share admin/oper records, in the passwordless
   * shape uuid|name|pubkey|act|seen|ts| (peers are HUBv3, so they parse it). */
  for (int i = 0; i < state->user_record_count; i++) {
    hub_user_record_t *u = &state->user_records[i];
    if (max_len - offset <= 1) break;
    written = hub_format_user_record(u, false, buffer + offset,
                                     (size_t)(max_len - offset));
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

  /* Include network opt flag string (peers must converge on this). */
  if (max_len - offset > 1 && state->opt_flags_ts > 0) {
    written = snprintf(buffer + offset, max_len - offset, "opt|%s|%ld\n",
                       state->opt_flags[0] ? state->opt_flags : "",
                       (long)state->opt_flags_ts);
    if (written > 0 && written < (max_len - offset)) offset += written;
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
      if (hub_lww_accepts(ts, hub_global_value_active(value),
                          state->global_entries[i].timestamp,
                          hub_global_value_active(state->global_entries[i].value))) {
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

/* Split a stored global 'c' entry value into its parts.
 *
 * Two shapes exist because two writers produce them:
 *   3-field  chan|key|op        — CMD_ADMIN_ADD/DEL_CHANNEL and legacy records
 *   4-field  chan|key|modes|op  — process_bot_config_push (bots report modes)
 * Both share the same anchors — channel is the first field, op is the last — so
 * split on those instead of counting fields.  Whatever sits between is the key,
 * optionally followed by the modes.  Reading op as the *last* field is what makes
 * the "del" tombstone check reliable across both shapes: a positional parse reads
 * "0|del" as the op on the 4-field form and treats a deleted channel as live.
 *
 * Any out-param may be NULL.  Returns false only when value has no '|' at all. */
static bool parse_global_channel_value(const char *value,
                                       char *chan_out, size_t chan_len,
                                       char *key_out, size_t key_len,
                                       int *modes_out,
                                       char *op_out, size_t op_len) {
  if (chan_out && chan_len) chan_out[0] = '\0';
  if (key_out && key_len)   key_out[0]  = '\0';
  if (op_out && op_len)     op_out[0]   = '\0';
  if (modes_out)            *modes_out  = 0;
  if (!value) return false;

  const char *first = strchr(value, '|');
  const char *last  = strrchr(value, '|');
  if (!first || !last) return false;

  if (chan_out && chan_len) {
    size_t n = (size_t)(first - value);
    if (n >= chan_len) n = chan_len - 1;
    memcpy(chan_out, value, n);
    chan_out[n] = '\0';
  }
  if (op_out && op_len) {
    size_t n = strlen(last + 1);
    if (n >= op_len) n = op_len - 1;
    memcpy(op_out, last + 1, n);
    op_out[n] = '\0';
  }

  /* Middle field(s): "key" (3-field) or "key|modes" (4-field). */
  if (last > first) {
    char middle[128];
    size_t n = (size_t)(last - first - 1);
    if (n >= sizeof(middle)) n = sizeof(middle) - 1;
    memcpy(middle, first + 1, n);
    middle[n] = '\0';

    char *sep = strrchr(middle, '|');
    if (sep) {
      *sep = '\0';
      if (modes_out) *modes_out = atoi(sep + 1);
    }
    if (key_out && key_len) {
      size_t klen = strlen(middle);
      if (klen >= key_len) klen = key_len - 1;
      memcpy(key_out, middle, klen);
      key_out[klen] = '\0';
    }
  }
  return true;
}

/* Modes currently recorded for a channel, or 0 when unknown.  The admin add path
 * has no modes of its own — they only ever arrive from a bot reporting a live
 * MODE change — so a re-add must carry forward what is already stored.  Global
 * entries are overwritten wholesale once the timestamp wins
 * (hub_storage_update_global_entry), so not carrying them forward erases them.
 * Matched case-sensitively on the channel name, same as the storage layer. */
static int global_channel_modes(hub_state_t *state, const char *chan) {
  for (int i = 0; i < state->global_entry_count; i++) {
    if (strcmp(state->global_entries[i].key, "c") != 0)
      continue;
    char stored_chan[128];  /* matches the admin handlers' channel buffers */
    int modes = 0;
    if (!parse_global_channel_value(state->global_entries[i].value,
                                    stored_chan, sizeof(stored_chan),
                                    NULL, 0, &modes, NULL, 0))
      continue;
    if (strcmp(stored_chan, chan) == 0)
      return modes;
  }
  return 0;
}

static void process_peer_sync(hub_state_t *state, char *payload,
                              int origin_fd) {
  char *saveptr;
  /* Change 5: a full-state peer sync can far exceed MAX_BUFFER (usermasks
   * alone reach tens of KB), so both the tokenizing copy and the re-forward
   * buffer are heap-allocated to the sync ceiling.  A stack MAX_BUFFER here
   * silently truncated the sync, dropping every record past 16 KB. */
  const size_t sync_cap = MAX_SYNC_PAYLOAD;
  char *work_buf = malloc(sync_cap);
  char *forward_buf = malloc(sync_cap);
  if (!work_buf || !forward_buf) {
    free(work_buf);
    free(forward_buf);
    return;
  }
  snprintf(work_buf, sync_cap, "%s", payload);

  char *line = strtok_r(work_buf, "\n", &saveptr);
  int updates = 0;
  int bot_push_updates = 0; /* only keys bots actually consume; gates full config push */
  int fwd_offset = 0;
  forward_buf[0] = 0;

  while (line) {
    // Check for PURGE command
    if (strncmp(line, "PURGE|", 6) == 0) {
      time_t cutoff;
      char purge_id[PURGE_ID_HEX + 1];
      if (!parse_purge_line(line, &cutoff, purge_id)) {
        hub_log("[MESH] Dropped malformed PURGE line from peer\n");
      } else {
        hub_log("[MESH] Received PURGE from peer: cutoff=%ld id=%s\n",
                (long)cutoff, purge_id[0] ? purge_id : "-");

        // DEDUPLICATION: Check if this PURGE was recently seen
        if (is_purge_recent(state, cutoff, purge_id)) {
          hub_log("[MESH] PURGE cutoff=%ld id=%s already processed recently, skipping to prevent loop\n",
                  (long)cutoff, purge_id[0] ? purge_id : "-");
        } else {
          // Record this PURGE and process it
          record_recent_purge(state, cutoff, purge_id);

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

    /* Handle 'opt|<letters>|<ts>' from peer hubs (mesh-replicated opt flags),
     * including the 'opt||<ts>' of a clear.  Adopt it if newer than ours. */
    if (strncmp(line, "opt|", 4) == 0) {
      char incoming_flags[MAX_OPT_FLAGS + 1];
      time_t incoming_ts;
      if (hub_parse_opt_value(line + 4, incoming_flags, &incoming_ts)) {
        if (hub_opt_accepts(incoming_ts, incoming_flags, state->opt_flags_ts,
                            state->opt_flags)) {
          memcpy(state->opt_flags, incoming_flags, sizeof(incoming_flags));
          state->opt_flags_ts = incoming_ts;
          state->config_dirty = true;
          updates++;
          bot_push_updates++;
          if (fwd_offset < (int)sync_cap - 64) {
            int wfwd = snprintf(forward_buf + fwd_offset,
                                sync_cap - fwd_offset,
                                "%s\n", line);
            if (wfwd > 0) fwd_offset += wfwd;
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
                /* hub_parse_user_record: uuid|name|pubkey|act|seen|ts| (a
                 * legacy password shape parses too; the password is dropped). */
                hub_user_record_t in;
                if (hub_parse_user_record(vstart, key[0], &in, NULL)) {
                  const char *uuid = in.uuid, *uname = in.name;
                  long long last_seen = (long long)in.last_seen;
                  long long ts = (long long)in.timestamp;
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
                  if (!discard_incoming && found_u &&
                      hub_lww_accepts((time_t)ts, in.is_active,
                                      found_u->timestamp, found_u->is_active)) {
                    snprintf(found_u->name, sizeof(found_u->name), "%s", uname);
                    found_u->type      = key[0];
                    found_u->is_active = in.is_active;
                    if (last_seen > found_u->last_seen) found_u->last_seen = last_seen;
                    found_u->timestamp = ts;
                    if (in.has_pubkey) {
                      snprintf(found_u->pubkey_b64, sizeof(found_u->pubkey_b64),
                               "%s", in.pubkey_b64);
                      found_u->has_pubkey = true;
                    }
                    state->config_dirty = true;
                    updates++;
                    bot_push_updates++; /* admin/oper name change — bots need this */
                    /* Forward our canonical a|/o| line, never the raw one: a
                     * legacy-shaped line must not carry a password onward. */
                    char uline[USER_LINE_MAX];
                    int ul = hub_format_user_record(found_u, false, uline,
                                                    sizeof(uline));
                    if (ul > 0 && ul < (int)sizeof(uline) &&
                        fwd_offset < (int)sync_cap - USER_LINE_MAX) {
                      memcpy(forward_buf + fwd_offset, uline, (size_t)ul);
                      fwd_offset += ul;
                      forward_buf[fwd_offset] = '\0';
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
                  long long last_used, ts;
                  snprintf(uuid,   sizeof(uuid),   "%.*s",(int)(pp1-vstart),vstart);
                  snprintf(mask_s, sizeof(mask_s), "%.*s",(int)(pp2-pp1-1),pp1+1);
                  snprintf(act,    sizeof(act),    "%.*s",(int)(pp3-pp2-1),pp2+1);
                  last_used = atoll(pp3+1); ts = atoll(pp4+1);
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
                  if (found_m && hub_lww_accepts(ts, is_active, found_m->timestamp,
                                                 found_m->is_active)) {
                    found_m->is_active = is_active;
                    if (last_used > found_m->last_used) found_m->last_used = last_used;
                    found_m->timestamp = ts;
                    state->config_dirty = true;
                    updates++;
                    bot_push_updates++; /* mask record — bots need this */
                    if (fwd_offset < (int)sync_cap - 200) {
                      int w = snprintf(forward_buf+fwd_offset,
                                       sync_cap-fwd_offset,
                                       "%s\n", line);
                      if (w>0) fwd_offset += w;
                    }
                  }
                }
                line = strtok_r(NULL, "\n", &saveptr);
                continue;
              }
            }

            /* Retired password-era shapes — the shared bot password p| and
             * the pre-UUID a|<password>|<ts> / o|<mask>|<password>|.. rows —
             * are dropped, never stored or forwarded. */
            if (strcmp(key, "p") == 0 || is_user_key) {
              line = strtok_r(NULL, "\n", &saveptr);
              continue;
            }

            /* Old-format or non-user global key: store in global_entries */
            char *p_last = strrchr(p1 + 1, '|');
            if (p_last && p_last > p1) {
              char val[1024];
              size_t val_len = p_last - (p1 + 1);
              if (val_len < sizeof(val)) {
                memcpy(val, p1 + 1, val_len);
                val[val_len] = 0;
                long long ts = atoll(p_last + 1);

                if (store_global_entry_raw(state, key, val, ts)) {
                  updates++;
                  bot_push_updates++; /* channel/password/global — bots need this */
                  // Forward to other peers
                  if (sync_cap - fwd_offset > 1200) {
                    int w = snprintf(forward_buf + fwd_offset,
                                     sync_cap - fwd_offset,
                                     "%s|%s|%lld\n", key, val, ts);
                    if (w > 0 && w < (int)(sync_cap - fwd_offset)) {
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
    long long ts;

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
          ts = atoll(p2 + 1);
          if (hub_storage_update_entry(state, uuid, key, "", "", "", ts)) {
            updates++;
            if (sync_cap - fwd_offset > 200) {
              int w = snprintf(forward_buf + fwd_offset,
                               sync_cap - fwd_offset,
                               "b|%s|%s|%lld\n", uuid, key, ts);
              if (w > 0 && w < (int)(sync_cap - fwd_offset))
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
          ts = atoll(p3 + 1);

          // For c/m/o keys, parse the combined value format.  The split
          // works on a scratch copy: val itself is re-forwarded to the other
          // peers below and must leave exactly as it arrived.  Splitting val
          // in place forwarded "b|uuid|c|#chan|ts" -- no key, modes or op --
          // which the next hub stored as an add, turning deletes into adds
          // one hop out.
          char parsed_val[512] = "", parsed_extra[256] = "", parsed_op[16] = "";
          char split[sizeof(val)];
          memcpy(split, val, strlen(val) + 1);
          if (strcmp(key, "c") == 0 || strcmp(key, "o") == 0) {
            /* Format: chan|key[|modes]|op  (3 or 4 fields)
             * Use first pipe for chan, last pipe for op, middle = extra */
            char *vp1 = strchr(split, '|');
            if (vp1) {
              *vp1 = 0;
              size_t len = strlen(split);
              if (len >= sizeof(parsed_val)) len = sizeof(parsed_val) - 1;
              memcpy(parsed_val, split, len);
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
            char *vp1 = strchr(split, '|');
            if (vp1) {
              *vp1 = 0;
              size_t len = strlen(split);
              if (len >= sizeof(parsed_val)) len = sizeof(parsed_val) - 1;
              memcpy(parsed_val, split, len);
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

            if (sync_cap - fwd_offset > 1200) {
              int w = snprintf(forward_buf + fwd_offset,
                               sync_cap - fwd_offset,
                               "b|%s|%s|%s|%lld\n", uuid, key, val, ts);
              if (w > 0 && w < (int)(sync_cap - fwd_offset)) {
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

  free(work_buf);
  free(forward_buf);
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

  // --- Purge tombstoned mask_records, and masks whose user is gone ---
  /* A mask with no user record left (its user purged above or earlier) can
   * never authenticate anyone and only holds a slot of the shared table.
   * Such orphans were left live on peers and bots by user deletes that did
   * not send the masks' tombstones; every hub applies the same rule on the
   * same PURGE, so they converge away. */
  hub_mask_record_t new_masks[MAX_HUB_USER_MASKS];
  int new_mask_count = 0;
  for (int i = 0; i < state->mask_record_count; i++) {
    bool owned = false;
    for (int u = 0; u < state->user_record_count; u++) {
      if (strcmp(state->user_records[u].uuid, state->mask_records[i].uuid) == 0) {
        owned = true;
        break;
      }
    }
    if (!owned ||
        (!state->mask_records[i].is_active &&
         (cutoff == 0 || state->mask_records[i].timestamp < cutoff))) {
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

  /* Local bots: first the purged config, then the PURGE line itself.
   * hub_broadcast_config_to_bots only logs its line and re-sends each bot its
   * full config — that replaces a bot's user/mask tables, but channel
   * tombstones are merged on the bot and only a PURGE| line removes them.
   * The PURGE frame is queued behind the (coalesced) config push on the same
   * lane, so a pre-purge config still queued cannot re-add what it purged. */
  char purge_msg[64];
  int purge_len = snprintf(purge_msg, sizeof(purge_msg), "PURGE|%lld\n",
                           (long long)cutoff);
  hub_broadcast_config_to_bots(state, purge_msg);
  for (int i = 0; purge_len > 0 && i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type != CLIENT_BOT || !c->authenticated) continue;
    queued_msg_t *m = queued_msg_new(CMD_CONFIG_DATA, LANE_BULK,
                                     (const unsigned char *)purge_msg,
                                     purge_len);
    if (!m) {
      hub_log("[PURGE] OOM queueing PURGE for bot %s\n", c->id);
      continue;
    }
    if (!peer_enqueue(c, m))
      hub_log("[PURGE] could not queue PURGE for bot %s\n", c->id);
  }

  return purged_count;
}

/* CMD_ADMIN_ADD/DEL_ALLOWLIST/DENYLIST (list 'w' or 'x').  The lists are
 * local to this hub: nothing is sent to peers or bots.  A change after which
 * the admin's own address could not connect is refused and rolled back; the
 * inbound connections a change refuses are closed by hub_maintenance. */
static bool admin_ip_acl_change(hub_state_t *state, hub_client_t *client,
                                char list, bool add, const char *payload) {
  const char *name = list == 'w' ? "allowlist" : "denylist";
  char msg[320];
  hub_ip_acl_t e;

  if (!payload || !payload[0])
    return send_response(state, client, "ERROR: Missing IP pattern.");
  if (!hub_ip_acl_parse(payload, &e)) {
    snprintf(msg, sizeof(msg), "ERROR: '%.40s' is not an IPv4 address or CIDR "
             "(e.g. 192.168.1.5 or 10.0.0.0/8).", payload);
    return send_response(state, client, msg);
  }

  hub_ip_acl_t *l = list == 'w' ? state->ip_allow : state->ip_deny;
  int *count = list == 'w' ? &state->ip_allow_count : &state->ip_deny_count;
  hub_ip_acl_t saved[MAX_IP_ACL_ENTRIES];
  int saved_count = *count;
  memcpy(saved, l, sizeof(saved));

  if (add) {
    e.added = time(NULL);
    ip_acl_add_t r = hub_ip_acl_add(state, list, &e);
    if (r != IP_ACL_ADDED) {
      if (r == IP_ACL_DUPLICATE)
        snprintf(msg, sizeof(msg), "ERROR: %s is already on the %s.", e.pattern, name);
      else
        snprintf(msg, sizeof(msg), "ERROR: The %s is full (%d entries).", name,
                 MAX_IP_ACL_ENTRIES);
      return send_response(state, client, msg);
    }
  } else if (!hub_ip_acl_remove(state, list, &e)) {
    snprintf(msg, sizeof(msg), "ERROR: %s is not on the %s.", e.pattern, name);
    return send_response(state, client, msg);
  }

  if (!hub_ip_acl_permits(state, client->ip)) {
    memcpy(l, saved, sizeof(saved));
    *count = saved_count;
    snprintf(msg, sizeof(msg), "ERROR: Refused: your own address %s could not "
             "connect after this change.%s", client->ip,
             list == 'w' ? " Allow it first." : "");
    return send_response(state, client, msg);
  }

  int closing = 0;
  for (int i = 0; i < state->client_count; i++) {
    const hub_client_t *c = state->clients[i];
    if (c != client && c->inbound && !hub_ip_acl_permits(state, c->ip))
      closing++;
  }
  state->ip_acl_changed = true;
  state->config_dirty = true;
  hub_log("[ACCESS_CONTROL] %s %s %s by %s\n", e.pattern,
          add ? "added to" : "removed from", name, client->id);

  int off = snprintf(msg, sizeof(msg), "SUCCESS: %s %s %s.", e.pattern,
                     add ? "added to" : "removed from", name);
  if (list == 'w' && add && *count == 1)
    off += snprintf(msg + off, sizeof(msg) - (size_t)off,
                    " The allowlist is now on: only listed addresses may connect.");
  else if (list == 'w' && !add && *count == 0)
    off += snprintf(msg + off, sizeof(msg) - (size_t)off,
                    " The allowlist is now empty: any address may connect.");
  if (closing > 0)
    snprintf(msg + off, sizeof(msg) - (size_t)off,
             " Closing %d existing connection(s) it no longer permits.", closing);
  return send_response(state, client, msg);
}

/* payload is NUL-terminated for the text opcodes; payload_len is the byte
 * count the frame carried, for the binary ones (a log level of 0 or a log size
 * with a zero byte has strlen < its real length). */
static bool handle_admin_command(hub_state_t *state, hub_client_t *client,
                                 int cmd, char *payload, int payload_len) {
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
      /* v3: per-bot independent keys.  Only the bot can rekey — it owns its
       * private key.  The bot's 'rekey' admin command regenerates the keypair
       * locally and pushes the new PUBLIC key to us over its authenticated
       * session (we store it as the bot's 'pub' entry and fan it out to peers
       * via auto-sync).  We deliberately do NOT disconnect the bot here: it
       * needs that active session to push the new pub, and it reconnects
       * itself with the new key as the final step of 'rekey'. */
      bool bot_online = false;
      for (int i = 0; i < state->client_count; i++) {
        if (state->clients[i]->type == CLIENT_BOT &&
            strcmp(state->clients[i]->id, payload) == 0) {
          bot_online = true;
          break;
        }
      }
      char msg[640];
      snprintf(msg, sizeof(msg),
               "INSTRUCT|%s|rekey is bot-local (only the bot holds its private "
               "key). As an admin, send the bot the command 'rekey' through "
               "your IRC client's ircbot auth script (a sealed ~A2 command "
               "signed with your key).\n"
               "The bot generates a new keypair, pushes its new pubkey here, "
               "and reconnects; peers auto-sync. Bot is currently %s.",
               payload,
               bot_online ? "ONLINE — you can rekey now"
                          : "OFFLINE — wait for it to reconnect first");
      return send_response(state, client, msg);
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
  case CMD_ADMIN_DEL: {
    time_t del_ts = 0;
    if (payload && hub_storage_delete(state, payload, &del_ts)) {
      // Disconnect bot if currently connected
      for (int i = 0; i < state->client_count; i++) {
        if (state->clients[i]->type == CLIENT_BOT &&
            strcmp(state->clients[i]->id, payload) == 0) {
          hub_log("[ADMIN] Disconnecting deleted bot %s\n", payload);
          hub_disconnect_client(state, state->clients[i]);
          break;
        }
      }

      /* Peers store the same tombstone (same stamp); every bot gets a config
       * that no longer lists the deleted bot and ends in the T| marker, so
       * it drops the bot from its trusted list (no more ~B2 or op grants). */
      char sync[256];
      snprintf(sync, sizeof(sync), "b|%s|d|1|%lld\n", payload,
               (long long)del_ts);
      hub_broadcast_sync_to_peers(state, sync, -1);
      hub_broadcast_config_to_bots(state, sync);
      return send_response(state, client, "SUCCESS: Deleted & Synced.");
    }
    return send_response(state, client, "ERROR: Not found.");
  }

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
        if (t) strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", t);
        else   snprintf(time_buf, sizeof(time_buf), "invalid");
      }

      /* Key fingerprint: compare with what a client script prints on ~A2A
       * auth, and with the bot's own 'status'. */
      char bfp[KEY_FP_LEN + 1] = "(no key)";
      for (int k = 0; k < b->entry_count; k++)
        if (strcmp(b->entries[k].key, "pub") == 0) {
          hub_crypto_key_fingerprint_b64(b->entries[k].value, bfp);
          break;
        }

      // Build output line
      written =
          snprintf(response + offset, LIST_FULL_SZ - offset,
                   "[%s] %-15s | Status: %-10s | Peer: %-20s | Key: %s | Last: %s\n",
                   b->uuid, nick, is_connected ? "CONNECTED" : "OFFLINE",
                   is_connected ? connected_to : "N/A", bfp, time_buf);

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
        unsigned long uidx = 0;
        int idx = hub_parse_uint(payload, 999, &uidx) ? (int)uidx : 0;
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
        snprintf(sync, sizeof(sync), "%s|t||%ld\n", target_uuid, (long)now);
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
      snprintf(sync, sizeof(sync), "%s|t||%ld\n", payload, (long)now);
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
    /* Change 5: heap the full-state buffer (MAX_SYNC_PAYLOAD > stack budget). */
    char *full_sync = malloc(MAX_SYNC_PAYLOAD);
    if (!full_sync)
      return send_response(state, client, "ERROR: OOM building sync.");
    hub_generate_sync_packet(state, full_sync, MAX_SYNC_PAYLOAD);
    hub_broadcast_sync_to_peers(state, full_sync, -1);
    free(full_sync);
    return send_response(state, client, "SUCCESS: Full Sync broadcasted.");
  }

  case CMD_ADMIN_CREATE_BOT: {
    /* v3: bot-provided identity.  Payload: "NICK|UUID|PUBKEY_B64".
     * The hub no longer generates the bot keypair — the bot did, locally
     * during 'ircbot -setup'.  Only the public key reaches the hub. */
    if (!payload || !*payload) {
      send_response(state, client, "ERROR|Empty payload");
      return true;
    }
    char nick[64] = {0}, uuid_in[64] = {0}, pubkey_in[256] = {0};
    if (sscanf(payload, "%63[^|]|%63[^|]|%255s", nick, uuid_in, pubkey_in) < 3) {
      send_response(state, client, "ERROR|Format: NICK|UUID|PUBKEY_B64");
      return true;
    }
    if (strlen(uuid_in) != 36 || uuid_in[8] != '-' || uuid_in[13] != '-' ||
        uuid_in[18] != '-' || uuid_in[23] != '-') {
      send_response(state, client, "ERROR|Invalid UUID format");
      return true;
    }
    if (strlen(pubkey_in) != COMBINED_KEY_B64) {
      send_response(state, client, "ERROR|pubkey must be 88-char base64");
      return true;
    }
    {
      int dec_len = 0;
      unsigned char *dec = base64_decode(pubkey_in, &dec_len);
      if (!dec || dec_len != COMBINED_KEY_LEN) {
        if (dec) free(dec);
        send_response(state, client, "ERROR|pubkey not valid 64-byte Curve25519");
        return true;
      }
      free(dec);
    }
    /* Reject if UUID already exists */
    for (int i = 0; i < state->bot_count; i++) {
      if (strcmp(state->bots[i].uuid, uuid_in) == 0) {
        send_response(state, client, "ERROR|Bot UUID already registered");
        return true;
      }
    }
    hub_state_add_bot_memory(state, uuid_in, nick, pubkey_in);
    state->config_dirty = true;

    char ok[128];
    snprintf(ok, sizeof(ok), "SUCCESS|%s|registered", uuid_in);
    send_response(state, client, ok);
  }
    return true;

  case CMD_ADMIN_REGEN_KEYS: {
    /* Local-only hub rekey: generate a new Curve25519 keypair, save it
     * encrypted in .irchub.cnf, dump the new public key for re-distribution.
     * Independent per-hub keys: the new pubkey is NOT pushed to peers; each
     * peer hub must re-register it via 'Set Peer Pubkey' in hub_admin.
     * Bots that connect here must also re-run 'sethubpub'. */
    unsigned char priv64[64], pub64[64];
    if (hub_crypto_generate_combined_keypair(priv64, pub64)) {
      hub_crypto_split_combined(priv64, state->hub_ed25519_priv, state->hub_x25519_priv);
      hub_crypto_split_combined(pub64,  state->hub_ed25519_pub,  state->hub_x25519_pub);
      char *pub_b64 = base64_encode(pub64, 64);
      secure_wipe(priv64, 64);
      if (!pub_b64) return send_response(state, client, "ERROR: Base64 encoding failed.");

      state->hub_keys_loaded = true;
      state->config_dirty = true;

      /* Disconnect peers + bots so they must reauthenticate (and rediscover
       * that this hub's pubkey changed). */
      for (int i = 0; i < state->client_count; i++) {
        if (state->clients[i]->type == CLIENT_HUB ||
            state->clients[i]->type == CLIENT_BOT) {
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
      free(pub_b64);
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

  case CMD_ADMIN_SET_PUBKEY: {
    if (!payload || strlen(payload) < COMBINED_KEY_B64)
      return send_response(state, client, "ERROR: Empty Payload.");
    unsigned char want[COMBINED_KEY_LEN];
    if (!hub_crypto_pubkey_b64_decode(payload, want))
      return send_response(state, client, "ERROR: Invalid Curve25519 public key.");
    /* The public key is not a setting of its own: it is fixed by the private
     * key.  Storing any other key made every signature this hub produces
     * (admin logins, bot and peer handshakes) fail against what it announces
     * — an admin lockout.  Accept only the key the private key derives; a new
     * identity goes through Set Private Key or Regenerate. */
    if (!state->hub_keys_loaded)
      return send_response(state, client,
                           "ERROR: No private key loaded; cannot verify the public key.");
    unsigned char priv[64], derived[COMBINED_KEY_LEN];
    memcpy(priv, state->hub_ed25519_priv, 32);
    memcpy(priv + 32, state->hub_x25519_priv, 32);
    bool derived_ok = hub_crypto_combined_pub_from_priv(priv, derived);
    secure_wipe(priv, sizeof(priv));
    if (!derived_ok || CRYPTO_memcmp(derived, want, COMBINED_KEY_LEN) != 0)
      return send_response(state, client,
                           "ERROR: That public key does not belong to this hub's "
                           "private key (use Set Private Key or Regenerate to "
                           "change the hub identity).");
    hub_crypto_split_combined(derived, state->hub_ed25519_pub, state->hub_x25519_pub);
    state->config_dirty = true;
    return send_response(state, client, "SUCCESS: Public Key Imported & Saved.");
  }

  case CMD_ADMIN_ADD_PEER:
    if (payload && strlen(payload) > 0) {
      char ip[256], uuid[64], name[64], pubkey_b64[128];
      int port;
      memset(uuid, 0, sizeof(uuid));
      memset(name, 0, sizeof(name));
      memset(pubkey_b64, 0, sizeof(pubkey_b64));

      /* Parse: IP:PORT:UUID:NAME[:PUBKEY_B64]
       * UUID and NAME optional; PUBKEY_B64 is required (refused below when
       * missing) and must be a valid 88-char Curve25519 combined key —
       * the peer is authenticated by its HUBv3 signature (the key is
       * required; there is no shared secret).
       */
      int args = sscanf(payload, "%255[^:]:%d:%63[^:]:%63[^:]:%127s",
                        ip, &port, uuid, name, pubkey_b64);

      if (args >= 2) {
        if (state->peer_count < MAX_PEERS) {
          if (uuid[0]) {
            for (int i = 0; i < state->peer_count; i++) {
              if (state->peers[i].uuid[0] &&
                  strcmp(state->peers[i].uuid, uuid) == 0) {
                return send_response(state, client,
                                   "ERROR: Peer with this UUID already exists.");
              }
            }
          }

          hub_peer_config_t *np = &state->peers[state->peer_count];
          memset(np, 0, sizeof(*np));

          size_t ip_len = strlen(ip);
          size_t max_len = sizeof(np->ip) - 1;
          size_t copy_len = (ip_len < max_len) ? ip_len : max_len;
          memcpy(np->ip, ip, copy_len);
          np->ip[copy_len] = '\0';
          np->port = port;

          if (uuid[0])
            snprintf(np->uuid, sizeof(np->uuid), "%s", uuid);
          if (name[0])
            snprintf(np->friendly_name, sizeof(np->friendly_name), "%s", name);

          np->has_pubkey = false;
          if (pubkey_b64[0]) {
            int dec_len = 0;
            unsigned char *dec = base64_decode(pubkey_b64, &dec_len);
            if (dec && dec_len == COMBINED_KEY_LEN) {
              memcpy(np->ed_pub,     dec,                   ED25519_KEY_LEN);
              memcpy(np->x25519_pub, dec + ED25519_KEY_LEN, X25519_KEY_LEN);
              np->has_pubkey = true;
            } else {
              if (dec) { secure_wipe(dec, (size_t)(dec_len > 0 ? dec_len : 0)); free(dec); }
              return send_response(state, client,
                                   "ERROR: pubkey must be 88-char base64 of "
                                   "64-byte Curve25519 combined key.");
            }
            if (dec) { secure_wipe(dec, (size_t)dec_len); free(dec); }
          }

          if (!np->has_pubkey)
            return send_response(state, client,
                                 "ERROR: Pubkey is required. "
                                 "Supply the 88-char base64 Curve25519 combined key.");

          np->connected = false;
          np->fd = -1;
          state->peer_count++;
          state->config_dirty = true;
          return send_response(state, client,
                               "SUCCESS: Peer added (HUBv3 / Ed25519 auth).");
        }
        return send_response(state, client, "ERROR: Max peers reached.");
      }
    }
    return send_response(state, client,
                         "ERROR: Use IP:PORT:UUID:NAME[:PUBKEY_B64]");

  case CMD_ADMIN_DEL_PEER:
    if (payload && strlen(payload) > 0) {
      /* The payload is the index LIST_PEERS printed.  Anything that is not a
       * plain number is refused outright rather than read as some index. */
      unsigned long uidx;
      if (!hub_parse_uint(payload, (unsigned long)MAX_PEERS + 1, &uidx))
        return send_response(state, client,
                             "ERROR: Invalid Index (expected the number from the peer list).");
      int idx = (int)uidx;
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

  case CMD_ADMIN_SET_PEER_PUBKEY:
    if (payload && strlen(payload) > 0) {
      char uuid[64], pubkey_b64[128];
      memset(uuid, 0, sizeof(uuid));
      memset(pubkey_b64, 0, sizeof(pubkey_b64));
      if (sscanf(payload, "%63[^:]:%127s", uuid, pubkey_b64) != 2 || !uuid[0] || !pubkey_b64[0])
        return send_response(state, client, "ERROR: Use UUID:PUBKEY_B64");

      int peer_idx = -1;
      for (int i = 0; i < state->peer_count; i++) {
        if (strcmp(state->peers[i].uuid, uuid) == 0) { peer_idx = i; break; }
      }
      if (peer_idx < 0)
        return send_response(state, client, "ERROR: No peer with that UUID.");

      int dec_len = 0;
      unsigned char *dec = base64_decode(pubkey_b64, &dec_len);
      if (!dec || dec_len != COMBINED_KEY_LEN) {
        if (dec) { secure_wipe(dec, (size_t)(dec_len > 0 ? dec_len : 0)); free(dec); }
        return send_response(state, client,
                             "ERROR: pubkey must be 88-char base64 of 64-byte combined key.");
      }
      memcpy(state->peers[peer_idx].ed_pub,     dec,                   ED25519_KEY_LEN);
      memcpy(state->peers[peer_idx].x25519_pub, dec + ED25519_KEY_LEN, X25519_KEY_LEN);
      state->peers[peer_idx].has_pubkey = true;
      secure_wipe(dec, (size_t)dec_len);
      free(dec);
      state->config_dirty = true;
      hub_log("[HUB] Peer %s pubkey set — next connection will use v2 Ed25519 auth.\n", uuid);
      return send_response(state, client,
                           "SUCCESS: Peer pubkey registered. Reconnect the peer to authenticate with it (HUBv3).");
    }
    return send_response(state, client, "ERROR: Use UUID:PUBKEY_B64");

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
        free(reported_mismatches);
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
        free(reported_mismatches);
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
        /* Handles both the 3-field admin shape and the 4-field bot shape that
         * carries modes; op is read as the last field so the tombstone check
         * below is correct for either. */
        bool parsed = parse_global_channel_value(state->global_entries[i].value,
                                                 chan_name, sizeof(chan_name),
                                                 chan_key, sizeof(chan_key),
                                                 NULL, op, sizeof(op));
        // Skip deleted channels
        if (strcmp(op, "del") == 0)
          continue;

        if (parsed && chan_name[0]) {
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
        /* Past the stored stamp: a remove in this same second would tie,
         * and the newest command must be the one that sticks. */
        time_t now = hub_lww_next_ts(hub_storage_global_ts(state, "c", chan));

        /* Carry forward any modes a bot previously reported for this channel.
         * The admin console only prompts for name + key, and the storage layer
         * replaces the whole value once the timestamp wins, so without this an
         * admin re-add to change the key silently wipes the recorded +i/+k
         * state.  Store and sync the 4-field shape so both writers agree. */
        int modes = global_channel_modes(state, chan);
        char extra[80];
        snprintf(extra, sizeof(extra), "%s|%d", key, modes);
        hub_storage_update_global_entry(state, "c", chan, extra, "add", now);
        state->config_dirty = true;

        char sync_msg[256];
        snprintf(sync_msg, sizeof(sync_msg), "c|%s|%s|%d|add|%ld\n", chan, key,
                 modes, (long)now);
        hub_broadcast_config_to_bots(state, sync_msg);
        hub_broadcast_sync_to_peers(state, sync_msg, -1);
        return send_response(state, client, "SUCCESS: Channel added and synced.");
      }
    }
    return send_response(state, client, "ERROR: Invalid payload.");
  }

  case CMD_ADMIN_DEL_CHANNEL: {
    if (payload && strlen(payload) > 0) {
      time_t now = hub_lww_next_ts(hub_storage_global_ts(state, "c", payload));
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
    /* Legacy global oper masks (pre-passwordless).  They authenticate no one
     * any more; they are listed only so they can be removed.  Their stored
     * password is never shown (and is no longer stored, see
     * hub_storage_update_global_entry). */
    offset = 0;
    written = snprintf(response, sizeof(response),
                       "--- Legacy Oper Masks (retired: no password, no login; "
                       "remove them) ---\n");
    if (written >= (int)sizeof(response))
      return send_response(state, client, "ERROR: Buffer overflow");
    offset += written;

    int oper_count = 0;
    for (int i = 0; i < state->global_entry_count; i++) {
      if (strcmp(state->global_entries[i].key, "o") != 0)
        continue;
      const char *v = state->global_entries[i].value;
      const char *first = strchr(v, '|');
      const char *last = strrchr(v, '|');
      if (!first || !last || strcmp(last + 1, "del") == 0)
        continue;
      oper_count++;
      written = snprintf(response + offset, sizeof(response) - offset,
                         "  %.*s\n", (int)(first - v), v);
      if (written < 0 || written >= (int)(sizeof(response) - offset))
        break;
      offset += written;
    }
    if (oper_count == 0) {
      written = snprintf(response + offset, sizeof(response) - offset,
                         "  (No oper masks configured)\n");
      if (written > 0 && written < (int)(sizeof(response) - offset))
        offset += written;
    }
    return send_response(state, client, response);
  }

  case CMD_ADMIN_ADD_OPER:
    /* Retired with passwordless: a mask|password oper stored the password in
     * plaintext, replicated it to every hub and listed it back.  Opers are
     * key-based records now (CMD_ADMIN_ADD_OPER_RECORD). */
    return send_response(state, client,
                         "ERR:retired (oper passwords removed; add an oper "
                         "with a public key instead)");

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

  case CMD_ADMIN_SET_ADMIN_PASS:
  case CMD_ADMIN_SET_BOT_PASS:
  case CMD_ADMIN_SET_USERPASS:
    /* Retired with passwordless (docs/passwordless.md §7.2): an older
     * hub_admin still offering these gets a clear answer, nothing changes. */
    return send_response(state, client,
                         "ERR:retired (passwords removed; keys only — use "
                         "'Change user public key')");

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

    /* Fail closed: only "immediate" purges everything.  A payload that is not
     * a whole number of days >= 1 is refused -- atoi() used to read "7d",
     * "-3" or an empty payload as 0, i.e. purge every tombstone now. */
    if (!payload || strcmp(payload, "immediate") != 0) {
      unsigned long udays;
      if (!payload || !hub_parse_uint(payload, 36500, &udays) || udays == 0)
        return send_response(state, client,
                             "ERROR: Purge needs 'immediate' or a number of days >= 1.");
      cutoff = now - ((time_t)udays * 86400);
      days_label = (int)udays;
    }

    char purge_log[MAX_BUFFER / 2];
    int purged_count = hub_execute_purge(state, cutoff,
                                          purge_log, sizeof(purge_log));

    // Broadcast PURGE|<cutoff>|<id> to all peer hubs.
    if (!hub_broadcast_purge(state, cutoff))
      return send_response(state, client,
                           "ERROR: Purged locally, but the purge could not be sent to peers.");

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
      unsigned long udays;
      if (!hub_parse_uint(payload, 36500, &udays))
        return send_response(state, client,
                             "ERROR: Purge days must be a whole number (0 disables).");
      int days = (int)udays;  // 0 = disabled

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
    if (!payload || !payload[0])
      return send_response(state, client, "ERROR: Missing hub name.");
    /* The name is written into '|'-separated config lines and sent inside
     * handshakes and ':'/','-separated gossip: a newline or separator in it
     * forged config records ("x|203.0.113.77|0" became a denylist entry). */
    if (!hub_name_valid(payload))
      return send_response(state, client,
                           "ERR:hub name must be 1-63 characters of A-Z a-z "
                           "0-9 . _ -");
    snprintf(state->hub_friendly_name, sizeof(state->hub_friendly_name), "%s",
             payload);
    state->config_dirty = true;
    /* Peers learn names from mesh-state gossip (process_mesh_state), not from
     * sync lines: the 'hub_name|<name>|<ts>' line sent here before was
     * ignored by every receiver, so a rename reached them only at the next
     * 5-minute gossip.  Gossip now. */
    state->mesh_state_dirty = true;
    char response[256];
    snprintf(response, sizeof(response), "SUCCESS: Hub name updated to '%s'",
             state->hub_friendly_name);
    return send_response(state, client, response);
  }

  case CMD_ADMIN_SET_BIND_PORT: {
    if (payload && strlen(payload) > 0) {
      unsigned long uport = 0;
      int port = hub_parse_uint(payload, 65535, &uport) ? (int)uport : 0;
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

  case CMD_ADMIN_LIST_ALLOWLIST:
  case CMD_ADMIN_LIST_DENYLIST: {
    bool allow = cmd == CMD_ADMIN_LIST_ALLOWLIST;
    const hub_ip_acl_t *l = allow ? state->ip_allow : state->ip_deny;
    int n = allow ? state->ip_allow_count : state->ip_deny_count;
    char list[MAX_BUFFER];  /* 64 short lines: always fits */
    int offset = snprintf(list, sizeof(list),
                          "════════════════════════════════════════════\n"
                          "           IP %s\n"
                          "════════════════════════════════════════════\n\n",
                          allow ? "ALLOWLIST" : "DENYLIST");

    for (int i = 0; i < n; i++)
      offset += snprintf(list + offset, sizeof(list) - (size_t)offset,
                         "%3d. %s\n", i + 1, l[i].pattern);
    if (n == 0)
      snprintf(list + offset, sizeof(list) - (size_t)offset, "%s",
               allow ? "(No allowlist entries - all IPs allowed)\n"
                     : "(No denylist entries)\n");

    return send_response(state, client, list);
  }

  case CMD_ADMIN_ADD_ALLOWLIST:
    return admin_ip_acl_change(state, client, 'w', true, payload);
  case CMD_ADMIN_DEL_ALLOWLIST:
    return admin_ip_acl_change(state, client, 'w', false, payload);
  case CMD_ADMIN_ADD_DENYLIST:
    return admin_ip_acl_change(state, client, 'x', true, payload);
  case CMD_ADMIN_DEL_DENYLIST:
    return admin_ip_acl_change(state, client, 'x', false, payload);

        case CMD_ADMIN_SET_LOG_LEVEL: {
            /* One raw byte (hub_admin): level 0 is the byte 0x00, so the
             * frame length decides, never strlen. */
            if (!payload || payload_len != 1) {
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
            /* Four raw bytes, network order: 10 MB is 00 A0 00 00. */
            if (!payload || payload_len != 4) {
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

  case CMD_ADMIN_GET_OPT_FLAGS: {
    char msg[128];
    snprintf(msg, sizeof(msg), "opt|%s",
             state->opt_flags[0] ? state->opt_flags : "(none)");
    return send_response(state, client, msg);
  }

  case CMD_ADMIN_SET_OPT_FLAGS: {
    /* Payload: bare flag string ([a-zA-Z0-9]+) or empty to clear. */
    char clean[MAX_OPT_FLAGS + 1] = {0};
    int w = 0;
    if (payload) {
      for (int i = 0; payload[i] && w < MAX_OPT_FLAGS; i++) {
        char c = payload[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9'))
          clean[w++] = c;
      }
    }
    clean[w] = '\0';
    /* Dedupe (preserve insertion order). */
    char dedup[MAX_OPT_FLAGS + 1] = {0};
    int dw = 0;
    for (int i = 0; clean[i] && dw < MAX_OPT_FLAGS; i++) {
      bool seen = false;
      for (int j = 0; j < dw; j++)
        if (dedup[j] == clean[i]) { seen = true; break; }
      if (!seen) dedup[dw++] = clean[i];
    }
    dedup[dw] = '\0';
    snprintf(state->opt_flags, sizeof(state->opt_flags), "%s", dedup);
    /* Past the previous stamp: a set and a clear in the same second must not
     * tie, or peers keep whichever arrived and the mesh splits. */
    state->opt_flags_ts = hub_lww_next_ts(state->opt_flags_ts);
    state->config_dirty = true;

    /* Broadcast to peer hubs */
    char sync_pkt[64];
    snprintf(sync_pkt, sizeof(sync_pkt), "opt|%s|%ld\n",
             state->opt_flags, (long)state->opt_flags_ts);
    hub_broadcast_sync_to_peers(state, sync_pkt, -1);

    /* Push to bots */
    broadcast_full_config_to_all_bots(state);

    char msg[128];
    snprintf(msg, sizeof(msg), "SUCCESS: opt flags now '%s'",
             state->opt_flags[0] ? state->opt_flags : "(none)");
    return send_response(state, client, msg);
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
        if (t) strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S UTC", t);
        else   snprintf(ts_buf, sizeof(ts_buf), "invalid");
      }
      char kfp[KEY_FP_LEN + 1];
      hub_crypto_key_fingerprint_b64(u->has_pubkey ? u->pubkey_b64 : "", kfp);
      off += snprintf(buf + off, sizeof(buf) - off,
                      "| %-*s  key %s  (last seen: %s)\n", name_w, u->name,
                      kfp, ts_buf);
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
    /* Payload: name|pubkey_b64|mask.  The user generated their own keypair
     * (keygen) and only the public half arrives: the hub never mints or
     * delivers a user's private key. */
    if (!payload || !*payload)
      return send_response(state, client, "ERR:missing payload");
    char pname[64], ppub[COMBINED_KEY_B64 + 2], pmask[MAX_MASK_LEN];
    if (sscanf(payload, "%63[^|]|%89[^|]|%255s", pname, ppub, pmask) < 3)
      return send_response(state, client, "ERR:syntax name|pubkey|mask");
    /* Validate name: no pipes, printable, reasonable length */
    if (!pname[0] || strchr(pname,'|') || strchr(pname,' '))
      return send_response(state, client, "ERR:invalid name");
    unsigned char praw[COMBINED_KEY_LEN];
    if (!hub_crypto_pubkey_b64_decode(ppub, praw))
      return send_response(state, client,
                           "ERR:pubkey must be the user's 88-char public key "
                           "(contents of their .public.b64)");
    /* Validate mask format */
    if (!strchr(pmask,'!') || !strchr(pmask,'@'))
      return send_response(state, client, "ERR:mask must contain ! and @");
    /* Check name uniqueness across all a|/o| records, and key uniqueness:
     * hub_admin logins identify the admin by key. */
    for (int i = 0; i < state->user_record_count; i++) {
      if (!state->user_records[i].is_active) continue;
      if (strcasecmp(state->user_records[i].name, pname) == 0)
        return send_response(state, client, "ERR:name already exists");
      if (state->user_records[i].has_pubkey &&
          strcmp(state->user_records[i].pubkey_b64, ppub) == 0)
        return send_response(state, client, "ERR:that key already belongs to another user");
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
    snprintf(u->uuid,       sizeof(u->uuid),       "%s", new_uuid);
    snprintf(u->name,       sizeof(u->name),       "%s", pname);
    memcpy(u->pubkey_b64, ppub, COMBINED_KEY_B64);  /* validated: 88 chars */
    u->pubkey_b64[COMBINED_KEY_B64] = '\0';
    u->has_pubkey = true;
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
    /* Bots get fresh per-connection payloads (right shape per bot version);
     * peers get the canonical record line. */
    char sync[MAX_BUFFER];
    hub_format_user_record(u, false, sync, sizeof(sync));
    hub_broadcast_config_to_bots(state, sync);
    hub_broadcast_sync_to_peers(state, sync, -1);
    snprintf(sync, sizeof(sync), "m|%s|%s|add|0|%ld\n",
             m->uuid, m->mask, (long)now);
    hub_broadcast_sync_to_peers(state, sync, -1);

    char fp[KEY_FP_LEN + 1];
    hub_crypto_key_fingerprint(praw, fp);
    char resp[512];
    snprintf(resp, sizeof(resp), "SUCCESS|%c|%s|%s|%s", u->type, pname, pmask,
             fp);
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
    /* Peers get ONE sync payload: the user tombstone, then a tombstone for
     * every mask the user owned.  No peer or bot cascades a user delete to
     * its masks, so a mask tombstone that is not sent leaves the mask live
     * there: an orphan holding a slot of the shared 200-mask table on every
     * other hub and on their bots.  One payload keeps the lines in order and
     * off the per-lane message cap (a user may own every mask slot). */
    size_t sync_cap = (size_t)USER_LINE_MAX +
                      (size_t)MAX_HUB_USER_MASKS * MASK_LINE_MAX + 1;
    char *sync = malloc(sync_cap);
    if (!sync)
      return send_response(state, client, "ERR:out of memory");
    target->is_active = false;
    target->timestamp = hub_lww_next_ts(target->timestamp);
    state->config_dirty = true;
    char uline[USER_LINE_MAX];
    int sync_len = hub_format_user_record(target, false, uline, sizeof(uline));
    if (sync_len < 0 || sync_len >= (int)sizeof(uline)) sync_len = 0;
    memcpy(sync, uline, (size_t)sync_len);
    sync[sync_len] = '\0';
    int masks_dropped = 0;
    for (int i = 0; i < state->mask_record_count; i++) {
      hub_mask_record_t *mr = &state->mask_records[i];
      if (strcmp(mr->uuid, target->uuid) != 0 || !mr->is_active)
        continue;
      mr->is_active = false;
      mr->timestamp = hub_lww_next_ts(mr->timestamp);
      masks_dropped++;
      int w = snprintf(sync + sync_len, sync_cap - (size_t)sync_len,
                       "m|%s|%s|del|%lld|%lld\n", mr->uuid, mr->mask,
                       (long long)mr->last_used, (long long)mr->timestamp);
      /* cannot overflow: sync_cap holds a line for every mask slot */
      if (w > 0 && (size_t)w < sync_cap - (size_t)sync_len)
        sync_len += w;
    }
    hub_broadcast_config_to_bots(state, uline);   /* logs the user line only */
    hub_broadcast_sync_to_peers(state, sync, -1);
    hub_log("[ADMIN] %s %s removed with %d usermask(s)\n",
            cmd == CMD_ADMIN_DEL_ADMIN ? "Admin" : "Oper", target->name,
            masks_dropped);
    free(sync);
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
    /* Duplicate active mask is an error; a tombstone for the same mask is
     * revived past its stamp (a second record could tie with the remove). */
    hub_mask_record_t *m = NULL;
    for (int i = 0; i < state->mask_record_count; i++) {
      if (strcmp(state->mask_records[i].uuid, target->uuid) != 0 ||
          strcasecmp(state->mask_records[i].mask, pmask) != 0)
        continue;
      if (state->mask_records[i].is_active)
        return send_response(state, client, "ERR:mask already exists");
      m = &state->mask_records[i];
    }
    if (m) {
      m->timestamp = hub_lww_next_ts(m->timestamp);
    } else {
      if (state->mask_record_count >= MAX_HUB_USER_MASKS)
        return send_response(state, client, "ERR:mask table full");
      char tuuid_add[37];
      snprintf(tuuid_add, sizeof(tuuid_add), "%s", target->uuid);
      m = &state->mask_records[state->mask_record_count++];
      memset(m, 0, sizeof(*m));
      snprintf(m->uuid, sizeof(m->uuid), "%s", tuuid_add);
      snprintf(m->mask, sizeof(m->mask), "%s", pmask);
      m->last_used = 0;
      m->timestamp = time(NULL);
    }
    m->is_active = true;
    state->config_dirty = true;
    char sync[MAX_BUFFER];
    snprintf(sync, sizeof(sync), "m|%s|%s|add|%lld|%lld\n", m->uuid, m->mask,
             (long long)m->last_used, (long long)m->timestamp);
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
    found->is_active = false;
    found->timestamp = hub_lww_next_ts(found->timestamp);
    state->config_dirty = true;
    char sync[MAX_BUFFER];
    snprintf(sync, sizeof(sync), "m|%s|%s|del|%lld|%lld\n",
             found->uuid, found->mask, (long long)found->last_used,
             (long long)found->timestamp);
    hub_broadcast_config_to_bots(state, sync);
    hub_broadcast_sync_to_peers(state, sync, -1);
    char resp[512];
    snprintf(resp, sizeof(resp), "SUCCESS: mask %s removed from %s", pmask, pname);
    return send_response(state, client, resp);
  }

  case CMD_ADMIN_SET_USERKEY: {
    /* Payload: name|pubkey_b64 — replace a user's key (rotation, a lost key,
     * or giving a legacy keyless user one).  UUID, masks and history stay;
     * the old key stops working for hub_admin and every bot at sync speed. */
    if (!payload || !*payload)
      return send_response(state, client, "ERR:missing payload");
    char pname[64], ppub[COMBINED_KEY_B64 + 2];
    if (sscanf(payload, "%63[^|]|%89s", pname, ppub) < 2)
      return send_response(state, client, "ERR:syntax name|pubkey");
    unsigned char praw[COMBINED_KEY_LEN];
    if (!hub_crypto_pubkey_b64_decode(ppub, praw))
      return send_response(state, client,
                           "ERR:pubkey must be the user's 88-char public key "
                           "(contents of their .public.b64)");
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
    for (int i = 0; i < state->user_record_count; i++) {
      hub_user_record_t *o = &state->user_records[i];
      if (o != target && o->is_active && o->has_pubkey &&
          strcmp(o->pubkey_b64, ppub) == 0)
        return send_response(state, client, "ERR:that key already belongs to another user");
    }
    memcpy(target->pubkey_b64, ppub, COMBINED_KEY_B64);  /* validated: 88 */
    target->pubkey_b64[COMBINED_KEY_B64] = '\0';
    target->has_pubkey = true;
    /* Bump timestamp so peers and bots see this update as newer than the
     * old record (otherwise replication compares ts and drops the change). */
    target->timestamp = hub_lww_next_ts(target->timestamp);
    state->config_dirty = true;
    char sync[MAX_BUFFER];
    hub_format_user_record(target, false, sync, sizeof(sync));
    hub_broadcast_config_to_bots(state, sync);
    hub_broadcast_sync_to_peers(state, sync, -1);
    char fp[KEY_FP_LEN + 1];
    hub_crypto_key_fingerprint(praw, fp);
    char resp[256];
    snprintf(resp, sizeof(resp), "SUCCESS: key for %s set (%s)", target->name,
             fp);
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
        if (t) strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S UTC", t);
        else   snprintf(ts_buf, sizeof(ts_buf), "invalid");
      }
      char kfp[KEY_FP_LEN + 1];
      hub_crypto_key_fingerprint_b64(u->has_pubkey ? u->pubkey_b64 : "", kfp);
      off += snprintf(buf + off, sizeof(buf) - off,
                      "| [%c] %-*s  key %s  (last seen: %s)\n",
                      u->type, name_w, u->name, kfp, ts_buf);
      for (int j = 0; j < state->mask_record_count; j++) {
        hub_mask_record_t *m = &state->mask_records[j];
        if (strcmp(m->uuid, u->uuid) != 0 || !m->is_active) continue;
        char used_buf[48];
        if (m->last_used == 0) {
          snprintf(used_buf, sizeof(used_buf), "never");
        } else {
          struct tm *tu = gmtime(&m->last_used);
          if (tu) strftime(used_buf, sizeof(used_buf), "%Y-%m-%d %H:%M:%S UTC", tu);
          else    snprintf(used_buf, sizeof(used_buf), "invalid");
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
  long long origin_ts = 0;

  int parsed = sscanf(payload,
                      "%63[^|]|%63[^|]|%63[^|]|%64[^|]|%255[^|]|%lld",
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

// ========== Channel-Access Requests (unban / invite / key) ==========

/* Frame `payload` under `cmd` and write it to one authenticated bot. */
static bool send_cmd_to_bot(hub_client_t *bot, uint8_t cmd,
                            const char *payload) {
  int pay_len = payload ? (int)strlen(payload) : 0;
  if (pay_len + 5 > MAX_BUFFER)
    return false;

  unsigned char plain[MAX_BUFFER], buf[MAX_BUFFER], tag[GCM_TAG_LEN];
  plain[0] = cmd;
  uint32_t net_pay = htonl((uint32_t)pay_len);
  memcpy(&plain[1], &net_pay, 4);
  if (pay_len)
    memcpy(&plain[5], payload, (size_t)pay_len);

  int enc_len = aes_gcm_encrypt(plain, 5 + pay_len, bot->session_key, buf + 4,
                                tag);
  if (enc_len <= 0) {
    secure_wipe(plain, (size_t)(5 + pay_len));
    return false;
  }
  memcpy(buf + 4 + enc_len, tag, GCM_TAG_LEN);
  uint32_t net_len = htonl((uint32_t)(enc_len + GCM_TAG_LEN));
  memcpy(buf, &net_len, 4);
  bool ok = write(bot->fd, buf, (size_t)(4 + enc_len + GCM_TAG_LEN)) > 0;
  /* A CHAN_REPLY carries a channel key, so the cleartext frame does not stay
   * on the stack after it has gone out.  Only the bytes used are touched. */
  secure_wipe(plain, (size_t)(5 + pay_len));
  return ok;
}

static bool chan_kind_valid(const char *kind) {
  return strcmp(kind, "unban") == 0 || strcmp(kind, "invite") == 0 ||
         strcmp(kind, "key") == 0;
}

static int add_pending_chan_request(hub_state_t *state, const char *request_id,
                                    const char *requester_uuid,
                                    const char *kind, const char *channel,
                                    int origin_fd) {
  time_t now = time(NULL);
  for (int i = 0; i < MAX_PENDING_CHAN_REQUESTS; i++) {
    pending_chan_request_t *p = &state->pending_chan_requests[i];
    /* Reuse a slot whose reply never came rather than filling the table. */
    if (p->active && now - p->timestamp > CHAN_REQUEST_TIMEOUT)
      p->active = false;
    if (!p->active) {
      snprintf(p->request_id, sizeof(p->request_id), "%s", request_id);
      snprintf(p->requester_uuid, sizeof(p->requester_uuid), "%s",
               requester_uuid);
      snprintf(p->kind, sizeof(p->kind), "%s", kind);
      snprintf(p->channel, sizeof(p->channel), "%s", channel);
      p->origin_fd = origin_fd;
      p->timestamp = now;
      p->active = true;
      return i;
    }
  }
  return -1;
}

static pending_chan_request_t *find_pending_chan_request(hub_state_t *state,
                                                        const char *request_id) {
  for (int i = 0; i < MAX_PENDING_CHAN_REQUESTS; i++) {
    if (state->pending_chan_requests[i].active &&
        strcmp(state->pending_chan_requests[i].request_id, request_id) == 0)
      return &state->pending_chan_requests[i];
  }
  return NULL;
}

/* Look up one `key` of a stored bot record (e.g. "h" hostmask, "n" nick).
 * Returns false when the bot or the key is unknown. */
static bool hub_bot_entry(hub_state_t *state, const char *uuid, const char *key,
                          char *out, size_t out_len) {
  for (int i = 0; i < state->bot_count; i++) {
    if (strcmp(state->bots[i].uuid, uuid) != 0)
      continue;
    for (int j = 0; j < state->bots[i].entry_count; j++) {
      if (strcmp(state->bots[i].entries[j].key, key) == 0) {
        snprintf(out, out_len, "%s", state->bots[i].entries[j].value);
        return out[0] != '\0';
      }
    }
    return false;
  }
  return false;
}

static void forward_chan_request_to_peers(hub_state_t *state,
                                          const char *request_id,
                                          const char *requester_uuid,
                                          const char *kind, const char *channel,
                                          const char *nick,
                                          const char *hostmask, int exclude_fd) {
  /* request_id|requester_uuid|kind|channel|nick|hostmask */
  char fwd[MAX_MASK_LEN + 256];
  snprintf(fwd, sizeof(fwd), "%s|%s|%s|%s|%s|%s", request_id, requester_uuid,
           kind, channel, nick ? nick : "", hostmask ? hostmask : "");

  int queued = 0;
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type == CLIENT_HUB && c->authenticated && c->fd != exclude_fd) {
      if (!peer_send_urgent(state, c, CMD_CHAN_FWD_REQUEST, fwd)) {
        hub_log("[HUB] URGENT queue full forwarding CHAN_REQUEST to peer "
                "fd=%d — disconnecting\n", c->fd);
        hub_disconnect_client(state, c);
        i--;
        continue;
      }
      queued++;
    }
  }
  if (queued > 0)
    hub_log("[HUB] Forwarded CHAN_FWD_REQUEST (id:%s %s %s) to %d peer(s)\n",
            request_id, kind, channel, queued);
}

/* Push the action to every authenticated local bot except the requester and
 * the peer it arrived from.  Returns how many bots were told. */
static int broadcast_chan_action(hub_state_t *state, const char *request_id,
                                 const char *requester_uuid, const char *kind,
                                 const char *channel, const char *nick,
                                 const char *hostmask) {
  char action[MAX_MASK_LEN + 256];
  snprintf(action, sizeof(action), "%s|%s|%s|%s|%s|%s", request_id, kind,
           channel, requester_uuid, nick ? nick : "", hostmask ? hostmask : "");

  int sent = 0;
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *bc = state->clients[i];
    if (bc->type != CLIENT_BOT || !bc->authenticated)
      continue;
    if (strcmp(bc->id, requester_uuid) == 0)
      continue; /* never ask the locked-out bot to help itself */
    if (send_cmd_to_bot(bc, CMD_CHAN_ACTION, action))
      sent++;
    else
      hub_log("[HUB] Failed to send CHAN_ACTION to bot %s\n", bc->id);
  }
  return sent;
}

/* Entry point shared by a local bot's request and a peer-forwarded one.
 * `origin_fd` is the peer fd to route a reply back to, or -1 when the
 * requester is one of our own bots. */
static void chan_request_dispatch(hub_state_t *state, const char *request_id,
                                  const char *requester_uuid, const char *kind,
                                  const char *channel, const char *nick,
                                  const char *hostmask, int origin_fd) {
  /* Only `key` sends anything back, so only `key` needs a pending slot. */
  if (strcmp(kind, "key") == 0 &&
      add_pending_chan_request(state, request_id, requester_uuid, kind, channel,
                               origin_fd) < 0) {
    hub_log("[HUB] Pending channel-request table full — dropping %s for %s\n",
            kind, channel);
    return;
  }

  int told = broadcast_chan_action(state, request_id, requester_uuid, kind,
                                   channel, nick, hostmask);
  forward_chan_request_to_peers(state, request_id, requester_uuid, kind,
                                channel, nick, hostmask, origin_fd);
  hub_log("[HUB] CHAN_REQUEST %s for %s (id:%s) delivered to %d local bot(s)\n",
          kind, channel, request_id, told);
}

static void process_chan_request(hub_state_t *state, hub_client_t *client,
                                 char *payload) {
  /* Payload from a bot is only `kind|channel`; everything that could be
   * forged is resolved here from the authenticated bot's own records. */
  char kind[8], channel[MAX_CHAN];
  if (sscanf(payload, "%7[^|]|%64s", kind, channel) != 2 ||
      !chan_kind_valid(kind)) {
    hub_log("[HUB] Invalid CHAN_REQUEST payload from %s\n", client->id);
    return;
  }
  if (channel[0] != '#' && channel[0] != '&') {
    hub_log("[HUB] CHAN_REQUEST from %s for non-channel '%s'\n", client->id,
            channel);
    return;
  }

  char nick[MAX_NICK] = "", hostmask[MAX_MASK_LEN] = "";
  hub_bot_entry(state, client->id, "n", nick, sizeof(nick));
  hub_bot_entry(state, client->id, "h", hostmask, sizeof(hostmask));

  /* An unban can only be matched against a mask, an invite only sent to a
   * nick.  Without them the request is unserviceable, so say so rather than
   * flooding the mesh with something no bot can act on. */
  if (strcmp(kind, "unban") == 0 && hostmask[0] == '\0') {
    hub_log("[HUB] No hostmask for %s — cannot service unban for %s\n",
            client->id, channel);
    return;
  }
  if (strcmp(kind, "invite") == 0 && nick[0] == '\0') {
    hub_log("[HUB] No nick for %s — cannot service invite for %s\n",
            client->id, channel);
    return;
  }

  hub_log("[HUB] CHAN_REQUEST %s from %s for %s\n", kind, client->id, channel);

  char request_id[64];
  generate_request_id(request_id, sizeof(request_id));
  op_forward_seen_check_and_add(state, request_id);
  chan_request_dispatch(state, request_id, client->id, kind, channel, nick,
                        hostmask, -1);
}

/* A bot answering a request (today only `key`).  Route it to the requester if
 * it is ours, otherwise back down the peer fd the request arrived on. */
static void process_chan_reply(hub_state_t *state, hub_client_t *client,
                               char *payload) {
  char request_id[64], kind[8], channel[MAX_CHAN], status[16];
  const char *data = "";

  /* Parsed straight out of `payload`: the %[^|] conversions do not write to
   * their source, so there is no second copy of the key to wipe afterwards. */
  if (sscanf(payload, "%63[^|]|%7[^|]|%64[^|]|%15[^|]", request_id, kind,
             channel, status) != 4) {
    hub_log("[HUB] Invalid CHAN_REPLY payload from %s\n", client->id);
    return;
  }
  /* The data field is the remainder after the 4th '|' — a channel key may
   * contain anything but whitespace, so it is never re-split. */
  int bars = 0;
  for (const char *p = payload; *p; p++) {
    if (*p == '|' && ++bars == 4) {
      data = p + 1;
      break;
    }
  }

  pending_chan_request_t *req = find_pending_chan_request(state, request_id);
  if (!req) {
    /* Late or duplicate answer — the first one already went home. */
    hub_log("[HUB] CHAN_REPLY (id:%s) from %s matches no pending request\n",
            request_id, client->id);
    return;
  }
  /* Bind the answer to what was actually asked: holding a request id must not
   * let a bot hand the requester a key for some other channel. */
  if (strcmp(req->kind, kind) != 0 || strcasecmp(req->channel, channel) != 0) {
    hub_log("[HUB] CHAN_REPLY (id:%s) from %s answers %s/%s but the request "
            "was %s/%s — dropped\n", request_id, client->id, kind, channel,
            req->kind, req->channel);
    return;
  }
  /* A bot answering its own request tells us nothing. */
  if (strcmp(client->id, req->requester_uuid) == 0)
    return;

  char out[MAX_BUFFER];
  snprintf(out, sizeof(out), "%s|%s|%s|%s|%s", request_id, kind, channel,
           status, data);

  if (req->origin_fd == -1) {
    hub_client_t *target = NULL;
    for (int i = 0; i < state->client_count; i++) {
      if (state->clients[i]->type == CLIENT_BOT &&
          state->clients[i]->authenticated &&
          strcmp(state->clients[i]->id, req->requester_uuid) == 0) {
        target = state->clients[i];
        break;
      }
    }
    if (target && send_cmd_to_bot(target, CMD_CHAN_REPLY, out))
      hub_log("[HUB] CHAN_REPLY %s for %s delivered to %s\n", kind, channel,
              req->requester_uuid);
    else
      hub_log("[HUB] CHAN_REPLY %s for %s undeliverable to %s\n", kind, channel,
              req->requester_uuid);
  } else {
    for (int i = 0; i < state->client_count; i++) {
      hub_client_t *c = state->clients[i];
      if (c->type == CLIENT_HUB && c->authenticated &&
          c->fd == req->origin_fd) {
        if (!peer_send_urgent(state, c, CMD_CHAN_FWD_REPLY, out))
          hub_log("[HUB] URGENT queue full routing CHAN_REPLY to peer fd=%d\n",
                  c->fd);
        else
          hub_log("[HUB] CHAN_REPLY %s for %s sent back as CHAN_FWD_REPLY to "
                  "peer fd=%d\n", kind, channel, c->fd);
        break;
      }
    }
  }

  req->active = false;
  secure_wipe(out, sizeof(out));
}

static void process_forward_chan_request(hub_state_t *state,
                                         hub_client_t *client, char *payload) {
  char request_id[64], requester_uuid[64], kind[8], channel[MAX_CHAN];
  char nick[MAX_NICK] = "", hostmask[MAX_MASK_LEN] = "";

  int parsed = sscanf(payload, "%63[^|]|%63[^|]|%7[^|]|%64[^|]|%31[^|]|%255[^|]",
                      request_id, requester_uuid, kind, channel, nick, hostmask);
  if (parsed < 4 || !chan_kind_valid(kind)) {
    hub_log("[HUB] Invalid CHAN_FWD_REQUEST from peer fd=%d\n", client->fd);
    return;
  }
  /* Second sighting of this id: another path already delivered it. */
  if (op_forward_seen_check_and_add(state, request_id))
    return;

  hub_log("[HUB] CHAN_FWD_REQUEST %s for %s (id:%s) from peer fd=%d\n", kind,
          channel, request_id, client->fd);
  chan_request_dispatch(state, request_id, requester_uuid, kind, channel, nick,
                        hostmask, client->fd);
}

static void process_forward_chan_reply(hub_state_t *state, hub_client_t *client,
                                       char *payload) {
  char request_id[64];
  if (sscanf(payload, "%63[^|]", request_id) != 1) {
    hub_log("[HUB] Invalid CHAN_FWD_REPLY from peer fd=%d\n", client->fd);
    return;
  }
  pending_chan_request_t *req = find_pending_chan_request(state, request_id);
  if (!req)
    return; /* not ours, or already answered */

  if (req->origin_fd == -1) {
    for (int i = 0; i < state->client_count; i++) {
      if (state->clients[i]->type == CLIENT_BOT &&
          state->clients[i]->authenticated &&
          strcmp(state->clients[i]->id, req->requester_uuid) == 0) {
        send_cmd_to_bot(state->clients[i], CMD_CHAN_REPLY, payload);
        hub_log("[HUB] CHAN_FWD_REPLY (id:%s) from peer fd=%d delivered to %s\n",
                request_id, client->fd, req->requester_uuid);
        break;
      }
    }
  } else {
    for (int i = 0; i < state->client_count; i++) {
      hub_client_t *c = state->clients[i];
      if (c->type == CLIENT_HUB && c->authenticated && c->fd == req->origin_fd) {
        peer_send_urgent(state, c, CMD_CHAN_FWD_REPLY, payload);
        hub_log("[HUB] CHAN_FWD_REPLY (id:%s) relayed on toward its origin "
                "(peer fd=%d)\n", request_id, c->fd);
        break;
      }
    }
  }
  req->active = false;
}

// ========== End Channel-Access Requests ==========

static void process_bot_command(hub_state_t *state, hub_client_t *client,
                                int cmd, char *payload) {
  switch (cmd) {
  case CMD_PING:
    if (!HIDEPINGPONG)
      hub_log("[HUB] Bot %s PING\n", client->id);
    break;

  case CMD_BOT_PRESENCE:
    process_bot_presence(state, client, payload);
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
    long long ts;
    if (sscanf(payload, "%31[^|]|%1023[^|]|%lld", key, val, &ts) < 2) {
      hub_log("[HUB] Invalid CMD_BOT_DELTA from %s — ignoring\n", client->id);
      break;
    }
    if (ts == 0) ts = (long long)time(NULL);

    /* Change 3 — opt 'h' (OPT_HUB_ONLY_MUTATIONS): the delta path bypasses the
     * reject-list that process_bot_config_push enforces, letting a compromised
     * bot mutate hub-authoritative records (a/o/m/c/p) that hub_storage routes
     * to global storage.  Apply the same guard here so the flag is binding on
     * every bot-write path. */
    if ((strchr(state->opt_flags, OPT_HUB_ONLY_MUTATIONS) != NULL) &&
        (strcmp(key, "a") == 0 || strcmp(key, "o") == 0 ||
         strcmp(key, "m") == 0 || strcmp(key, "c") == 0 ||
         strcmp(key, "p") == 0)) {
      hub_log("[HUB] opt 'h' active: REJECTED bot delta '%s' from %s "
              "(hub-authoritative)\n", key, client->id);
      break;
    }

    /* Change 3b's per-bot key whitelist + value caps are enforced centrally in
     * hub_storage_update_entry (the single choke point shared by this delta
     * path, process_bot_config_push, process_peer_sync, and config load), so a
     * rejected key/value simply returns "not accepted" below. */

    hub_log("[HUB] BOT_DELTA from %s: key=%s val=%.40s ts=%lld\n",
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
                        "b|%s|%s|%s|%lld\n",
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

  case CMD_CHAN_REQUEST:
    process_chan_request(state, client, payload);
    break;

  case CMD_CHAN_REPLY:
    process_chan_reply(state, client, payload);
    break;

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
    /* Payload: target_uuid|cipher:tag — forward to target bot. The hub
     * KNOWS the sender's identity from the authenticated session
     * (client->id == sender bot's UUID). It prepends that UUID to the
     * forwarded CMD_BOT_MSG payload so the receiver can verify the
     * sender's GCM AAD binding. */
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

    /* Build the forwarded payload: "<sender_uuid>|<cipher:tag>" */
    char forwarded_payload[MAX_BUFFER];
    int forwarded_len = snprintf(forwarded_payload, sizeof(forwarded_payload),
                                  "%s|%s", client->id, relay_payload);
    if (forwarded_len <= 0 || forwarded_len >= (int)sizeof(forwarded_payload)) {
      hub_log("[HUB] CMD_BOT_RELAY: forwarded payload too long\n");
      break;
    }
    int relay_len = forwarded_len;
    unsigned char msg_plain[MAX_BUFFER], msg_buf[MAX_BUFFER], msg_tag[GCM_TAG_LEN];
    msg_plain[0] = (unsigned char)CMD_BOT_MSG;
    uint32_t msg_net_pay = htonl((uint32_t)relay_len);
    memcpy(&msg_plain[1], &msg_net_pay, 4);
    memcpy(&msg_plain[5], forwarded_payload, relay_len);

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
  /* Change 5: heap the generation buffer — a full config can exceed MAX_BUFFER
   * at scale and is too large for the stack.  MAX_CONFIG_PAYLOAD is a hard
   * upper bound (see hub.h), so hub_generate_bot_payload never truncates. */
  char *payload = malloc(MAX_CONFIG_PAYLOAD);
  if (!payload) {
    hub_log("[HUB] send_config_to_bot: OOM for %s\n", client->id);
    return;
  }

  // Use the new payload generator that combines Global + Bot-specific
  // and omits "b|uuid|" prefix for correct bot parsing
  hub_generate_bot_payload(state, client->id,
                           client->bot_proto >= BOT_PROTO_PASSWORDLESS,
                           payload, MAX_CONFIG_PAYLOAD);

  int len = strlen(payload);
  if (len == 0) {
    hub_log("[HUB] No config to send to %s\n", client->id);
    free(payload);
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
  free(payload);
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

    // ADDED: Enhanced bounds checking. D2: bound against the client's actual
    // buffer capacity (recv_cap), which is the small PREAUTH_BUF_SIZE until the
    // handshake completes. This turns the pre-auth buffer into a clean hard
    // limit — an oversized pre-auth frame is rejected here rather than hanging
    // until the recv loop fills and trips the overflow path.
    if (packet_len < 0 || packet_len > (client->recv_cap - 4)) {
      hub_log("[ERROR] Invalid packet length %d from %s (cap %d)\n", packet_len,
              client->ip, client->recv_cap);
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
      /* ADMIN-HELLO probe (login v2, docs/passwordless.md §6): plaintext
       * "ADMIN-HELLO" from hub_admin.  Reply
       *   "HUB-PUBKEY2|<hub_x_pub_b64>|<hub_uuid>|<nonce32_b64>"
       * (plaintext, length-prefixed) and stay unauthenticated.  The nonce is
       * this connection's one-time login challenge: hub_admin must sign it
       * (with the hub key, hub UUID and its ephemeral key) in ADMIN2.  One
       * HELLO per connection — a second one is refused. */
      if (packet_len == 11 && memcmp(data, "ADMIN-HELLO", 11) == 0 &&
          client->bot_auth_state == BOT_AUTH_IDLE) {
        if (client->admin_hello_seen) {
          hub_log("[HUB] Repeated ADMIN-HELLO from %s — disconnecting\n",
                  client->ip);
          record_failed_auth(state, client->ip);
          hub_disconnect_client(state, client);
          return false;
        }
        /* D4b: an interactive admin client may take a moment before its
         * sealed-box ADMIN2 arrives. Grant it the longer pre-auth window
         * (PREAUTH_ADMIN_TIMEOUT_SEC); bots/peers/slowloris are unaffected. */
        client->admin_hello_seen = true;
        if (state->hub_keys_loaded &&
            RAND_bytes(client->admin_nonce, sizeof(client->admin_nonce)) == 1) {
          client->admin_nonce_set = true;
          char *pub_b64 = base64_encode(state->hub_x25519_pub, 32);
          char *n_b64 = base64_encode(client->admin_nonce,
                                      sizeof(client->admin_nonce));
          if (pub_b64 && n_b64) {
            char reply[256];
            int rl = snprintf(reply, sizeof(reply), "HUB-PUBKEY2|%s|%s|%s",
                              pub_b64, state->hub_uuid[0] ? state->hub_uuid : "",
                              n_b64);
            if (rl > 0 && rl < (int)sizeof(reply)) {
              uint32_t nl = htonl((uint32_t)rl);
              if (write(client->fd, &nl, 4) == 4)
                (void)!write(client->fd, reply, rl);
            }
          }
          free(pub_b64);
          free(n_b64);
        }
        goto packet_consumed;
      }

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
        static const unsigned char ADMIN_INFO[] = "irchub-admin-session-v2";
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

          /* ADMIN login v2 (docs/passwordless.md §6), no name, no password:
           *   "ADMIN2|<admin_pub_b64>|<sig_b64>|<ip>:<port>"
           *   sig = Ed25519(admin_ed_priv, "irchub-admin-auth-v2\0" ||
           *         hub_uuid || "\0" || hub_x_pub(32) || nonce(32) ||
           *         eph_pub(32) || admin_pub(64))
           * eph_pub is data[0..31], hub_admin's fresh ephemeral key that keyed
           * this sealed box; nonce is the challenge this connection received
           * in HUB-PUBKEY2.  The signature proves possession of the admin's
           * private key, is useless on any other connection or hub (nonce,
           * hub key and UUID are bound), and the ephemeral key gives the
           * session forward secrecy.  The legacy "ADMIN|name|password|..."
           * login is gone. */
          if (strncmp(payload, "ADMIN2|", 7) == 0) {
            unsigned char nonce[32];
            bool nonce_ok = client->admin_nonce_set;
            memcpy(nonce, client->admin_nonce, sizeof(nonce));
            secure_wipe(client->admin_nonce, sizeof(client->admin_nonce));
            client->admin_nonce_set = false;  /* single use, success or not */

            char pub_b64[COMBINED_KEY_B64 + 1] = {0};
            char sig_b64[89] = {0};
            char client_addr[96] = {0};
            const char *f1 = payload + 7;
            const char *b1 = strchr(f1, '|');
            const char *b2 = b1 ? strchr(b1 + 1, '|') : NULL;
            bool shape_ok = b1 && b2 && (b1 - f1) == COMBINED_KEY_B64 &&
                            (b2 - b1 - 1) == 88;
            if (shape_ok) {
              memcpy(pub_b64, f1, COMBINED_KEY_B64);
              memcpy(sig_b64, b1 + 1, 88);
              snprintf(client_addr, sizeof(client_addr), "%s", b2 + 1);
            }

            unsigned char admin_pub[COMBINED_KEY_LEN];
            hub_user_record_t *admin_u = NULL;
            const char *why = "malformed ADMIN2 payload";
            bool pass_ok = false;
            if (!nonce_ok) {
              why = "no login challenge on this connection (ADMIN-HELLO first)";
            } else if (shape_ok &&
                       hub_crypto_pubkey_b64_decode(pub_b64, admin_pub)) {
              int matches = 0;
              for (int ui = 0; ui < state->user_record_count; ui++) {
                hub_user_record_t *u = &state->user_records[ui];
                if (u->type == 'a' && u->is_active && u->has_pubkey &&
                    strcmp(u->pubkey_b64, pub_b64) == 0) {
                  admin_u = u;
                  matches++;
                }
              }
              if (matches == 0) {
                why = "no active admin record holds this key";
                admin_u = NULL;
              } else if (matches > 1) {
                why = "key is on more than one admin record — refusing";
                admin_u = NULL;
              } else {
                int sl = 0;
                unsigned char *sig = base64_decode(sig_b64, &sl);
                unsigned char msg[64 + 64 + 32 + 32 + 32 + COMBINED_KEY_LEN];
                size_t ml = 0;
                static const char AUTH_CTX[] = "irchub-admin-auth-v2";
                size_t ul = strlen(state->hub_uuid);
                if (ul < 64) {
                  memcpy(msg + ml, AUTH_CTX, sizeof(AUTH_CTX)); /* incl. NUL */
                  ml += sizeof(AUTH_CTX);
                  memcpy(msg + ml, state->hub_uuid, ul); ml += ul;
                  msg[ml++] = '\0';
                  memcpy(msg + ml, state->hub_x25519_pub, 32); ml += 32;
                  memcpy(msg + ml, nonce, 32); ml += 32;
                  memcpy(msg + ml, data, 32); ml += 32;  /* eph_pub */
                  memcpy(msg + ml, admin_pub, COMBINED_KEY_LEN);
                  ml += COMBINED_KEY_LEN;
                  pass_ok = sig && sl == ED25519_SIG_LEN &&
                            hub_crypto_ed25519_verify(admin_pub, msg, ml, sig);
                }
                if (!pass_ok) why = "signature invalid";
                free(sig);
              }
            }
            secure_wipe(nonce, sizeof(nonce));
            const char *auth_name = admin_u ? admin_u->name : "?";

            if (pass_ok) {
              /* client->id is the admin's identity key for storage lookups
               * and logging.  "ADMIN:" + a 63-char name does not fit in
               * id[64], and two long names sharing a prefix would collapse
               * to the same id.  Fail closed rather than authenticate under
               * a truncated identity. */
              if (strlen(auth_name) + sizeof("ADMIN:") > sizeof(client->id)) {
                hub_log("[HUB] Admin auth from %s: name '%s' too long for "
                        "client id — refusing\n", client->ip, auth_name);
                hub_disconnect_client(state, client);
                return false;
              }
              client->type = CLIENT_ADMIN;
              client->authenticated = true;
              /* D2: grow buffers now that the admin is authenticated. */
              if (!hub_client_promote_buffers(client)) {
                hub_log("[HUB][ERROR] Buffer promotion OOM for admin %s — "
                        "disconnecting\n", client->ip);
                hub_disconnect_client(state, client);
                return false;
              }
              snprintf(client->id, sizeof(client->id), "ADMIN:%.*s",
                       (int)(sizeof(client->id) - sizeof("ADMIN:")), auth_name);

              /* Capture admin's reported ip:port (informational) */
              if (client_addr[0]) {
                char *colon = strchr(client_addr, ':');
                if (colon) {
                  int ip_len = (int)(colon - client_addr);
                  if (ip_len >= (int)sizeof(client->admin_connect_ip))
                    ip_len = sizeof(client->admin_connect_ip) - 1;
                  memcpy(client->admin_connect_ip, client_addr, ip_len);
                  client->admin_connect_ip[ip_len] = '\0';
                  client->admin_connect_port = atoi(colon + 1);
                }
              } else {
                client->admin_connect_ip[0] = '\0';
                client->admin_connect_port = 0;
              }

              admin_u->last_seen = time(NULL);
              state->config_dirty = true;
              char afp[KEY_FP_LEN + 1];
              hub_crypto_key_fingerprint(admin_pub, afp);
              hub_log("[HUB] Admin Login (key %s): %s as '%s'\n",
                      afp, client->ip, auth_name);

              /* Tell hub_admin who it is logged in as (encrypted). */
              char ok_msg[96];
              snprintf(ok_msg, sizeof(ok_msg), "AUTH-OK|%s", auth_name);
              if (!send_response(state, client, ok_msg)) {
                secure_wipe(plain, sizeof(plain));
                return false;  /* send_response already disconnected */
              }

              state->anti_entropy_due = true;
              hub_request_sync_from_peers(state);
              broadcast_full_config_to_all_bots(state);
            } else {
              hub_log("[HUB] Failed admin auth from %s: %s\n", client->ip, why);
              record_failed_auth(state, client->ip);
              secure_wipe(plain, sizeof(plain));
              hub_disconnect_client(state, client);
              return false;
            }
          }
          // HUBv2 = a pre-passwordless peer.  It would send a|/o| records with
          // passwords and read ours as passwords, so mixed versions must never
          // exchange state (docs/passwordless.md §3.4): refuse it by name.
          else if (strncmp(payload, "HUBv2|", 6) == 0) {
            hub_log("[HUB] Peer %s speaks HUBv2 (pre-passwordless) — refusing; "
                    "upgrade that hub (all hubs upgrade together)\n",
                    client->ip);
            record_failed_auth(state, client->ip);
            secure_wipe(plain, sizeof(plain));
            hub_disconnect_client(state, client);
            return false;
          }
          // v3 HUB Peer Authentication (Ed25519 signature, no password)
          else if (strncmp(payload, "HUBv3|", 6) == 0) {
            /* Format: "HUBv3|<uuid>|<port>|<name>|<bind_ip>|<ts>|<sig_b64>" */
            char peer_uuid[64] = "", peer_name[64] = "", peer_bind_ip[64] = "";
            char ts_str[32] = "", sig_b64[128] = "";
            int claimed_port = 0;

            /* Parse pipe-separated fields without sscanf-quirks. */
            char work[MAX_BUFFER];
            snprintf(work, sizeof(work), "%s", payload + 6);
            char *sp_v2;
            char *t_uuid    = strtok_r(work,  "|", &sp_v2);
            char *t_port    = strtok_r(NULL,  "|", &sp_v2);
            char *t_name    = strtok_r(NULL,  "|", &sp_v2);
            char *t_bind    = strtok_r(NULL,  "|", &sp_v2);
            char *t_ts      = strtok_r(NULL,  "|", &sp_v2);
            char *t_sig     = strtok_r(NULL,  "|", &sp_v2);
            if (!t_uuid || !t_port || !t_name || !t_bind || !t_ts || !t_sig) {
              hub_log("[HUB] v3 peer auth: malformed payload from %s\n",
                      client->ip);
              secure_wipe(plain, sizeof(plain));
              hub_disconnect_client(state, client);
              return false;
            }
            snprintf(peer_uuid,    sizeof(peer_uuid),    "%s", t_uuid);
            snprintf(peer_name,    sizeof(peer_name),    "%s", t_name);
            snprintf(peer_bind_ip, sizeof(peer_bind_ip), "%s", t_bind);
            snprintf(ts_str,       sizeof(ts_str),       "%s", t_ts);
            snprintf(sig_b64,      sizeof(sig_b64),      "%s", t_sig);
            claimed_port = atoi(t_port);

            /* Locate peer entry by UUID; require stored pubkey. */
            int peer_idx = -1;
            for (int p = 0; p < state->peer_count; p++) {
              if (state->peers[p].uuid[0] &&
                  strcmp(state->peers[p].uuid, peer_uuid) == 0) {
                peer_idx = p;
                break;
              }
            }
            if (peer_idx < 0 || !state->peers[peer_idx].has_pubkey) {
              hub_log("[HUB] v3 peer auth: no pubkey on file for uuid %s "
                      "(from %s) — add the peer with its 88-char pubkey.\n",
                      peer_uuid, client->ip);
              record_failed_auth(state, client->ip);
              secure_wipe(plain, sizeof(plain));
              hub_disconnect_client(state, client);
              return false;
            }

            /* Reconstruct the transcript the sender committed to and verify. */
            char transcript[512];
            int tlen = snprintf(transcript, sizeof(transcript),
                                "irchub-peer-auth-v3|%s|%s|%d|%s|%s",
                                peer_uuid, ts_str, claimed_port,
                                peer_name, peer_bind_ip);
            if (tlen < 0 || tlen >= (int)sizeof(transcript)) {
              hub_log("[HUB] v3 peer auth: transcript overflow\n");
              secure_wipe(plain, sizeof(plain));
              hub_disconnect_client(state, client);
              return false;
            }

            int sig_len = 0;
            unsigned char *sig = base64_decode(sig_b64, &sig_len);
            if (!sig || sig_len != ED25519_SIG_LEN) {
              hub_log("[HUB] v3 peer auth: bad signature length %d\n", sig_len);
              if (sig) { secure_wipe(sig, (size_t)sig_len); free(sig); }
              record_failed_auth(state, client->ip);
              secure_wipe(plain, sizeof(plain));
              hub_disconnect_client(state, client);
              return false;
            }

            bool sig_ok = hub_crypto_ed25519_verify(
                state->peers[peer_idx].ed_pub,
                (unsigned char *)transcript, (size_t)tlen, sig);
            secure_wipe(sig, (size_t)sig_len);
            free(sig);

            if (!sig_ok) {
              hub_log("[HUB] v3 peer auth: signature verify FAILED for uuid %s "
                      "(from %s)\n", peer_uuid, client->ip);
              record_failed_auth(state, client->ip);
              secure_wipe(plain, sizeof(plain));
              hub_disconnect_client(state, client);
              return false;
            }

            /* Freshness window (±60 s). */
            time_t client_ts = (time_t)strtoll(ts_str, NULL, 10);
            time_t now_v2 = time(NULL);
            if (llabs((long long)(now_v2 - client_ts)) > 60) {
              hub_log("[HUB] v3 peer auth: timestamp skew %lds (max 60) for %s\n",
                      (long)(now_v2 - client_ts), peer_uuid);
              record_failed_auth(state, client->ip);
              secure_wipe(plain, sizeof(plain));
              hub_disconnect_client(state, client);
              return false;
            }

            /* Accept. */
            client->type = CLIENT_HUB;
            client->authenticated = true;
            /* D2: grow buffers — peers exchange bulk anti-entropy sync. */
            if (!hub_client_promote_buffers(client)) {
              hub_log("[HUB][ERROR] Buffer promotion OOM for peer %s — "
                      "disconnecting\n", client->ip);
              hub_disconnect_client(state, client);
              return false;
            }
            state->peers[peer_idx].connected = true;
            state->peers[peer_idx].fd = client->fd;
            snprintf(state->peers[peer_idx].remote_ip,
                     sizeof(state->peers[peer_idx].remote_ip), "%s", client->ip);
            if (!state->peers[peer_idx].friendly_name[0] &&
                hub_name_valid(peer_name)) {
              snprintf(state->peers[peer_idx].friendly_name,
                       sizeof(state->peers[peer_idx].friendly_name),
                       "%s", peer_name);
            }
            snprintf(client->id, sizeof(client->id), "%s",
                     state->peers[peer_idx].friendly_name[0] ?
                     state->peers[peer_idx].friendly_name :
                     (hub_name_valid(peer_name) ? peer_name : "HUB-PEER"));
            client->id[sizeof(client->id) - 1] = 0;

            hub_log("[HUB] v3 Peer authenticated by Ed25519 signature: %s (%s)\n",
                    peer_name[0] ? peer_name : client->ip, peer_uuid);

            /* Initial full state sync to the newly authenticated peer. */
            {
              char *init_sync = malloc(MAX_SYNC_PAYLOAD);
              if (init_sync) {
                hub_generate_sync_packet(state, init_sync, MAX_SYNC_PAYLOAD);
                int slen = (int)strlen(init_sync);
                if (slen > 0) {
                  queued_msg_t *sm = queued_msg_new(CMD_PEER_SYNC, LANE_BULK,
                                                   (const unsigned char *)init_sync, slen);
                  if (sm) peer_enqueue(client, sm);
                }
                free(init_sync);
              }
            }
          }
          else {
            secure_wipe(plain, sizeof(plain));
            hub_disconnect_client(state, client);
            return false;
          }

          secure_wipe(plain, sizeof(plain));
        } else {
          secure_wipe(session_key, 32);
          secure_wipe(plain, sizeof(plain));
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
        /* Change 5: an authenticated peer frame (full CMD_PEER_SYNC) can be
         * far larger than MAX_BUFFER — recv_cap was promoted to
         * MAX_SYNC_PAYLOAD for it — so the plaintext must be heap-sized to the
         * frame, not a 16 KB stack buffer.  A stack MAX_BUFFER here both
         * truncated large peer syncs (records past 16 KB were lost) and risked
         * a stack overwrite.  Bot/admin frames stay small; the alloc is sized
         * to this frame and freed on every path. */
        unsigned char tag[GCM_TAG_LEN];
        unsigned char *plain = malloc((size_t)packet_len + 1);
        if (!plain) {
          hub_log("[HUB] OOM decrypting frame from %s\n", client->ip);
          hub_disconnect_client(state, client);
          return false;
        }

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
                secure_wipe(plain, (size_t)packet_len + 1);
                free(plain);
                return false;
              }
              client->last_pong_sent = now;
            }
          } else {
            plain[pl] = 0;
            char *payload_ptr = (char *)plain + 5;

            if (client->type == CLIENT_ADMIN) {
              if (!handle_admin_command(state, client, cmd, payload_ptr,
                                        pl >= 5 ? pl - 5 : 0)) {
                secure_wipe(plain, (size_t)packet_len + 1);
                free(plain);
                return false;
              }
            } else if (client->type == CLIENT_BOT) {
              process_bot_command(state, client, cmd, payload_ptr);
            } else if (client->type == CLIENT_HUB) {
              if (cmd == CMD_PEER_SYNC) {
                process_peer_sync(state, payload_ptr, client->fd);
              } else if (cmd == CMD_MESH_STATE) {
                process_mesh_state(state, client, payload_ptr);
              } else if (cmd == CMD_BOT_ROSTER) {
                process_bot_roster(state, payload_ptr);
              } else if (cmd == CMD_OP_FORWARD_REQUEST) {
                process_forward_op_request(state, client, payload_ptr);
              } else if (cmd == CMD_OP_FORWARD_GRANT) {
                process_forward_op_grant(state, client, payload_ptr);
              } else if (cmd == CMD_OP_FORWARD_FAILED) {
                process_forward_op_failed(state, client, payload_ptr);
              } else if (cmd == CMD_CHAN_FWD_REQUEST) {
                process_forward_chan_request(state, client, payload_ptr);
              } else if (cmd == CMD_CHAN_FWD_REPLY) {
                process_forward_chan_reply(state, client, payload_ptr);
              } else if (cmd == CMD_PEER_REKEY_BOT) {
                /* v3: per-bot independent keys.  Peer-forwarded bot rekey
                 * is rejected because it would carry a private key. */
                hub_log("[HUB] Rejected CMD_PEER_REKEY_BOT from peer %s: "
                        "per-bot independent keys; rekey is bot-local.\n",
                        client->ip);
              } else if (cmd == CMD_SYNC_REQUEST) {
                /* Peer is asking us for our full state immediately.
                 * Send our full sync packet to just this requesting peer. */
                hub_log("[MESH] Sync request from peer %s — sending full state\n",
                        client->ip);
                char *reply_sync = malloc(MAX_SYNC_PAYLOAD);
                if (reply_sync) {
                  hub_generate_sync_packet(state, reply_sync, MAX_SYNC_PAYLOAD);
                  if (reply_sync[0] != '\0') {
                    int reply_len = (int)strlen(reply_sync);
                    queued_msg_t *sm = queued_msg_new(CMD_PEER_SYNC, LANE_BULK,
                                                      (const unsigned char *)reply_sync,
                                                      reply_len);
                    if (sm) peer_enqueue(client, sm);
                  }
                  free(reply_sync);
                }
              } else if (cmd == CMD_UPDATE_PUBKEY) {
                /* v3: independent per-hub keypairs.  A peer must NEVER
                 * push its private key to us.  Refuse and log. */
                hub_log("[HUB] Rejected CMD_UPDATE_PUBKEY from peer %s: "
                        "per-hub independent keys; private keys do not "
                        "cross hub boundaries.\n", client->ip);
              }
            }
          }
        } else {
          hub_log("[HUB] GCM decrypt failed from %s\n", client->ip);
          secure_wipe(plain, (size_t)packet_len + 1);
          free(plain);
          hub_disconnect_client(state, client);
          return false;
        }

        secure_wipe(plain, (size_t)packet_len + 1);
        free(plain);
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
