#include "hub.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <strings.h>
#include <sys/select.h>

static void send_config_to_bot(hub_state_t *state, hub_client_t *client,
                               bool force);
static void hub_broadcast_config_to_bots(hub_state_t *state, const char *config_line);

/* ==========================================================================
 * '|'-delimited wire fields
 *
 * sscanf's "%[^|]" cannot match an EMPTY field: the conversion fails there
 * and every field after it is left untouched.  A frame with an optional
 * middle field — "id|2.99.0|||*|file://…", which is exactly what an upgrade
 * run that names neither a variant nor an artifact kind looks like — was
 * therefore parsed as two fields, silently dropping the manifest base.  Every
 * '|'-framed field is read through these instead; they are the C counterpart
 * of split('|') on the Rust side, so both hubs read a frame identically.
 * ========================================================================== */

/* Field `idx` of `s`, NUL-terminated into `dst`.  An over-long field is a
 * malformed frame, not something to truncate silently: false, `dst` empty. */
hub_stats_t g_hub_stats;

/* A config push that never reaches its bot must not stand as "sent", or the
 * next identical broadcast would be skipped and the bot left behind. */
static void cfg_push_lost(hub_client_t *c, const queued_msg_t *m) {
  if (m->cmd == CMD_BOT_TREE) c->tree_sent_valid = false; /* same for a tree */
  if (m->cmd != CMD_CONFIG_DATA) return;
  c->cfg_sent_valid = false;
  g_hub_stats.cfg_lost++;
}

/* Max-merge one activity time (last_seen / last_used) outside LWW.  A rise
 * is persisted but is never a config update: nothing forwarded or pushed. */
static bool activity_raise(hub_state_t *state, time_t *slot, time_t ts) {
  if (ts <= *slot || ts > time(NULL) + ACTIVITY_MAX_FUTURE) return false;
  *slot = ts;
  state->config_dirty = true;
  return true;
}

static bool wire_field(const char *s, int idx, char *dst, size_t cap) {
  if (!dst || cap == 0) return false;
  dst[0] = '\0';
  if (!s) return false;
  for (int i = 0; i < idx; i++) {
    const char *bar = strchr(s, '|');
    if (!bar) return false;
    s = bar + 1;
  }
  const char *bar = strchr(s, '|');
  size_t len = bar ? (size_t)(bar - s) : strcspn(s, "\r\n");
  if (len >= cap) return false;
  memcpy(dst, s, len);
  dst[len] = '\0';
  return true;
}

/* Field `idx` and everything after it, minus any trailing CR/LF.  The last
 * field of a frame is free text (a reason, a base URL) and may contain '|';
 * display text is clamped to the buffer rather than rejected. */
static bool wire_tail(const char *s, int idx, char *dst, size_t cap) {
  if (!dst || cap == 0) return false;
  dst[0] = '\0';
  if (!s) return false;
  for (int i = 0; i < idx; i++) {
    const char *bar = strchr(s, '|');
    if (!bar) return false;
    s = bar + 1;
  }
  size_t len = strcspn(s, "\r\n");
  if (len >= cap) len = cap - 1;
  memcpy(dst, s, len);
  dst[len] = '\0';
  return true;
}

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
      hub_log_warning("[MESH] queue %s lane full — dropping oldest (peer fd=%d)\n",
              li == LANE_DELTA ? "DELTA" : "BULK", peer->fd);
      cfg_push_lost(peer, old);
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
  if (m->cmd == CMD_CONFIG_DATA || m->cmd == CMD_BOT_TREE ||
      m->cmd == CMD_ACTIVITY_REPLY) {
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
    hub_log_warning("[MESH] send error to %s (fd=%d): %s\n", peer->ip, peer->fd,
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
      if (wire_len <= 0) {
        hub_log_error("[MESH] encrypt failed for peer %s lane %d\n", peer->ip, li);
        cfg_push_lost(peer, m);
        queued_msg_free(m);
        continue;  /* drop and move on */
      }
      g_hub_stats.tx_frames[m->cmd]++;
      g_hub_stats.tx_bytes[m->cmd] += (uint64_t)wire_len;
      queued_msg_free(m);
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
        hub_log_warning("[MESH] send error to %s (fd=%d): %s\n", peer->ip, peer->fd,
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
    hub_log_warning("[URGENT] Queue full for peer %s — disconnecting\n", peer->ip);
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
static void process_peer_sync(hub_state_t *state, char *payload, int origin_fd,
                              bool bcast);
static bool handle_admin_command(hub_state_t *state, hub_client_t *client,
                                 int cmd, char *payload, int payload_len);
static void process_bot_command(hub_state_t *state, hub_client_t *client,
                                int cmd, char *payload);

/* Network upgrade orchestration (definitions live next to
 * process_bot_command, after send_cmd_to_bot). */
static bool hub_upgrade_start(hub_state_t *state, hub_client_t *admin,
                              const char *target_ver, const char *variant,
                              const char *kind, const char *min_from,
                              const char *base, const char *hub_ver,
                              const char *hub_base, char *msg,
                              size_t msg_size);
static void hub_upgrade_status(hub_state_t *state, char *out, size_t out_size);
static void hub_upgrade_note_ready(hub_state_t *state, const char *payload,
                                   hub_client_t *from_peer);
static hub_client_t *upgrade_find_client(hub_state_t *state, const char *uuid,
                                         client_type_t type);
static hub_client_t *upgrade_find_peer(hub_state_t *state, const char *uuid);
static const char *upgrade_peer_uuid(const hub_state_t *state,
                                     const hub_client_t *c);
static void hub_upgrade_note_result(hub_state_t *state, const char *payload);
static void hub_upgrade_abort(hub_state_t *state, const char *reason);
static void process_peer_upgrade_prepare(hub_state_t *state,
                                         hub_client_t *peer,
                                         const char *payload);
static void process_peer_upgrade_commit(hub_state_t *state, hub_client_t *peer,
                                        const char *payload);
static void process_peer_upgrade_abort(hub_state_t *state, hub_client_t *peer,
                                       const char *payload);
static void hub_upgrade_note_presence(hub_state_t *state, const char *uuid,
                                      const char *version);
static void hub_rollup_note_presence(hub_state_t *state, const char *uuid,
                                     char node_kind, const char *version);
static bool hub_rollup_note_ready(hub_state_t *state, const char *payload);
static bool hub_rollup_note_result(hub_state_t *state, const char *payload);
static bool hub_rollup_forget(hub_state_t *state, const char *why);
static void hub_request_sync_from_peers(hub_state_t *state);
static void process_peer_upgrade_forget(hub_state_t *state, hub_client_t *peer,
                                        const char *payload);
static bool hub_config_frozen(const hub_state_t *state);
static bool hub_admin_cmd_mutates_config(int cmd);

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
/* The peer link to the hub the roster places bot `target_uuid` on, or NULL
 * (flood) when it is on no direct peer, on more than one hub (mid-move), or
 * unknown.  Never the peer on `exclude_fd`: that is where it came from. */
static hub_client_t *op_route_peer(hub_state_t *state, const char *target_uuid,
                                   int exclude_fd) {
  const char *home = NULL;
  for (int r = 0; r < state->roster_count; r++) {
    if (strcmp(state->roster[r].bot_uuid, target_uuid) != 0) continue;
    if (home && strcmp(home, state->roster[r].hub_uuid) != 0) return NULL;
    home = state->roster[r].hub_uuid;
  }
  if (!home) return NULL;
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type == CLIENT_HUB && c->authenticated && c->fd != exclude_fd &&
        strcmp(upgrade_peer_uuid(state, c), home) == 0)
      return c;
  }
  return NULL;
}

static void forward_op_request_to_peers(hub_state_t *state,
                                         const char *request_id,
                                         const char *requester_uuid,
                                         const char *target_uuid,
                                         const char *channel,
                                         const char *requester_hostmask,
                                         int exclude_fd,
                                         time_t origin_ts, bool split);
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
  time_t window = id[0] ? PURGE_DEDUP_WINDOW : PURGE_DEDUP_WINDOW_LEGACY;
  for (int i = 0; i < state->recent_purge_count; i++) {
    if (state->recent_purges[i].cutoff == cutoff &&
        strcmp(state->recent_purges[i].id, id) == 0 &&
        now - state->recent_purges[i].received_at < window)
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
    hub_log_error("[PURGE] no random bytes for a purge id; purge not broadcast\n");
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
        hub_log_warning("[RATE_LIMIT] IP %s is blocked until %ld\n",
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
        hub_log_warning("[RATE_LIMIT] IP %s connection churn flood (%d conns/%ds) — "
                "blocked %ds\n", ip, entry->churn_count, CHURN_WINDOW_SEC,
                CHURN_BLOCK_SEC);
        return false;
    }

    // Check connection limit
    if (entry->active_connections >= MAX_CONNECTIONS_PER_IP) {
        hub_log_warning("[RATE_LIMIT] IP %s exceeded connection limit (%d/%d)\n",
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

    hub_log_warning("[AUTH_FAIL] IP %s failed auth (attempt %d/%d)\n",
            ip, entry->failed_auth_count, MAX_FAILED_AUTH_ATTEMPTS);

    // Block if exceeded max attempts
    if (entry->failed_auth_count >= MAX_FAILED_AUTH_ATTEMPTS) {
        entry->blocked_until = now + FAILED_AUTH_BLOCK_DURATION;
        hub_log_warning("[AUTH_BLOCK] IP %s blocked for %d seconds (too many failed attempts)\n",
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
    hub_log_warning("[ACCESS_CONTROL] IP %s denied (%s)\n", ip,
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

    hub_log_debug("[HUB] Bot auth attempt from %s with UUID: %s\n", client->ip, uuid);

    bool authorized = false;
    for (int i = 0; i < state->bot_count; i++) {
      if (strcmp(state->bots[i].uuid, uuid) == 0 &&
          state->bots[i].is_active) { authorized = true; break; }
    }

    if (!authorized) {
      hub_log_warning("[HUB] Unauthorized bot UUID: %s from %s\n", uuid, client->ip);
      add_pending_bot(state, uuid, client->ip);
      record_failed_auth(state, client->ip);
      return false;
    }

    // Generate challenge + ephemeral X25519 keypair
    if (RAND_bytes(client->challenge, 32) != 1) {
      hub_log_error("[HUB] Failed to generate challenge\n");
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
               hub_log_error("[HUB] Ephemeral X25519 keygen failed\n"); return false; }
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
      hub_log_error("[HUB] transcript alloc failed\n");
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
      hub_log_error("[HUB] Hub Ed25519 sign failed\n");
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
      hub_log_warning("[HUB] Failed to send v2 challenge to %s\n", uuid);
      return false;
    }

    snprintf(client->id, sizeof(client->id), "%s", uuid);
    client->bot_auth_state = BOT_AUTH_CHALLENGE_SENT;
    client->last_seen = time(NULL);

    hub_log_debug("[HUB] Sent v2 signed Curve25519 challenge to bot %s\n", uuid);
    return true;
  }

  // PHASE 2: Receive 64-byte Ed25519 signature
  if (!client->authenticated &&
      client->bot_auth_state == BOT_AUTH_CHALLENGE_SENT) {
    hub_log_debug("[HUB] Received signature from bot %s (%d bytes)\n", client->id, packet_len);

    if (packet_len != 64 || !client->bot_eph_priv_set) {
      hub_log_warning("[HUB] Bad signature size or state from %s\n", client->id);
      return false;
    }

    unsigned char bot_combined[64], bot_ed_pub[32], bot_x_pub[32];
    if (!load_bot_combined_pub(state, client->id, bot_combined)) {
      hub_log_warning("[HUB] No public key for bot %s\n", client->id);
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
        hub_log_error("[HUB] OOM building challenge transcript for %s\n",
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
        hub_log_warning("[HUB] Invalid signature from bot %s\n", client->id);
        record_failed_auth(state, client->ip);
        secure_wipe(bot_combined, 64);
        return false;
      }
    }

    unsigned char shared[32];
    if (!hub_crypto_x25519_derive(client->bot_eph_x25519_priv, bot_x_pub, shared)) {
      hub_log_error("[HUB] X25519 derive failed for %s\n", client->id);
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
      hub_log_error("[HUB] HKDF failed for %s\n", client->id);
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
      hub_log_error("[HUB] ACK encrypt failed for %s\n", client->id);
      return false;
    }
    memcpy(ack_wire + enc_len, ack_tag, GCM_TAG_LEN);
    int ack_total = enc_len + GCM_TAG_LEN;

    uint32_t nl = htonl((uint32_t)ack_total);
    if (write(client->fd, &nl, 4) != 4 ||
        write(client->fd, ack_wire, ack_total) != ack_total) {
      hub_log_warning("[HUB] Failed to send v2 ACK to %s\n", client->id);
      return false;
    }

    client->type = CLIENT_BOT;
    client->authenticated = true;
    client->bot_auth_state = BOT_AUTH_COMPLETE;
    client->last_seen = time(NULL);

    /* D2: grow buffers to full size now that the bot is authenticated. */
    if (!hub_client_promote_buffers(client)) {
      hub_log_error("[HUB] Buffer promotion OOM for %s — disconnecting\n",
              client->id);
      return false;
    }

    hub_storage_update_entry(state, client->id, "seen", "", "", "", client->last_seen);

    /* A new bot joins the tree: gossip and push on the next tick instead of
     * leaving it invisible to the mesh until the periodic refresh. */
    hub_roster_mark_dirty(state, true);
    state->last_presence_gossip = 0;

    hub_log_info("[HUB] Bot %s authenticated (Curve25519)\n", client->id);
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
              hub_log_debug("[MESH] Updated peer friendly_name to: %s\n", remote_name);
              config_updated = true;
            }
          }

          // Also update UUID if it changed (in case peer was added without UUID)
          if (fields >= 3 && remote_uuid[0] && strcmp(remote_uuid, "-") != 0) {
            if (!state->peers[i].uuid[0] ||
                strcmp(state->peers[i].uuid, remote_uuid) != 0) {
              snprintf(state->peers[i].uuid,
                      sizeof(state->peers[i].uuid), "%s", remote_uuid);
              hub_log_debug("[MESH] Updated peer UUID to: %s\n", remote_uuid);
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

void hub_roster_mark_dirty(hub_state_t *state, bool local) {
  state->tree_dirty = true;
  if (local) state->tree_dirty_local = true;
}

void hub_roster_expire(hub_state_t *state, time_t now) {
  for (int i = 0; i < state->roster_count;) {
    if (now - state->roster[i].reported_at > BOT_ROSTER_TTL) {
      hub_log_info("[PRESENCE] %s on hub %s aged out of the roster\n",
              state->roster[i].nick[0] ? state->roster[i].nick
                                       : state->roster[i].bot_uuid,
              state->roster[i].hub_name);
      state->roster[i] = state->roster[--state->roster_count];
      state->tree_dirty = true;
      continue; /* the swapped-in entry still needs checking */
    }
    i++;
  }
  for (int i = 0; i < state->mesh_hub_count;) {
    if (now - state->mesh_hubs[i].reported_at > BOT_ROSTER_TTL) {
      hub_log_info("[PRESENCE] Hub %s aged out of the mesh map\n",
              state->mesh_hubs[i].name[0] ? state->mesh_hubs[i].name
                                          : state->mesh_hubs[i].uuid);
      state->mesh_hubs[i] = state->mesh_hubs[--state->mesh_hub_count];
      state->tree_dirty = true;
      continue;
    }
    i++;
  }
}

/* The mesh-map record for hub `uuid`, or NULL. */
static mesh_hub_t *mesh_hub_find(hub_state_t *state, const char *uuid) {
  for (int i = 0; i < state->mesh_hub_count; i++)
    if (strcmp(state->mesh_hubs[i].uuid, uuid) == 0) return &state->mesh_hubs[i];
  return NULL;
}

/* ...created on first sight.  NULL when the map is full: that hub's frames
 * are then applied as before but not relayed, so a map overflow degrades to
 * the one-hop tree instead of a relay loop. */
static mesh_hub_t *mesh_hub_get(hub_state_t *state, const char *uuid) {
  mesh_hub_t *h = mesh_hub_find(state, uuid);
  if (h) return h;
  if (state->mesh_hub_count >= MAX_MESH_HUBS) {
    hub_log_warning("[PRESENCE] Mesh map full (%d) — %s is not relayed\n",
            MAX_MESH_HUBS, uuid);
    return NULL;
  }
  h = &state->mesh_hubs[state->mesh_hub_count++];
  memset(h, 0, sizeof(*h));
  snprintf(h->uuid, sizeof(h->uuid), "%s", uuid);
  h->gen = -1;
  return h;
}

/* Same links, same order: what a hub's l| lines render in the tree.
 * old_n < 0 is "no list before", which is always a change. */
static bool mesh_links_equal(const mesh_link_t *a, int old_n,
                             const mesh_link_t *b, int new_n) {
  if (old_n != new_n) return false;
  for (int i = 0; i < new_n; i++)
    if (a[i].online != b[i].online || strcmp(a[i].uuid, b[i].uuid) != 0 ||
        strcmp(a[i].name, b[i].name) != 0)
      return false;
  return true;
}

/* True when our link to configured peer `p` is up right now. */
static bool peer_is_linked(const hub_state_t *state, const hub_peer_config_t *p) {
  if (p->fd <= 0) return false;
  for (int c = 0; c < state->client_count; c++)
    if (state->clients[c]->type == CLIENT_HUB &&
        state->clients[c]->authenticated && state->clients[c]->fd == p->fd)
      return true;
  return false;
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
                   strcmp(e->variant, in->variant) != 0 ||
                   strcmp(e->server, in->server) != 0 ||
                   e->connected_at != in->connected_at;
    *e = *in;
    if (changed) state->tree_dirty = true;
    return;
  }
  if (state->roster_count >= MAX_BOT_ROSTER) {
    hub_log_warning("[PRESENCE] Roster full (%d) — dropping report for %s\n",
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
  char variant[ROSTER_VARIANT_MAX + 1] = "";
  long long started = 0;

  /* "<version>|<server>|<started>|<variant>" — a short, fixed shape.  The
   * variant (code base, c / rs) is the newest field; a bot that predates it
   * sends three and simply shows no code base.  Anything longer than the
   * field caps is truncated by roster_clean, never rejected, so a newer bot
   * advertising more never drops off the tree entirely. */
  char work[ROSTER_VERSION_MAX + ROSTER_SERVER_MAX + ROSTER_VARIANT_MAX + 64];
  snprintf(work, sizeof(work), "%s", payload ? payload : "");
  char *p1 = strchr(work, '|');
  if (p1) {
    *p1 = '\0';
    char *p2 = strchr(p1 + 1, '|');
    if (p2) {
      *p2 = '\0';
      char *p3 = strchr(p2 + 1, '|');
      if (p3) {
        *p3 = '\0';
        char *p4 = strchr(p3 + 1, '|'); /* room for fields after it */
        if (p4) *p4 = '\0';
        roster_clean(variant, sizeof(variant), p3 + 1);
      }
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
                 strcmp(client->bot_variant, variant) != 0 ||
                 client->bot_started != (time_t)started;
  snprintf(client->bot_version, sizeof(client->bot_version), "%s", version);
  snprintf(client->bot_server, sizeof(client->bot_server), "%s", server);
  snprintf(client->bot_variant, sizeof(client->bot_variant), "%s", variant);
  client->bot_started = (time_t)started;

  if (changed) {
    hub_log_info("[PRESENCE] Bot %s: version %s (%s) on %s\n", client->id,
            version[0] ? version : "?", variant[0] ? variant : "?",
            server[0] ? server : "(no server)");
    hub_roster_mark_dirty(state, true);
    state->last_presence_gossip = 0; /* gossip the change on the next tick */
  }

  /* A committed node coming back on the target version is the authoritative
   * success signal for a rolling upgrade — CMD_UPGRADE_RESULT can be lost,
   * but without this frame the bot is not on the mesh at all. */
  hub_upgrade_note_presence(state, client->id, version);
  hub_rollup_note_presence(state, client->id, 'b', version);

  /* If this hub is following a run another hub drives, a local bot reappearing
   * on the followed target is that bot's authoritative success: synthesize a
   * RESULT up to the driver so a lost bot RESULT does not stall the run. */
  if (state->follow_id[0] && version[0] &&
      strcmp(version, state->follow_target) == 0) {
    hub_client_t *origin = upgrade_find_peer(state, state->follow_origin);
    if (origin) {
      char p[192];
      snprintf(p, sizeof(p), "%s|%s|ok|%s|", state->follow_id, client->id,
               version);
      peer_send_urgent(state, origin, CMD_UPGRADE_RESULT, p);
    }
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

/* One roster frame to every authenticated peer except `skip` (NULL: all).
 * Deliberately NOT coalesced: a large roster is chunked into several frames
 * and coalescing on one key would collapse them into whichever arrived last.
 * Best-effort on the BULK lane — a dropped frame just means those bots
 * refresh on the next tick. */
static void roster_send_to_peers(hub_state_t *state, const char *frame,
                                 int len, const hub_client_t *skip,
                                 const mesh_hub_t *origin) {
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type != CLIENT_HUB || !c->authenticated || c == skip) continue;
    /* Split horizon for a relayed frame: a peer that IS the origin, or that
     * the origin says it is linked to right now, already has it first hand.
     * On a full mesh this leaves nothing to relay at all. */
    if (origin) {
      const char *cu = upgrade_peer_uuid(state, c);
      bool direct = cu[0] && strcmp(cu, origin->uuid) == 0;
      for (int l = 0; l < origin->link_count && !direct; l++)
        direct = origin->links[l].online && cu[0] &&
                 strcmp(origin->links[l].uuid, cu) == 0;
      if (direct) continue;
    }
    queued_msg_t *m = queued_msg_new(CMD_BOT_ROSTER, LANE_BULK,
                                     (const unsigned char *)frame, len);
    if (!m) continue;
    if (!peer_enqueue(c, m))
      hub_log_warning("[PRESENCE] roster enqueue failed for peer %s\n", c->ip);
  }
}

/* Start one gossip frame: the header lines every frame repeats, the relay
 * line, and — on the first chunk only — this hub's peer links.  Returns the
 * offset rows start at, or -1 if it cannot fit. */
static int roster_frame_begin(hub_state_t *state, char *frame, int cap,
                              long long gen, int chunk) {
  int off = snprintf(frame, cap, "h|%s|%s|%lld|%s\nv|%s\ng|%lld|%d|%d\n",
                     state->hub_uuid[0] ? state->hub_uuid : "-",
                     state->hub_friendly_name[0] ? state->hub_friendly_name
                                                 : "-",
                     (long long)state->hub_started, HUB_VERSION,
                     HUB_UPDATE_VARIANT, gen, chunk, ROSTER_RELAY_HOPS);
  if (off <= 0 || off >= cap) return -1;
  if (chunk != 0) return off;
  for (int p = 0; p < state->peer_count; p++) {
    const hub_peer_config_t *peer = &state->peers[p];
    if (!peer->uuid[0]) continue;
    char pname[64];
    roster_clean(pname, sizeof(pname),
                 peer->friendly_name[0] ? peer->friendly_name : peer->ip);
    int w = snprintf(frame + off, cap - off, "l|%s|%s|%d\n", peer->uuid,
                     pname[0] ? pname : "-",
                     peer_is_linked(state, peer) ? 1 : 0);
    if (w <= 0 || w >= cap - off) return -1;
    off += w;
  }
  return off;
}

/* Gossip the bots connected to THIS hub out to the peers.  Chunked to a byte
 * budget: each frame repeats the h| header and carries whole rows only, so a
 * receiver can apply any frame on its own without waiting for the rest.
 *
 * Frame shape:
 *   h|<hub_uuid>|<name>|<started>|<hub_version>
 *   v|<hub_variant>                          (this hub's code base: c / rs)
 *   g|<gen>|<chunk>|<ttl>                    (relay control, see below)
 *   l|<peer_uuid>|<peer_name>|<online>       (first chunk only, per peer)
 *   b|<bot_uuid>|<nick>|<version>|<server>|<started>|<variant>
 * The hub's variant is a line of its own, not a sixth h| field: a hub that
 * predates it reads everything after the version's '|' into the version
 * (roster_clean drops the '|'), which would read as "2.4.0c" and stall any
 * upgrade run waiting on "2.4.0".  Older hubs skip an unknown line, which is
 * also why g| and l| are lines of their own.  The b| variant can ride last
 * because older hubs split five fields and atoll() the start time, which
 * stops at the '|'.
 *
 * g| makes the gossip multi-hop: a hub that receives a frame it has not seen
 * (origin, gen, chunk) passes it on with ttl-1, so every hub hears every
 * other hub however the peers are wired.  l| is what lets a receiver draw
 * the mesh deeper than its own peers. */
static void hub_gossip_bot_roster(hub_state_t *state) {
  if (state->peer_count == 0) return;

  char frame[ROSTER_FRAME_BUDGET];
  time_t now = time(NULL);
  /* Generations only ever grow, across restarts too (wall-clock based), so a
   * receiver can tell a new round from a late copy of an old one. */
  long long gen = (long long)now * 1000;
  if (gen <= state->roster_gen) gen = state->roster_gen + 1;
  state->roster_gen = gen;

  int chunk = 0;
  int offset = roster_frame_begin(state, frame, sizeof(frame), gen, chunk);
  if (offset < 0) return;
  int rows = 0, frames = 0;

  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type != CLIENT_BOT || !c->authenticated) continue;

    char nick[MAX_NICK];
    bot_nick_from_config(state, c->id, nick, sizeof(nick));
    char row[TREE_ROW_MAX];
    int rl = snprintf(row, sizeof(row), "b|%s|%s|%s|%s|%lld|%s\n", c->id,
                      nick[0] ? nick : "-",
                      c->bot_version[0] ? c->bot_version : "-",
                      c->bot_server[0] ? c->bot_server : "-",
                      (long long)c->bot_started,
                      c->bot_variant[0] ? c->bot_variant : "-");
    if (rl <= 0 || rl >= (int)sizeof(row)) continue; /* unrepresentable row */

    if (offset + rl >= (int)sizeof(frame) && rows > 0) { /* full: flush */
      roster_send_to_peers(state, frame, offset, NULL, NULL);
      frames++;
      offset = roster_frame_begin(state, frame, sizeof(frame), gen, ++chunk);
      if (offset < 0) return;
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
    roster_send_to_peers(state, frame, offset, NULL, NULL);
  state->last_presence_gossip = now;
}

/* Read the h| and g| lines of a roster frame without touching it.  Returns
 * true when the frame carries a g| relay line. */
static bool roster_frame_peek(const char *payload, char *origin, size_t ocap,
                              long long *started, long long *gen, int *chunk,
                              int *ttl) {
  bool have_g = false;
  origin[0] = '\0';
  *started = 0;
  for (const char *line = payload; line && *line;) {
    const char *nl = strchr(line, '\n');
    size_t len = nl ? (size_t)(nl - line) : strlen(line);
    char buf[256];
    if (len < sizeof(buf)) {
      memcpy(buf, line, len);
      buf[len] = '\0';
      if (strncmp(buf, "h|", 2) == 0 && !origin[0]) {
        char tmp[64] = "", st[24] = "";
        if (wire_field(buf + 2, 0, tmp, sizeof(tmp)))
          roster_clean(origin, ocap, tmp);
        if (wire_field(buf + 2, 2, st, sizeof(st))) *started = atoll(st);
      } else if (strncmp(buf, "g|", 2) == 0 && !have_g) {
        char g[24] = "", c[12] = "", t[12] = "";
        if (wire_field(buf + 2, 0, g, sizeof(g)) &&
            wire_field(buf + 2, 1, c, sizeof(c)) &&
            wire_field(buf + 2, 2, t, sizeof(t)) && g[0]) {
          *gen = atoll(g);
          *chunk = atoi(c);
          *ttl = atoi(t);
          have_g = true;
        }
      }
    }
    line = nl ? nl + 1 : NULL;
  }
  return have_g;
}

/* The same frame with its g| ttl replaced, for the next hop.  Returns the new
 * length, or -1. */
static int roster_frame_rettl(const char *payload, char *out, int cap,
                              long long gen, int chunk, int ttl) {
  int off = 0;
  for (const char *line = payload; line && *line;) {
    const char *nl = strchr(line, '\n');
    size_t len = nl ? (size_t)(nl - line) : strlen(line);
    int w;
    if (strncmp(line, "g|", 2) == 0)
      w = snprintf(out + off, cap - off, "g|%lld|%d|%d\n", gen, chunk, ttl);
    else
      w = snprintf(out + off, cap - off, "%.*s\n", (int)len, line);
    if (w <= 0 || w >= cap - off) return -1;
    off += w;
    line = nl ? nl + 1 : NULL;
  }
  return off;
}

/* A hub told us which bots are on it — a peer about itself, or any hub
 * further out, relayed.  `from` is the peer link it arrived on. */
static void process_bot_roster(hub_state_t *state, hub_client_t *from,
                               char *payload) {
  char hub_uuid[64] = "", hub_name[64] = "";
  time_t now = time(NULL);
  char *saveptr = NULL;

  /* Relay bookkeeping first, on the untouched frame. */
  char origin[64];
  long long o_started = 0, gen = 0;
  int chunk = 0, ttl = 0;
  bool relayable = roster_frame_peek(payload, origin, sizeof(origin),
                                     &o_started, &gen, &chunk, &ttl);
  if (!origin[0] || strcmp(origin, "-") == 0) return;
  if (state->hub_uuid[0] && strcmp(origin, state->hub_uuid) == 0)
    return; /* our own gossip, back around a cycle */
  mesh_hub_t *mh = mesh_hub_get(state, origin);
  if (relayable && mh) {
    /* A restarted origin starts its generations over from its clock, so a
     * new start time resets the window rather than reading as stale. */
    if (o_started > 0 && mh->started > 0 && (time_t)o_started != mh->started) {
      mh->gen = -1;
      mh->chunks_seen = 0;
    }
    if (gen < mh->gen) return; /* a late copy of an older round */
    uint64_t bit = (chunk >= 0 && chunk < 64) ? (1ULL << chunk) : 0;
    if (gen == mh->gen && (!bit || (mh->chunks_seen & bit))) return;
    if (gen > mh->gen) {
      mh->gen = gen;
      mh->chunks_seen = 0;
    }
    mh->chunks_seen |= bit;
  }
  char *relay = NULL;
  int relay_len = -1;
  if (relayable && mh && ttl > 1 && ttl <= ROSTER_RELAY_HOPS) {
    relay = malloc(ROSTER_FRAME_BUDGET + 64);
    if (relay)
      relay_len = roster_frame_rettl(payload, relay, ROSTER_FRAME_BUDGET + 64,
                                     gen, chunk, ttl - 1);
  }
  bool links_reset = false;
  /* The link list this frame replaces: re-rendering every bot's tree is only
   * worth it when the list really changed, not on every gossip round. */
  mesh_link_t old_links[MAX_PEERS];
  int old_link_count = -1;

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
      if (!hub_uuid[0]) continue;
      bool sane_start = started > 0 && (time_t)started <= now;
      /* The header doubles as the remote hub's uptime and version beacon.
       * Clamp rather than trust: a peer's clock skew would render as a
       * negative uptime. */
      if (mh && strcmp(mh->uuid, hub_uuid) == 0) {
        if (strcmp(mh->name, hub_name) != 0 ||
            strcmp(mh->version, hub_ver) != 0 ||
            (sane_start && mh->started != (time_t)started))
          state->tree_dirty = true;
        snprintf(mh->name, sizeof(mh->name), "%s", hub_name);
        snprintf(mh->version, sizeof(mh->version), "%s", hub_ver);
        if (sane_start) mh->started = (time_t)started;
        mh->reported_at = now;
      }
      for (int p = 0; p < state->peer_count; p++) {
        if (!state->peers[p].uuid[0] ||
            strcmp(state->peers[p].uuid, hub_uuid) != 0)
          continue;
        if (sane_start && state->peers[p].remote_started != (time_t)started) {
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
      /* Same authoritative signal the bots give through their presence: a
       * hub node of a run we drive is done when it reappears in the gossip on
       * the target version.  Its CMD_UPGRADE_RESULT can be lost — several
       * hops more of it, now that a run reaches the whole mesh — but this
       * gossip cannot, or the hub is not on the mesh at all.  Relayed gossip
       * counts too: that is how a hub several hops out reports in.
       * No roll-up here: a peer hub is never rolled up by a PREPARE from its
       * neighbour.  A peer cannot tell a single-node roll-up PREPARE from a
       * run's, so it would fan the frame out to the whole mesh — and every
       * hub holding the plan would do the same to every other, which is the
       * storm a hub-and-bot net produced. */
      hub_upgrade_note_presence(state, hub_uuid, hub_ver);
      continue;
    }
    if (strncmp(line, "v|", 2) == 0) {
      /* The code base of the hub whose h| header this frame opened with. */
      if (!hub_uuid[0] || strcmp(hub_uuid, "-") == 0) continue;
      char hv[ROSTER_VARIANT_MAX + 1];
      roster_clean(hv, sizeof(hv), line + 2);
      if (mh && strcmp(mh->uuid, hub_uuid) == 0 && strcmp(mh->variant, hv) != 0) {
        snprintf(mh->variant, sizeof(mh->variant), "%s", hv);
        state->tree_dirty = true;
      }
      for (int p = 0; p < state->peer_count; p++) {
        if (!state->peers[p].uuid[0] ||
            strcmp(state->peers[p].uuid, hub_uuid) != 0)
          continue;
        if (strcmp(state->peers[p].remote_variant, hv) != 0) {
          snprintf(state->peers[p].remote_variant,
                   sizeof(state->peers[p].remote_variant), "%s", hv);
          state->tree_dirty = true;
        }
        break;
      }
      continue;
    }
    if (strncmp(line, "l|", 2) == 0) {
      /* The origin's peer links, first chunk of a round only: the list
       * replaces what we had, so a link it dropped disappears. */
      if (!relayable || chunk != 0 || !mh || strcmp(mh->uuid, hub_uuid) != 0)
        continue;
      if (!links_reset) {
        old_link_count = mh->have_links ? mh->link_count : -1;
        if (old_link_count > 0)
          memcpy(old_links, mh->links, sizeof(mesh_link_t) * (size_t)old_link_count);
        mh->link_count = 0;
        mh->have_links = true;
        links_reset = true;
      }
      char lu[64] = "", ln[64] = "", lo[4] = "";
      if (!wire_field(line + 2, 0, lu, sizeof(lu)) ||
          !wire_field(line + 2, 1, ln, sizeof(ln)) ||
          !wire_field(line + 2, 2, lo, sizeof(lo)))
        continue;
      if (mh->link_count >= MAX_PEERS) continue;
      mesh_link_t *L = &mh->links[mh->link_count];
      roster_clean(L->uuid, sizeof(L->uuid), lu);
      if (!L->uuid[0]) continue;
      roster_clean(L->name, sizeof(L->name), ln);
      L->online = lo[0] == '1';
      mh->link_count++;
      continue;
    }
    if (strncmp(line, "b|", 2) != 0) continue;
    /* A row before its header has no hub to hang off — ignore it rather than
     * guess, so a malformed frame cannot graft bots onto the wrong branch. */
    if (!hub_uuid[0] || strcmp(hub_uuid, "-") == 0) continue;
    /* Never let a peer report bots as belonging to US: our own branch is
     * built from our live client list and nothing else. */
    if (state->hub_uuid[0] && strcmp(hub_uuid, state->hub_uuid) == 0) continue;

    /* Five fields from any hub; a sixth (the bot's code base) from one that
     * knows it. */
    char *fields[6] = {NULL, NULL, NULL, NULL, NULL, NULL};
    char *cur = line + 2;
    int n = 0;
    while (n < 6) {
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
    if (n >= 6 && strcmp(fields[5], "-") != 0)
      roster_clean(e.variant, sizeof(e.variant), fields[5]);
    long long started = atoll(fields[4]);
    /* Clamp a peer's clock skew rather than trusting it: a future start time
     * would render as a negative uptime. */
    e.connected_at = (started > 0 && (time_t)started <= now) ? (time_t)started : 0;
    e.reported_at = now;
    roster_upsert(state, &e);
  }

  if (links_reset && !mesh_links_equal(old_links, old_link_count, mh->links,
                                        mh->link_count))
    state->tree_dirty = true;

  /* Pass it on after applying it, so the split horizon uses the links this
   * very frame just reported. */
  if (relay && relay_len > 0)
    roster_send_to_peers(state, relay, relay_len, from, mh);
  free(relay);
}

/* "<version> (<code base>)" for a bot that is on the mesh right now, e.g.
 * "2.4.0 (rs)": our own live client first, else the freshest peer report.
 * The bare version when the reporter did not say which code base, "-" when
 * nobody reports the bot at all.  For hub_admin's bot list. */
static void bot_version_label(const hub_state_t *state, const char *uuid,
                              char *out, size_t cap) {
  const char *ver = "", *var = "";
  bool found = false;
  for (int i = 0; i < state->client_count && !found; i++) {
    const hub_client_t *c = state->clients[i];
    if (c->type != CLIENT_BOT || !c->authenticated ||
        strcmp(c->id, uuid) != 0)
      continue;
    ver = c->bot_version;
    var = c->bot_variant;
    found = true;
  }
  time_t freshest = 0;
  for (int r = 0; r < state->roster_count && !found; r++) {
    const bot_roster_t *e = &state->roster[r];
    if (strcmp(e->bot_uuid, uuid) != 0 || e->reported_at < freshest) continue;
    freshest = e->reported_at;
    ver = e->version;
    var = e->variant;
  }
  if (!ver[0])
    snprintf(out, cap, "-");
  else if (var[0])
    snprintf(out, cap, "%s (%s)", ver, var);
  else
    snprintf(out, cap, "%s", ver);
}

/* One hub node of the tree while it is being laid out. */
enum { TREE_HUBS = MAX_MESH_HUBS + MAX_PEERS + 1 };
typedef struct {
  char uuid[64];
  char name[64];
  bool online;
  int depth, parent; /* parent: index into the same array, -1 = the root */
} tree_hub_t;

/* Is `uuid` this hub, or already placed in the tree? */
static bool tree_hub_placed(const hub_state_t *state, const tree_hub_t *th,
                            int nth, const char *uuid) {
  if (strcmp(uuid, state->hub_uuid) == 0) return true;
  for (int k = 0; k < nth; k++)
    if (strcmp(th[k].uuid, uuid) == 0) return true;
  return false;
}

/* Build the tree for the bots on THIS hub, in DFS pre-order.  Row shapes:
 *   H|<depth>|<name>|<uuid>|<online>|<uptime>|<version>|<variant>
 *   B|<depth>|<nick>|<uuid>|<version>|<server>|<uptime>|<variant>
 *   D|<nick>|<uuid>|<last_seen>            (offline; always the tail)
 * Depth plus pre-order is all a renderer needs to draw the connectors: a node
 * is the last child at its level when no later row shares its depth before a
 * shallower one appears.  The bot does the drawing (commands.c) so the glyphs
 * can change without a hub deploy.
 *
 * Rooted at this hub because that is the vantage point the asking bot has:
 * its own hub first, its peer hubs beneath it, and every hub further out
 * beneath the hub that links to it (from the relayed gossip).  The same
 * network legitimately renders differently depending on which bot you ask. */
static int hub_build_tree(hub_state_t *state, char *buf, int max_len) {
  int offset = 0, written;
  buf[0] = '\0';

  /* <variant> is the code base (c / rs); after it comes <started>, the
   * node's absolute start time (0 = unknown), from which the bot works out
   * the uptime itself.  A bot that predates a field splits a fixed field
   * count and never looks past it.  The old uptime field is always 0: a tree
   * that says the same thing is then the same bytes, and an unchanged tree is
   * not pushed again (hub_push_tree_to_bots). */
  written = snprintf(buf, max_len, "H|0|%s|%s|1|0|%s|%s|%lld\n",
                     state->hub_friendly_name[0] ? state->hub_friendly_name
                                                 : "hub",
                     state->hub_uuid[0] ? state->hub_uuid : "-",
                     HUB_VERSION, HUB_UPDATE_VARIANT,
                     (long long)state->hub_started);
  if (written < 0 || written >= max_len) return 0;
  offset += written;

  /* Our own bots, from the live client list — never from a peer's report. */
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type != CLIENT_BOT || !c->authenticated) continue;
    if (max_len - offset <= TREE_ROW_MAX) break;
    char nick[MAX_NICK];
    bot_nick_from_config(state, c->id, nick, sizeof(nick));
    written = snprintf(buf + offset, max_len - offset,
                       "B|1|%s|%s|%s|%s|0|%s|%lld\n",
                       nick[0] ? nick : "-", c->id,
                       c->bot_version[0] ? c->bot_version : "-",
                       c->bot_server[0] ? c->bot_server : "-",
                       c->bot_variant[0] ? c->bot_variant : "-",
                       (long long)c->bot_started);
    if (written < 0 || written >= max_len - offset) break;
    offset += written;
  }

  /* Every other hub, breadth-first from here: our configured peers at depth
   * 1 (linked or not — "configured, down" is worth showing), then whatever
   * each linked hub reports it is linked to, one level further out.  A hub is
   * placed once, at the first (so the shortest) path found; a hub only
   * reported through a DOWN link is hung, unlinked, under the first hub that
   * reports it once the live mesh has been walked.  Emitted depth-first
   * below, since pre-order plus depth is what the renderer reads. */
  tree_hub_t *th = calloc(TREE_HUBS, sizeof(*th));
  if (!th) return offset;
  int nth = 0;
  for (int p = 0; p < state->peer_count && nth < TREE_HUBS; p++) {
    hub_peer_config_t *peer = &state->peers[p];
    snprintf(th[nth].uuid, sizeof(th[nth].uuid), "%s",
             peer->uuid[0] ? peer->uuid : "-");
    roster_clean(th[nth].name, sizeof(th[nth].name),
                 peer->friendly_name[0] ? peer->friendly_name : peer->ip);
    th[nth].online = peer_is_linked(state, peer);
    th[nth].depth = 1;
    th[nth].parent = -1;
    nth++;
  }
  for (int pass = 0; pass < 2; pass++) {
    /* pass 0 walks live links only; pass 1 hangs what is left, unlinked. */
    for (int i = 0; i < nth && nth < TREE_HUBS; i++) {
      if (!th[i].online || th[i].depth >= MAX_TREE_DEPTH) continue;
      const mesh_hub_t *mh = mesh_hub_find(state, th[i].uuid);
      if (!mh) continue;
      for (int l = 0; l < mh->link_count && nth < TREE_HUBS; l++) {
        const mesh_link_t *L = &mh->links[l];
        if (L->online != (pass == 0) ||
            tree_hub_placed(state, th, nth, L->uuid))
          continue;
        snprintf(th[nth].uuid, sizeof(th[nth].uuid), "%s", L->uuid);
        const mesh_hub_t *lh = mesh_hub_find(state, L->uuid);
        roster_clean(th[nth].name, sizeof(th[nth].name),
                     lh && lh->name[0] ? lh->name : L->name);
        th[nth].online = L->online;
        th[nth].depth = th[i].depth + 1;
        th[nth].parent = i;
        nth++;
      }
    }
  }

  /* Depth-first emission: a hub, its bots, then its child hubs. */
  int stack[TREE_HUBS], sp = 0;
  for (int i = nth - 1; i >= 0; i--)
    if (th[i].parent < 0) stack[sp++] = i;
  while (sp > 0) {
    int i = stack[--sp];
    if (max_len - offset <= TREE_ROW_MAX) break;
    const char *puuid = strcmp(th[i].uuid, "-") != 0 ? th[i].uuid : "";
    /* Uptime / version / code base: from our own peer record for a direct
     * peer, else from the hub's own (relayed) gossip. */
    time_t started = 0;
    const char *ver = "", *var = "";
    for (int p = 0; p < state->peer_count && puuid[0]; p++) {
      if (strcmp(state->peers[p].uuid, puuid) != 0) continue;
      started = state->peers[p].remote_started;
      ver = state->peers[p].remote_version;
      var = state->peers[p].remote_variant;
      break;
    }
    const mesh_hub_t *mh = puuid[0] ? mesh_hub_find(state, puuid) : NULL;
    if (mh) {
      if (!started) started = mh->started;
      if (!ver[0]) ver = mh->version;
      if (!var[0]) var = mh->variant;
    }
    written = snprintf(buf + offset, max_len - offset,
                       "H|%d|%s|%s|%d|0|%s|%s|%lld\n", th[i].depth,
                       th[i].name[0] ? th[i].name : "peer",
                       puuid[0] ? puuid : "-", th[i].online ? 1 : 0,
                       ver[0] ? ver : "-", var[0] ? var : "-",
                       (long long)started);
    if (written < 0 || written >= max_len - offset) break;
    offset += written;

    if (puuid[0]) {
      for (int r = 0; r < state->roster_count; r++) {
        bot_roster_t *e = &state->roster[r];
        if (strcmp(e->hub_uuid, puuid) != 0) continue;
        if (max_len - offset <= TREE_ROW_MAX) break;
        written = snprintf(buf + offset, max_len - offset,
                           "B|%d|%s|%s|%s|%s|0|%s|%lld\n", th[i].depth + 1,
                           e->nick[0] ? e->nick : "-", e->bot_uuid,
                           e->version[0] ? e->version : "-",
                           e->server[0] ? e->server : "-",
                           e->variant[0] ? e->variant : "-",
                           (long long)e->connected_at);
        if (written < 0 || written >= max_len - offset) break;
        offset += written;
      }
    }
    for (int k = nth - 1; k > i; k--)
      if (th[k].parent == i && sp < TREE_HUBS) stack[sp++] = k;
  }
  free(th);

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
 * burst of roster changes collapses to one send per drain cycle.  force=false
 * (a change) skips a bot that was already sent this exact tree; the
 * BOT_TREE_REFRESH push is forced, which is what keeps a bot's tree from
 * looking stale (BOT_TREE_STALE_AFTER) on a quiet mesh. */
static void hub_push_tree_to_bots(hub_state_t *state, bool force) {
  int bots = 0;
  for (int i = 0; i < state->client_count; i++)
    if (state->clients[i]->type == CLIENT_BOT && state->clients[i]->authenticated)
      bots++;
  if (bots == 0) return;

  char *payload = malloc(MAX_TREE_PAYLOAD);
  if (!payload) {
    hub_log_error("[PRESENCE] OOM building bot tree\n");
    return;
  }
  int len = hub_build_tree(state, payload, MAX_TREE_PAYLOAD);
  if (len <= 0) { free(payload); return; }

  unsigned char hash[32];
  unsigned int hlen = 0;
  bool hashed = EVP_Digest(payload, (size_t)len, hash, &hlen, EVP_sha256(),
                           NULL) == 1 && hlen == sizeof(hash);
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type != CLIENT_BOT || !c->authenticated) continue;
    if (!force && hashed && c->tree_sent_valid &&
        memcmp(hash, c->tree_sent_hash, sizeof(hash)) == 0)
      continue;
    queued_msg_t *m = queued_msg_new(CMD_BOT_TREE, LANE_BULK,
                                     (const unsigned char *)payload, len);
    if (!m) continue;
    c->tree_sent_valid = hashed;
    if (hashed) memcpy(c->tree_sent_hash, hash, sizeof(hash));
    char coalesce[160];
    snprintf(coalesce, sizeof(coalesce), "%s|bot_tree|%s", state->hub_uuid,
             c->id);
    queued_msg_set_coalesce(m, state->hub_uuid, hub_next_lamport_seq(state),
                            coalesce);
    if (!peer_enqueue(c, m)) c->tree_sent_valid = false;
  }
  free(payload);
}

void hub_presence_tick(hub_state_t *state, time_t now) {
  if (state->hub_started == 0) state->hub_started = now;

  hub_roster_expire(state, now);

  /* A peer link that came up or went down is news for everyone's tree and for
   * every forwarder's split horizon (hub_broadcast_sync_to_peers): gossip it
   * now rather than on the next interval. */
  uint32_t mask = 0;
  for (int p = 0; p < state->peer_count && p < 32; p++)
    if (peer_is_linked(state, &state->peers[p])) mask |= 1u << p;
  if (mask != state->gossip_link_mask) {
    /* A link went down: see SYNC_RESYNC_AFTER_LINK_LOSS. */
    if (state->gossip_link_mask & ~mask)
      state->resync_due_at = now + SYNC_RESYNC_AFTER_LINK_LOSS;
    state->gossip_link_mask = mask;
    state->last_presence_gossip = 0;
    state->tree_dirty = true;
  }
  if (state->resync_due_at && now >= state->resync_due_at) {
    state->resync_due_at = 0;
    hub_request_sync_from_peers(state);
  }

  if (now - state->last_presence_gossip >= BOT_PRESENCE_INTERVAL)
    hub_gossip_bot_roster(state);

  /* Push on change (only to bots whose tree it changes), with an
   * unconditional refresh so a bot that missed a frame — or connected between
   * changes — still converges.  Only the refresh restarts the refresh clock:
   * a change push may reach no bot at all.  Changes are coalesced (see
   * BOT_TREE_COALESCE): under churn every peer's gossip round re-rendered the
   * tree for every bot, O(hubs x bots) 10 KB frames a minute. */
  bool refresh = now - state->last_tree_push >= BOT_TREE_REFRESH;
  int gap = state->tree_dirty_local ? BOT_TREE_COALESCE_LOCAL : BOT_TREE_COALESCE;
  bool due = state->tree_dirty && now - state->last_tree_change_push >= gap;
  if (due || refresh) {
    state->tree_dirty = false;
    state->tree_dirty_local = false;
    state->last_tree_change_push = now;
    if (refresh) state->last_tree_push = now;
    hub_push_tree_to_bots(state, refresh);
  }
}

/* The opcode a config broadcast goes to peer `c` under: CMD_PEER_BCAST when
 * its gossip shows it knows the opcode (it sends l| lines), else the
 * CMD_PEER_SYNC every hub understands. */
static uint8_t sync_bcast_opcode(hub_state_t *state, const hub_client_t *c) {
  const char *cu = upgrade_peer_uuid(state, c);
  const mesh_hub_t *mh = cu[0] ? mesh_hub_find(state, cu) : NULL;
  return (mh && mh->have_links) ? CMD_PEER_BCAST : CMD_PEER_SYNC;
}

/* The mesh-map record of the peer on `from_fd`, if its link report is fresh
 * enough to trust for a split horizon (sent the moment a link changes,
 * refreshed every BOT_PRESENCE_INTERVAL), else NULL. */
static const mesh_hub_t *split_horizon_sender(hub_state_t *state, int from_fd) {
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type != CLIENT_HUB || !c->authenticated || c->fd != from_fd)
      continue;
    const char *su = upgrade_peer_uuid(state, c);
    const mesh_hub_t *mh = su[0] ? mesh_hub_find(state, su) : NULL;
    if (mh && mh->have_links &&
        time(NULL) - mh->reported_at <= SYNC_SPLIT_HORIZON_FRESH)
      return mh;
    return NULL;
  }
  return NULL;
}

/* True when `sender` is linked to peer `c` right now: it sent `c` its flood
 * directly, so we need not. */
static bool split_horizon_has(hub_state_t *state, const mesh_hub_t *sender,
                              const hub_client_t *c) {
  const char *cu = upgrade_peer_uuid(state, c);
  for (int l = 0; l < sender->link_count && cu[0]; l++)
    if (sender->links[l].online && strcmp(sender->links[l].uuid, cu) == 0)
      return true;
  return false;
}

/* One config payload to every authenticated peer except `exclude_fd`.
 * `split`: the payload is a forward of a CMD_PEER_BCAST the peer on
 * `exclude_fd` sent us, so the split horizon may apply (see CMD_PEER_BCAST).
 * `coalesce`/`seq`: queue coalescing for a single-key delta, or NULL. */
static void sync_send_to_peers(hub_state_t *state, const char *payload,
                               int exclude_fd, bool split, lane_t lane,
                               const char *coalesce, uint64_t seq) {
  int payload_len = (int)strlen(payload);
  /* Change 5: a full-state anti-entropy sync can exceed MAX_BUFFER; bound by
   * the sync-payload ceiling so it is never silently dropped here. */
  if (payload_len > (MAX_SYNC_PAYLOAD - 10))
    return;

  /* The sender's links, if we may trust them: its report is fresh (sent the
   * moment a link changes, refreshed every BOT_PRESENCE_INTERVAL).  A peer it
   * is linked to right now got this frame from it directly.  A copy lost to a
   * link that dropped in the moment before its gossip said so is what the
   * resync after a link loss (SYNC_RESYNC_AFTER_LINK_LOSS) and the periodic
   * anti-entropy exist to repair. */
  const mesh_hub_t *sender = split ? split_horizon_sender(state, exclude_fd)
                                   : NULL;

  int skipped = 0;
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type != CLIENT_HUB || !c->authenticated || c->fd == exclude_fd)
      continue;
    if (sender && split_horizon_has(state, sender, c)) {
      skipped++;
      continue;
    }
    queued_msg_t *m = queued_msg_new(sync_bcast_opcode(state, c), lane,
                                     (const unsigned char *)payload,
                                     payload_len);
    if (!m) continue;
    if (coalesce) queued_msg_set_coalesce(m, state->hub_uuid, seq, coalesce);
    if (!peer_enqueue(c, m)) {
      /* Only URGENT can fail here; PEER_SYNC is DELTA/BULK so this is
       * effectively unreachable, but be safe. */
      hub_log_warning("[MESH] enqueue failed for peer %s\n", c->ip);
    }
  }
  if (skipped)
    hub_log_debug("[MESH] Forward skipped %d peer(s) the sender reaches itself\n",
            skipped);
}

void hub_broadcast_sync_to_peers(hub_state_t *state, const char *payload,
                                 int exclude_fd) {
  /* Lane heuristic:
   *  - Single-line CMD_PEER_SYNC payloads originating from a delta forward
   *    (typical: one trailing newline) are short — < 1 KB — and time-
   *    sensitive; treat as DELTA so they're not throttled by the BULK budget.
   *  - Larger payloads (multi-line, e.g. anti-entropy full sync) ride BULK. */
  lane_t lane = (strlen(payload) > 1024) ? LANE_BULK : LANE_DELTA;
  sync_send_to_peers(state, payload, exclude_fd, false, lane, NULL, 0);
}

/* A forward of what we accepted from a peer's frame.  `bcast`: that frame
 * was a CMD_PEER_BCAST, so the split horizon applies. */
static void sync_forward_to_peers(hub_state_t *state, const char *payload,
                                  int origin_fd, bool bcast) {
  lane_t lane = (strlen(payload) > 1024) ? LANE_BULK : LANE_DELTA;
  sync_send_to_peers(state, payload, origin_fd, bcast, lane, NULL, 0);
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
    hub_log_debug("[MESH] Sent sync request to %d peer(s)\n", sent);
}

/* Owe every local bot a full config push.  It used to be sent right here, once
 * per accepted update: a burst of N updates (fifty bots reconnecting send two
 * each, and each one reaches every hub) became N full pushes to every bot,
 * O(updates x bots) of 8 KB frames, while each push only ever carries the
 * current state anyway.  hub_flush_bot_config sends one, at most once per
 * BOT_CONFIG_PUSH_COALESCE, with whatever the state is by then. */
static void broadcast_full_config_to_all_bots(hub_state_t *state) {
  state->bot_config_pending = true;
}

void hub_flush_bot_config(hub_state_t *state, time_t now) {
  if (!state->bot_config_pending ||
      now - state->last_bot_config_push < BOT_CONFIG_PUSH_COALESCE)
    return;
  state->bot_config_pending = false;
  state->last_bot_config_push = now;
  int sent_count = 0;
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type == CLIENT_BOT && c->authenticated) {
      send_config_to_bot(state, c, false);
      sent_count++;
    }
  }
  hub_log_debug("[HUB] Broadcasted FULL config to %d bots\n", sent_count);
}

static void process_bot_config_push(hub_state_t *state, hub_client_t *client,
                                    char *payload) {
  if (client->type != CLIENT_BOT || !client->authenticated) {
    hub_log_warning("[HUB] Rejected config push from non-bot client\n");
    return;
  }

  hub_log_debug("[HUB] Processing config push from %s\n", client->id);
  /* The bot's tables may now differ from what it was last sent (a push the
   * hub does not accept stays in them), so its next broadcast goes out. */
  client->cfg_sent_valid = false;

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

  /* Task 6 — opt 'F' (OPT_CONFIG_FROZEN): an upgrade run is open, so the
   * store holds still entirely.  Dropping the whole push (rather than
   * filtering it) is deliberate: a bot that restarts mid-roll re-pushes its
   * config on reconnect, and nothing here is lost that the bot will not
   * offer again once the freeze lifts. */
  if (hub_config_frozen(state)) {
    hub_log_warning("[UPGRADE] config frozen: REJECTED config push from %s\n",
            client->id);
    return;
  }

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
        hub_log_info("[HUB] Bot %s speaks protocol v%ld (passwordless)\n",
                client->id, v);
      }
      line = strtok_r(NULL, "\n", &saveptr);
      continue;
    }
    if (type == 'p') {
      hub_log_warning("[HUB] Ignored retired bot-password line from %s "
              "(pre-passwordless bot)\n", client->id);
      line = strtok_r(NULL, "\n", &saveptr);
      continue;
    }

    /* Reject hub-authoritative record types from bots while opt 'h' is active. */
    if (hub_only_mutations &&
        (type == 'a' || type == 'o' || type == 'm' || type == 'c')) {
      hub_log_warning("[HUB] opt 'h' active: REJECTED bot-pushed '%c' record from %s "
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
        hub_log_debug("[HUB] Channel %s: ts=%lld op=%s modes=%d -> %s\n",
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
          } else if (found_m) {
            /* Activity repair, outside LWW: not an update. */
            activity_raise(state, &found_m->last_used, (time_t)last_used);
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
        } else if (found_u) {
          activity_raise(state, &found_u->last_seen, in.last_seen);
        }
      }
    } else if (type == 'h') {
      // Hostmask: h|nick!user@host|timestamp
      char hostmask[256];
      long long ts;
      if (sscanf(data, "%255[^|]|%lld", hostmask, &ts) == 2) {
        bool accepted = hub_storage_update_entry(state, client->id, "h", hostmask, "", "", ts);
        hub_log_debug("[HUB] Hostmask %s: ts=%lld -> %s\n", hostmask, ts, accepted ? "ACCEPTED" : "REJECTED");
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
        hub_log_debug("[HUB] Nick %s: ts=%lld -> %s\n", nick, ts, accepted ? "ACCEPTED" : "REJECTED");
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
    hub_log_warning("[HUB] Bot %s is a pre-passwordless build (no v|2): it gets "
            "legacy records with empty password slots; upgrade it\n",
            client->id);
  }

  if (updates > 0) {
    hub_log_debug("[HUB] Applied %d updates from %s\n", updates, client->id);

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
    send_config_to_bot(state, client, true);
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
                              int origin_fd, bool bcast) {
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
  g_hub_stats.sync_frames++;

  while (line) {
    g_hub_stats.sync_records++;
    // Check for PURGE command
    if (strncmp(line, "PURGE|", 6) == 0) {
      time_t cutoff;
      char purge_id[PURGE_ID_HEX + 1];
      if (!parse_purge_line(line, &cutoff, purge_id)) {
        hub_log_warning("[MESH] Dropped malformed PURGE line from peer\n");
      } else {
        hub_log_info("[MESH] Received PURGE from peer: cutoff=%ld id=%s\n",
                (long)cutoff, purge_id[0] ? purge_id : "-");

        // DEDUPLICATION: Check if this PURGE was recently seen
        if (is_purge_recent(state, cutoff, purge_id)) {
          hub_log_debug("[MESH] PURGE cutoff=%ld id=%s already processed recently, skipping to prevent loop\n",
                  (long)cutoff, purge_id[0] ? purge_id : "-");
        } else {
          // Record this PURGE and process it
          record_recent_purge(state, cutoff, purge_id);

          char purge_log[MAX_BUFFER];
          int purged = hub_execute_purge(state, cutoff,
                                         purge_log, sizeof(purge_log));
          if (purged > 0) {
            hub_log_info("[MESH] Purged %d entries from peer sync\n", purged);
            updates += purged;
          }

          // Forward to all other peers (exclude sender to prevent immediate
          // echo; combined with deduplication prevents feedback loops).
          if (origin_fd != -1) {
            sync_forward_to_peers(state, line, origin_fd, bcast);
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
        hub_log_info("[MESH] Forwarded INVITE_REQUEST: invite %s into %s\n",
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
                          hub_log_info("[MESH] Dedup: '%s' (%c) UUID collision resolved, adopting %s\n",
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
                  } else if (!discard_incoming && found_u) {
                    /* Activity repair, outside LWW: not an update. */
                    activity_raise(state, &found_u->last_seen, (time_t)last_seen);
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
                  } else if (found_m) {
                    activity_raise(state, &found_m->last_used, (time_t)last_used);
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

  if (updates > 0)
    g_hub_stats.sync_applied += (uint64_t)updates;
  else
    g_hub_stats.sync_noop++;

  if (updates > 0) {
    state->config_dirty = true;
    hub_log_debug("[MESH] Synced %d entries from Peer (%d bot-relevant).\n",
            updates, bot_push_updates);

    if (fwd_offset > 0)
      sync_forward_to_peers(state, forward_buf, origin_fd, bcast);

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

/* A change the bots must see.  The line is for the log only: what reaches the
 * bots is the full config, owed through broadcast_full_config_to_all_bots and
 * coalesced by hub_flush_bot_config like every other push. */
static void hub_broadcast_config_to_bots(hub_state_t *state,
                                          const char *config_line) {
  hub_log_debug("[HUB] Broadcasting config update to all bots: %s", config_line);
  broadcast_full_config_to_all_bots(state);
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
    hub_log_error("[PURGE] malloc failed for new_bots\n");
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
      hub_log_error("[PURGE] OOM queueing PURGE for bot %s\n", c->id);
      continue;
    }
    if (!peer_enqueue(c, m))
      hub_log_warning("[PURGE] could not queue PURGE for bot %s\n", c->id);
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
  hub_log_info("[ACCESS_CONTROL] %s %s %s by %s\n", e.pattern,
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

  /* Task 6: an upgrade run holds the config still.  One gate here covers
   * every mutator rather than a check inside each; queries and the opt-flag
   * command itself stay available (the latter is how a stuck freeze is
   * lifted by hand). */
  if (hub_config_frozen(state) && hub_admin_cmd_mutates_config(cmd)) {
    hub_log_warning("[UPGRADE] Refused admin command 0x%02x: config frozen\n", cmd);
    return send_response(state, client,
                         "ERROR: config frozen (upgrade in progress)");
  }

  switch (cmd) {

  case CMD_ADMIN_UPGRADE_NET: {
    /* Payload: target_ver|variant|kind|min_from|base|hub_ver|hub_base —
     * everything past the version is optional ("" = let each node decide).
     * target_ver/base are the bots' (ircbot-releases); hub_ver/hub_base are
     * the hubs' own (irchub-releases), and an empty hub_ver leaves every hub
     * where it is.  A base never contains '|' (hub_upgrade_start refuses
     * one), so only the last field is a tail. */
    char ver[64] = "", variant[8] = "", kind[8] = "", min_from[64] = "";
    char base[512] = "", hub_ver[64] = "", hub_base[512] = "";
    if (payload) {
      wire_field(payload, 0, ver, sizeof(ver));
      wire_field(payload, 1, variant, sizeof(variant));
      wire_field(payload, 2, kind, sizeof(kind));
      wire_field(payload, 3, min_from, sizeof(min_from));
      wire_field(payload, 4, base, sizeof(base));
      wire_field(payload, 5, hub_ver, sizeof(hub_ver));
      wire_tail(payload, 6, hub_base, sizeof(hub_base));
    }
    char msg[320];
    hub_upgrade_start(state, client, ver, variant, kind, min_from, base,
                      hub_ver, hub_base, msg, sizeof(msg));
    return send_response(state, client, msg);
  }

  case CMD_ADMIN_UPGRADE_STATUS: {
    /* A payload of "abort" stops a run in flight and rolls the mesh back. */
    if (payload && strcasecmp(payload, "abort") == 0) {
      if (!state->upgrade.active)
        return send_response(state, client, "ERROR: no upgrade is running");
      hub_upgrade_abort(state, "aborted by admin");
      return send_response(state, client, "OK:upgrade aborted; rolling back");
    }
    /* "forget" drops the roll-up plan a finished run left behind, here and
     * (flooded) on every other hub. */
    if (payload && strcasecmp(payload, "forget") == 0) {
      if (state->upgrade.active || hub_config_frozen(state))
        return send_response(state, client,
                             "ERROR: an upgrade is running — the plan is kept "
                             "until it ends (abort it first)");
      char had[64] = "";
      if (state->rollup.have_plan)
        snprintf(had, sizeof(had), "%s", state->rollup.target);
      hub_rollup_forget(state, "forgotten by admin");
      char id[64], fwd[96];
      generate_request_id(id, sizeof(id));
      op_forward_seen_check_and_add(state, id);
      snprintf(fwd, sizeof(fwd), "%s|%lld", id, (long long)time(NULL));
      int told = 0;
      for (int i = 0; i < state->client_count; i++) {
        hub_client_t *c = state->clients[i];
        if (c->type == CLIENT_HUB && c->authenticated &&
            peer_send_urgent(state, c, CMD_UPGRADE_FORGET, fwd))
          told++;
      }
      snprintf(response, sizeof(response),
               "OK:%s%s%s; told %d peer hub(s) to drop theirs",
               had[0] ? "roll-up plan " : "no roll-up plan on this hub",
               had, had[0] ? " forgotten on this hub" : "", told);
      return send_response(state, client, response);
    }
    hub_upgrade_status(state, response, sizeof(response));
    return send_response(state, client, response);
  }
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
          hub_log_warning("[ADMIN] Disconnecting bot %s\n", payload);
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
          hub_log_warning("[ADMIN] Disconnecting deleted bot %s\n", payload);
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

      /* Still not found: the live presence roster (CMD_BOT_ROSTER) knows
       * every bot a peer hub has right now, TTL'd, whatever the legacy
       * gossip above carries. */
      if (!is_connected) {
        const bot_roster_t *best = NULL;
        for (int r = 0; r < state->roster_count; r++)
          if (strcmp(state->roster[r].bot_uuid, b->uuid) == 0 &&
              (!best || state->roster[r].reported_at >= best->reported_at))
            best = &state->roster[r];
        if (best) {
          is_connected = true;
          snprintf(connected_to, sizeof(connected_to), "PEER (%.100s)",
                   best->hub_name);
          for (int p = 0; p < state->peer_count; p++)
            if (state->peers[p].uuid[0] &&
                strcmp(state->peers[p].uuid, best->hub_uuid) == 0) {
              snprintf(connected_to, sizeof(connected_to), "PEER (%.64s:%d)",
                       state->peers[p].ip, state->peers[p].port);
              break;
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

      /* Version and code base, e.g. "2.4.0 (rs)", from the volatile presence
       * data — known only while the bot is on the mesh. */
      char ver[ROSTER_VERSION_MAX + ROSTER_VARIANT_MAX + 4] = "-";
      if (is_connected) bot_version_label(state, b->uuid, ver, sizeof(ver));

      // Build output line
      written =
          snprintf(response + offset, LIST_FULL_SZ - offset,
                   "[%s] %-15s | Status: %-10s | Peer: %-20s | Version: %-12s | Key: %s | Last: %s\n",
                   b->uuid, nick, is_connected ? "CONNECTED" : "OFFLINE",
                   is_connected ? connected_to : "N/A", ver, bfp, time_buf);

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
        /* A duplicate is named as such even on a full table: "max peers"
         * would send the admin looking for a slot the add never needed. */
        if (uuid[0]) {
          for (int i = 0; i < state->peer_count; i++) {
            if (state->peers[i].uuid[0] &&
                strcmp(state->peers[i].uuid, uuid) == 0) {
              return send_response(state, client,
                                   "ERROR: Peer with this UUID already exists.");
            }
          }
        }
        if (state->peer_count < MAX_PEERS) {
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
      hub_log_info("[HUB] Peer %s pubkey set — next connection will use v2 Ed25519 auth.\n", uuid);
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

    // Add 25 for the IP:Port column (21 chars + " | " = 24); 7 for Code
    int line_len = peer_col_width + 3 + 24 + (count * 5) + 15 + 10 + 7;

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
                       " Mesh State    | Bots | Code |\n");
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

      /* Code base (c / rs): ours is compiled in; a peer's comes from the v|
       * line of its roster gossip, so only hubs we peer with directly (and
       * that send one) are known — anything else shows "?". */
      const char *code = "?";
      if (all_peers[row].is_me) {
        code = HUB_UPDATE_VARIANT;
      } else {
        for (int p = 0; p < state->peer_count; p++) {
          bool peer_matches;
          if (all_peers[row].uuid[0] && state->peers[p].uuid[0])
            peer_matches = strcmp(state->peers[p].uuid, all_peers[row].uuid) == 0;
          else
            peer_matches = state->peers[p].port == all_peers[row].port &&
                           strcmp(state->peers[p].ip, all_peers[row].ip) == 0;
          if (peer_matches) {
            if (state->peers[p].remote_variant[0])
              code = state->peers[p].remote_variant;
            break;
          }
        }
      }

      if (is_offline) {
        // CRITICAL FIX: Add overflow check
        written = snprintf(response_ptr + offset, 65536 - offset,
                           " ??   | %-4s |\n", code);
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
                           " %-4d | %-4s |\n", bot_cnt, code);
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
        forward_op_request_to_peers(state, request_id, "ADMIN", "ANY", admin_payload, "", -1, admin_origin_ts, false);

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
            state->config_dirty = true;   /* log_level| survives a restart */
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
            if (size < HUB_LOG_SIZE_MIN) size = HUB_LOG_SIZE_MIN;
            if (size > HUB_LOG_SIZE_MAX) size = HUB_LOG_SIZE_MAX;
            state->log_max_size = (int)size;
            state->config_dirty = true;   /* log_size| survives a restart */
            char msg[64];
            snprintf(msg, sizeof(msg), "OK:log_size set to %d", state->log_max_size);
            send_response(state, client, msg);
            break;
        }

  case CMD_ADMIN_STATS: {
    /* Read-only snapshot of g_hub_stats; see CMD_ADMIN_STATS in hub.h. */
    const hub_stats_t *st = &g_hub_stats;
    size_t cap = MAX_BUFFER - 64, off = 0;
    char *out = malloc(cap);
    if (!out) return send_response(state, client, "ERROR: out of memory");
    int w = snprintf(out, cap,
                     "stats|up=%lld\n"
                     "cfg|sent=%llu|same=%llu|lost=%llu\n"
                     "sync|frames=%llu|noop=%llu|records=%llu|applied=%llu\n",
                     (long long)(state->hub_started > 0
                                     ? time(NULL) - state->hub_started : 0),
                     (unsigned long long)st->cfg_sent,
                     (unsigned long long)st->cfg_same,
                     (unsigned long long)st->cfg_lost,
                     (unsigned long long)st->sync_frames,
                     (unsigned long long)st->sync_noop,
                     (unsigned long long)st->sync_records,
                     (unsigned long long)st->sync_applied);
    off = (w > 0 && (size_t)w < cap) ? (size_t)w : 0;
    for (int op = 0; op < 256 && off < cap; op++) {
      if (!st->rx_frames[op] && !st->tx_frames[op]) continue;
      w = snprintf(out + off, cap - off, "op|0x%02X|rx=%llu/%llu|tx=%llu/%llu\n",
                   op, (unsigned long long)st->rx_frames[op],
                   (unsigned long long)st->rx_bytes[op],
                   (unsigned long long)st->tx_frames[op],
                   (unsigned long long)st->tx_bytes[op]);
      if (w <= 0 || (size_t)w >= cap - off) break;
      off += (size_t)w;
    }
    if (off > 0 && out[off - 1] == '\n') out[--off] = '\0';
    bool ok = send_response(state, client, out);
    free(out);
    return ok;
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
    hub_log_info("[ADMIN] %s %s removed with %d usermask(s)\n",
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
                                         time_t origin_ts, bool split) {
  /* Payload format (7 fields):
   *   request_id|requester_uuid|target_uuid|channel|requester_hostmask|origin_ts|how
   * `how` is newest: "F" = flooded to every peer the sender is linked to (a
   * receiver may apply the split horizon), "D" = sent to one peer only.  Old
   * hubs read a fixed field count and ignore it; a frame without it is
   * treated as "D" (no split horizon) — the old behaviour. */
  hub_client_t *route = strcmp(target_uuid, "ANY") != 0
                            ? op_route_peer(state, target_uuid, exclude_fd)
                            : NULL;
  char forward_payload[680];
  snprintf(forward_payload, sizeof(forward_payload), "%s|%s|%s|%s|%s|%ld|%s",
           request_id, requester_uuid, target_uuid, channel,
           requester_hostmask ? requester_hostmask : "",
           (long)(origin_ts > 0 ? origin_ts : time(NULL)), route ? "D" : "F");

  if (route) {
    /* Directed: the roster says which hub holds the target and it is one of
     * ours.  Flooding put ~hubs^2 copies on the mesh for one grant.  If the
     * roster was stale, that hub routes it on the same way (it excludes us),
     * so the request is still delivered, one hop later. */
    if (!peer_send_urgent(state, route, CMD_OP_FORWARD_REQUEST, forward_payload)) {
      hub_log_warning("[HUB] URGENT queue full forwarding OP_REQUEST to peer fd=%d — disconnecting\n",
              route->fd);
      hub_disconnect_client(state, route);
      return;
    }
    hub_log_debug("[HUB] Routed OP_FORWARD_REQUEST (id:%s) to peer fd=%d, the hub of %s\n",
            request_id, route->fd, target_uuid);
    return;
  }

  /* Flood, with the split horizon when the sender flooded too: a peer the
   * sender is linked to got its copy straight from the sender. */
  const mesh_hub_t *sender = split ? split_horizon_sender(state, exclude_fd)
                                   : NULL;
  int queued_count = 0, skipped = 0;
  /* Route through URGENT lane — op grants must not be delayed by BULK sync. */
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type == CLIENT_HUB && c->authenticated && c->fd != exclude_fd) {
      if (sender && split_horizon_has(state, sender, c)) {
        skipped++;
        continue;
      }
      if (!peer_send_urgent(state, c, CMD_OP_FORWARD_REQUEST, forward_payload)) {
        hub_log_warning("[HUB] URGENT queue full forwarding OP_REQUEST to peer fd=%d — disconnecting\n",
                c->fd);
        hub_disconnect_client(state, c);
        i--;
        continue;
      }
      queued_count++;
      if (state->log_level >= LOG_DEBUG)
        hub_log_debug("[HUB] Queued OP_FORWARD_REQUEST (id:%s) URGENT to peer fd=%d\n",
              request_id, c->fd);
    }
  }
  if (queued_count > 0 || skipped > 0)
    hub_log_debug("[HUB] Forwarded OP_FORWARD_REQUEST (id:%s) to %d peer(s), %d skipped (split horizon)\n",
            request_id, queued_count, skipped);
}

// ========== End OP Request Forwarding Helper Functions ==========

// ========== Handlers for Forwarded OP Commands from Peer Hubs ==========

static void process_forward_op_request(hub_state_t *state,
                                        hub_client_t *client, char *payload) {
  /* Payload format (6 fields, 6th is new and optional for old senders):
   *   request_id|requester_uuid|target_uuid|channel|requester_hostmask|origin_ts|how */
  char request_id[64], requester_uuid[64], target_uuid[64], channel[MAX_CHAN];
  char carried_hostmask[MAX_MASK_LEN] = "";
  long long origin_ts = 0;

  int parsed = sscanf(payload,
                      "%63[^|]|%63[^|]|%63[^|]|%64[^|]|%255[^|]|%lld",
                      request_id, requester_uuid, target_uuid, channel,
                      carried_hostmask, &origin_ts);
  if (parsed < 4) {
    hub_log_warning("[HUB] Invalid OP_FORWARD_REQUEST payload from peer fd=%d\n",
            client->fd);
    return;
  }
  /* The trailing "F": the sender flooded it (see forward_op_request_to_peers).
   * Read from the end: an empty hostmask field stops the sscanf above early. */
  const char *how = strrchr(payload, '|');
  bool flooded = how && strcmp(how + 1, "F") == 0;

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
        hub_log_debug("[HUB] Dropping expired OP_FORWARD_REQUEST (id:%s, age=%lds > %ds TTL)\n",
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
      hub_log_debug("[HUB] Dropping duplicate OP_FORWARD_REQUEST (id:%s) -- already processed\n",
                  request_id);
    return;
  }

  hub_log_debug("[HUB] Received OP_FORWARD_REQUEST (id:%s) from peer fd=%d target=%s channel=%s\n",
          request_id, client->fd, target_uuid, channel);

  // Handle admin requests specially (target_uuid = "ANY", requester_uuid = "ADMIN")
  if (strcmp(target_uuid, "ANY") == 0 && strcmp(requester_uuid, "ADMIN") == 0) {
    // Admin op request - decode nick:channel format
    char nick[64], chan[MAX_CHAN];
    if (sscanf(channel, "%63[^:]:%64s", nick, chan) == 2) {
      hub_log_info("[HUB] Admin OP_REQUEST for %s in %s - broadcasting to local bots\n",
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
                                  channel, "", client->fd, (time_t)origin_ts,
                                  flooded);
      hub_log_info("[HUB] Admin OP_REQUEST delivered to %d local bot(s), forwarding to peers\n",
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
      hub_log_warning("[HUB] No hostmask for requester %s (not in payload or storage)\n",
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
        hub_log_debug("[HUB] Sent OP_GRANT to local bot %s for request id:%s\n",
                target_uuid, request_id);
        /* Forward grant confirmation back to origin peer via URGENT. */
        peer_send_urgent(state, client, CMD_OP_FORWARD_GRANT, request_id);
        hub_log_debug("[HUB] Queued OP_FORWARD_GRANT URGENT back to peer for id:%s\n",
                request_id);
      }
    }
  } else {
    // Target not found locally - forward to other peers (exclude origin)
    hub_log_debug("[HUB] Target bot %s not found locally, forwarding to %d peer(s)\n",
            target_uuid, state->client_count);
    forward_op_request_to_peers(state, request_id, requester_uuid, target_uuid,
                                 channel, carried_hostmask, client->fd, (time_t)origin_ts,
                                 flooded);
  }
}

static void process_forward_op_grant(hub_state_t *state, hub_client_t *client,
                                      char *payload) {
  (void)client; // Not used - response goes to original requester
  // Payload format: request_id
  char request_id[64];
  if (strlen(payload) >= sizeof(request_id)) {
    hub_log_warning("[HUB] OP_FORWARD_GRANT: oversized request_id, ignoring\n");
    return;
  }
  snprintf(request_id, sizeof(request_id), "%s", payload);

  hub_log_debug("[HUB] Received OP_FORWARD_GRANT from peer for request id:%s\n",
          request_id);

  // Find the pending request
  pending_op_request_t *req = find_pending_op_request(state, request_id);
  if (!req) {
    hub_log_warning("[HUB] No pending request found for id:%s\n", request_id);
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
    hub_log_debug("[HUB] OP_FORWARD_GRANT acknowledged for id:%s — requester learns via IRC MODE\n",
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
    hub_log_warning("[HUB] Invalid OP_FORWARD_FAILED payload from peer\n");
    return;
  }

  hub_log_debug("[HUB] Received OP_FORWARD_FAILED from peer for request id:%s\n",
          request_id);

  // Find the pending request
  pending_op_request_t *req = find_pending_op_request(state, request_id);
  if (!req) {
    hub_log_warning("[HUB] No pending request found for id:%s\n", request_id);
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
        hub_log_info("[HUB] Notified requester bot of failure for id:%s\n",
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
        hub_log_warning("[HUB] URGENT queue full forwarding CHAN_REQUEST to peer "
                "fd=%d — disconnecting\n", c->fd);
        hub_disconnect_client(state, c);
        i--;
        continue;
      }
      queued++;
    }
  }
  if (queued > 0)
    hub_log_debug("[HUB] Forwarded CHAN_FWD_REQUEST (id:%s %s %s) to %d peer(s)\n",
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
      hub_log_warning("[HUB] Failed to send CHAN_ACTION to bot %s\n", bc->id);
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
    hub_log_warning("[HUB] Pending channel-request table full — dropping %s for %s\n",
            kind, channel);
    return;
  }

  int told = broadcast_chan_action(state, request_id, requester_uuid, kind,
                                   channel, nick, hostmask);
  forward_chan_request_to_peers(state, request_id, requester_uuid, kind,
                                channel, nick, hostmask, origin_fd);
  hub_log_debug("[HUB] CHAN_REQUEST %s for %s (id:%s) delivered to %d local bot(s)\n",
          kind, channel, request_id, told);
}

static void process_chan_request(hub_state_t *state, hub_client_t *client,
                                 char *payload) {
  /* Payload from a bot is only `kind|channel`; everything that could be
   * forged is resolved here from the authenticated bot's own records. */
  char kind[8], channel[MAX_CHAN];
  if (sscanf(payload, "%7[^|]|%64s", kind, channel) != 2 ||
      !chan_kind_valid(kind)) {
    hub_log_warning("[HUB] Invalid CHAN_REQUEST payload from %s\n", client->id);
    return;
  }
  if (channel[0] != '#' && channel[0] != '&') {
    hub_log_warning("[HUB] CHAN_REQUEST from %s for non-channel '%s'\n", client->id,
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
    hub_log_warning("[HUB] No hostmask for %s — cannot service unban for %s\n",
            client->id, channel);
    return;
  }
  if (strcmp(kind, "invite") == 0 && nick[0] == '\0') {
    hub_log_warning("[HUB] No nick for %s — cannot service invite for %s\n",
            client->id, channel);
    return;
  }

  hub_log_info("[HUB] CHAN_REQUEST %s from %s for %s\n", kind, client->id, channel);

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
    hub_log_warning("[HUB] Invalid CHAN_REPLY payload from %s\n", client->id);
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
    hub_log_warning("[HUB] CHAN_REPLY (id:%s) from %s matches no pending request\n",
            request_id, client->id);
    return;
  }
  /* Bind the answer to what was actually asked: holding a request id must not
   * let a bot hand the requester a key for some other channel. */
  if (strcmp(req->kind, kind) != 0 || strcasecmp(req->channel, channel) != 0) {
    hub_log_warning("[HUB] CHAN_REPLY (id:%s) from %s answers %s/%s but the request "
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
      hub_log_info("[HUB] CHAN_REPLY %s for %s delivered to %s\n", kind, channel,
              req->requester_uuid);
    else
      hub_log_warning("[HUB] CHAN_REPLY %s for %s undeliverable to %s\n", kind, channel,
              req->requester_uuid);
  } else {
    for (int i = 0; i < state->client_count; i++) {
      hub_client_t *c = state->clients[i];
      if (c->type == CLIENT_HUB && c->authenticated &&
          c->fd == req->origin_fd) {
        if (!peer_send_urgent(state, c, CMD_CHAN_FWD_REPLY, out))
          hub_log_warning("[HUB] URGENT queue full routing CHAN_REPLY to peer fd=%d\n",
                  c->fd);
        else
          hub_log_debug("[HUB] CHAN_REPLY %s for %s sent back as CHAN_FWD_REPLY to "
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
    hub_log_warning("[HUB] Invalid CHAN_FWD_REQUEST from peer fd=%d\n", client->fd);
    return;
  }
  /* Second sighting of this id: another path already delivered it. */
  if (op_forward_seen_check_and_add(state, request_id))
    return;

  hub_log_debug("[HUB] CHAN_FWD_REQUEST %s for %s (id:%s) from peer fd=%d\n", kind,
          channel, request_id, client->fd);
  chan_request_dispatch(state, request_id, requester_uuid, kind, channel, nick,
                        hostmask, client->fd);
}

static void process_forward_chan_reply(hub_state_t *state, hub_client_t *client,
                                       char *payload) {
  char request_id[64];
  if (sscanf(payload, "%63[^|]", request_id) != 1) {
    hub_log_warning("[HUB] Invalid CHAN_FWD_REPLY from peer fd=%d\n", client->fd);
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
        hub_log_debug("[HUB] CHAN_FWD_REPLY (id:%s) from peer fd=%d delivered to %s\n",
                request_id, client->fd, req->requester_uuid);
        break;
      }
    }
  } else {
    for (int i = 0; i < state->client_count; i++) {
      hub_client_t *c = state->clients[i];
      if (c->type == CLIENT_HUB && c->authenticated && c->fd == req->origin_fd) {
        peer_send_urgent(state, c, CMD_CHAN_FWD_REPLY, payload);
        hub_log_debug("[HUB] CHAN_FWD_REPLY (id:%s) relayed on toward its origin "
                "(peer fd=%d)\n", request_id, c->fd);
        break;
      }
    }
  }
  req->active = false;
}

// ========== End Channel-Access Requests ==========

/* ======================================================================
 * Network upgrade orchestration (CMD_ADMIN_UPGRADE_NET → CMD_UPGRADE_*)
 *
 * hub_admin asks this hub to move the whole network to a version.  The hub
 * freezes the config, asks every node whether it could take that build
 * (PREPARE → READY/UNABLE), then commits them in a rolling plan: bots in
 * waves so a channel never loses all its bots at once, peer hubs afterwards
 * one at a time so the mesh never fully drops, and this hub last of all.
 *
 * The ack routing mirrors pending_op_request_t: one id per run, replies
 * matched by that id, status routed home down origin_fd.  Unlike an op grant
 * a committed node DISCONNECTS (it execs a new binary), so success is
 * normally observed as "it came back announcing the target version" — the
 * CMD_UPGRADE_RESULT frame is a faster confirmation, not the only one.
 * ====================================================================== */

/* Add or replace a flag in the replicated opt record, stamped and pushed the
 * same way CMD_ADMIN_SET_OPT_FLAGS does it. */
static void hub_opt_flag_set(hub_state_t *state, char flag, bool on) {
  char cur[MAX_OPT_FLAGS + 1];
  snprintf(cur, sizeof(cur), "%s", state->opt_flags);
  bool present = (strchr(cur, flag) != NULL);
  if (present == on) return;

  char next[MAX_OPT_FLAGS + 1] = {0};
  int w = 0;
  for (int i = 0; cur[i] && w < MAX_OPT_FLAGS; i++)
    if (cur[i] != flag) next[w++] = cur[i];
  if (on && w < MAX_OPT_FLAGS) next[w++] = flag;
  next[w] = '\0';

  snprintf(state->opt_flags, sizeof(state->opt_flags), "%s", next);
  /* Past the previous stamp: a set and a clear in the same second must not
   * tie, or peers keep whichever arrived and the mesh splits. */
  state->opt_flags_ts = hub_lww_next_ts(state->opt_flags_ts);
  state->config_dirty = true;

  char sync_pkt[64];
  snprintf(sync_pkt, sizeof(sync_pkt), "opt|%s|%ld\n", state->opt_flags,
           (long)state->opt_flags_ts);
  hub_broadcast_sync_to_peers(state, sync_pkt, -1);
  broadcast_full_config_to_all_bots(state);
  hub_log_info("[UPGRADE] opt flags now '%s'\n",
          state->opt_flags[0] ? state->opt_flags : "(none)");
}

/* Task 6: while a run holds the freeze, config mutations are refused.  The
 * flag replicates like any other opt, so peer hubs refuse them too. */
static bool hub_config_frozen(const hub_state_t *state) {
  return state && strchr(state->opt_flags, OPT_CONFIG_FROZEN) != NULL;
}

/* Admin commands that write the replicated store or change which nodes exist.
 * Read-only queries and the local operational settings stay available, and so
 * does CMD_ADMIN_SET_OPT_FLAGS deliberately: it is the manual escape hatch
 * that lifts a freeze a crashed run left behind. */
static bool hub_admin_cmd_mutates_config(int cmd) {
  switch (cmd) {
  case CMD_ADMIN_ADD:
  case CMD_ADMIN_DEL:
  case CMD_ADMIN_REGEN_KEYS:
  case CMD_ADMIN_APPROVE:
  case CMD_ADMIN_ADD_PEER:
  case CMD_ADMIN_DEL_PEER:
  case CMD_ADMIN_SET_PRIVKEY:
  case CMD_ADMIN_SET_PUBKEY:
  case CMD_ADMIN_REKEY_BOT:
  case CMD_ADMIN_CREATE_BOT:
  case CMD_ADMIN_ADD_CHANNEL:
  case CMD_ADMIN_DEL_CHANNEL:
  case CMD_ADMIN_ADD_MASK:
  case CMD_ADMIN_DEL_MASK:
  case CMD_ADMIN_ADD_OPER:
  case CMD_ADMIN_DEL_OPER:
  case CMD_ADMIN_PURGE_TOMBSTONES:
  case CMD_ADMIN_SET_PURGE_DAYS:
  case CMD_ADMIN_ADD_ADMIN:
  case CMD_ADMIN_DEL_ADMIN:
  case CMD_ADMIN_ADD_OPER_RECORD:
  case CMD_ADMIN_DEL_OPER_RECORD:
  case CMD_ADMIN_ADD_USERMASK:
  case CMD_ADMIN_DEL_USERMASK:
  case CMD_ADMIN_SET_PEER_PUBKEY:
  case CMD_ADMIN_SET_USERKEY:
    return true;
  default:
    return false;
  }
}

static const char *upgrade_node_state_name(upgrade_node_state_t s) {
  switch (s) {
  case UPG_NODE_PENDING:   return "pending";
  case UPG_NODE_READY:     return "ready";
  case UPG_NODE_UNABLE:    return "unable";
  case UPG_NODE_COMMITTED: return "committing";
  case UPG_NODE_DONE:      return "done";
  case UPG_NODE_FAILED:    return "failed";
  }
  return "?";
}

static const char *upgrade_phase_name(upgrade_phase_t p) {
  switch (p) {
  case UPG_IDLE:    return "idle";
  case UPG_PREPARE: return "preparing";
  case UPG_ROLLING: return "rolling";
  case UPG_DONE:    return "done";
  case UPG_FAILED:  return "failed";
  case UPG_ABORTED: return "aborted";
  }
  return "?";
}

static upgrade_node_t *upgrade_find_node(pending_upgrade_t *u,
                                         const char *uuid) {
  if (!uuid || !uuid[0]) return NULL;
  for (int i = 0; i < u->node_count; i++)
    if (strcmp(u->nodes[i].uuid, uuid) == 0) return &u->nodes[i];
  return NULL;
}

static upgrade_node_t *upgrade_add_node(pending_upgrade_t *u, const char *uuid,
                                        char kind, int fd, const char *ver) {
  if (u->node_count >= MAX_UPGRADE_NODES) return NULL;
  if (!uuid || !uuid[0]) return NULL; /* the table is keyed by uuid */
  upgrade_node_t *n = &u->nodes[u->node_count++];
  memset(n, 0, sizeof(*n));
  snprintf(n->uuid, sizeof(n->uuid), "%s", uuid);
  n->kind = kind;
  n->fd = fd;
  n->state = UPG_NODE_PENDING;
  if (ver) snprintf(n->cur_version, sizeof(n->cur_version), "%s", ver);
  u->last_added = time(NULL);
  return n;
}

/* Relayed-bot READYs still owed: what the hub nodes said they relayed to,
 * less the remote bots already in the table.  Bounded by the PREPARE timeout
 * like every other wait. */
static int upgrade_relays_owed(const pending_upgrade_t *u) {
  int promised = 0, seen = 0;
  for (int i = 0; i < u->node_count; i++) {
    const upgrade_node_t *n = &u->nodes[i];
    if (n->kind == 'h') promised += n->relayed;
    else if (n->kind == 'b' && n->via[0]) seen++;
  }
  return promised > seen ? promised - seen : 0;
}

static int upgrade_count(const pending_upgrade_t *u, upgrade_node_state_t st,
                         char kind) {
  int n = 0;
  for (int i = 0; i < u->node_count; i++)
    if (u->nodes[i].state == st && (kind == 0 || u->nodes[i].kind == kind)) n++;
  return n;
}

/* The uuid a peer hub knows ITSELF by.  A peer connection's client->id is the
 * peer's FRIENDLY NAME — that is what the roster, the logs and hub_admin show
 * — while every upgrade frame a peer sends is keyed by its hub uuid.  The two
 * have to be bridged, or the driver never matches a peer's own UPGRADE_READY
 * to the node it created for it and files the answer as a brand-new bot.
 * Returns "" when the connection is not a known peer. */
static const char *upgrade_peer_uuid(const hub_state_t *state,
                                     const hub_client_t *c) {
  if (!c || c->type != CLIENT_HUB) return "";
  for (int i = 0; i < state->peer_count; i++)
    if (state->peers[i].connected && state->peers[i].fd == c->fd)
      return state->peers[i].uuid;
  return "";
}

/* The peer connection belonging to a hub uuid (the inverse of the above). */
static hub_client_t *upgrade_find_peer(hub_state_t *state, const char *uuid) {
  if (!uuid || !uuid[0]) return NULL;
  for (int i = 0; i < state->peer_count; i++) {
    if (!state->peers[i].connected) continue;
    if (strcmp(state->peers[i].uuid, uuid) != 0) continue;
    for (int j = 0; j < state->client_count; j++) {
      hub_client_t *c = state->clients[j];
      if (c->type == CLIENT_HUB && c->authenticated &&
          c->fd == state->peers[i].fd)
        return c;
    }
  }
  return NULL;
}

static hub_client_t *upgrade_find_client(hub_state_t *state, const char *uuid,
                                         client_type_t type) {
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type == type && c->authenticated && strcmp(c->id, uuid) == 0)
      return c;
  }
  return NULL;
}

/* Strip '|' and control bytes: reasons come back from nodes and travel on
 * through a '|'-delimited status frame into an admin's terminal. */
static void upgrade_clean(char *dst, size_t cap, const char *src) {
  size_t o = 0;
  for (const char *p = src ? src : ""; *p && o + 1 < cap; p++) {
    unsigned char c = (unsigned char)*p;
    if (c == '|') c = '/';
    if (c < 0x20 || c == 0x7f) c = ' ';
    dst[o++] = (char)c;
  }
  dst[o] = '\0';
}

/* End the run: lift the freeze and record why it stopped.  The table stays
 * behind so CMD_ADMIN_UPGRADE_STATUS can still explain what happened. */
static void upgrade_finish(hub_state_t *state, upgrade_phase_t phase,
                           const char *summary) {
  pending_upgrade_t *u = &state->upgrade;
  /* Keep the plan of a run that actually got somewhere: a node that was down
   * or homed elsewhere while it went through is walked up to this target when
   * it comes back (see hub_rollup_*).  An aborted run left the mesh where it
   * was, so there is nothing to catch up to. */
  if (phase == UPG_DONE) {
    pending_rollup_t *r = &state->rollup;
    r->have_plan = true;
    snprintf(r->target, sizeof(r->target), "%s", u->target_ver);
    snprintf(r->variant, sizeof(r->variant), "%s", u->variant);
    snprintf(r->kind, sizeof(r->kind), "%s", u->kind);
    snprintf(r->min_from, sizeof(r->min_from), "%s", u->min_from);
    snprintf(r->base, sizeof(r->base), "%s", u->base);
    snprintf(r->hub_target, sizeof(r->hub_target), "%s", u->hub_ver);
    snprintf(r->hub_base, sizeof(r->hub_base), "%s", u->hub_base);
    r->plan_set = time(NULL);
    state->rollup_try_count = 0;
    hub_config_write(state); /* the plan survives a restart (Task 13) */
  } else if (phase == UPG_ABORTED) {
    state->rollup.have_plan = false;
    hub_config_write(state);
  }
  u->active = false;
  u->phase = phase;
  upgrade_clean(u->summary, sizeof(u->summary), summary);
  hub_opt_flag_set(state, OPT_CONFIG_FROZEN, false);
  hub_log_info("[UPGRADE] Run %s %s: %s\n", u->id, upgrade_phase_name(phase),
          u->summary);
}

/* Tell every node that already moved (or is moving) to go back, then end the
 * run.  Rolling the finished nodes back too is the point: a half-upgraded
 * mesh is worse than one that never started. */
static void hub_upgrade_abort(hub_state_t *state, const char *reason) {
  pending_upgrade_t *u = &state->upgrade;
  char msg[256];
  snprintf(msg, sizeof(msg), "%s|", u->id);
  upgrade_clean(msg + strlen(msg), sizeof(msg) - strlen(msg), reason);

  int told = 0;
  for (int i = 0; i < u->node_count; i++) {
    upgrade_node_t *n = &u->nodes[i];
    if (n->state != UPG_NODE_COMMITTED && n->state != UPG_NODE_DONE) continue;
    if (n->via[0]) {
      /* A node below a peer hub: send that peer an id|uuid|reason frame.  Each
       * hop relays it on, and the last one turns it into the plain id|reason
       * ABORT its local bot understands. */
      hub_client_t *peer = upgrade_find_peer(state, n->via);
      char relay[320];
      snprintf(relay, sizeof(relay), "%s|%s|", u->id, n->uuid);
      upgrade_clean(relay + strlen(relay), sizeof(relay) - strlen(relay), reason);
      if (peer && peer_send_urgent(state, peer, CMD_UPGRADE_ABORT, relay)) told++;
    } else if (n->kind == 'b') {
      hub_client_t *c = upgrade_find_client(state, n->uuid, CLIENT_BOT);
      if (c && send_cmd_to_bot(c, CMD_UPGRADE_ABORT, msg)) told++;
    } else if (n->kind == 'h') {
      /* Peer hub as a self-node: id||reason (empty uuid = "you, not a bot"). */
      hub_client_t *c = upgrade_find_peer(state, n->uuid);
      char relay[320];
      snprintf(relay, sizeof(relay), "%s||", u->id);
      upgrade_clean(relay + strlen(relay), sizeof(relay) - strlen(relay), reason);
      if (c && peer_send_urgent(state, c, CMD_UPGRADE_ABORT, relay)) told++;
    }
  }
  hub_log_info("[UPGRADE] Abort %s sent to %d node(s): %s\n", u->id, told, reason);
  upgrade_finish(state, UPG_ABORTED, reason);
}

/* The version a node of this run is being moved to: the bots' target for a
 * bot, the hubs' own for a hub.  Never mixed — the two are separate products
 * on separate version lines. */
static const char *upgrade_node_target(const pending_upgrade_t *u,
                                       const upgrade_node_t *n) {
  return n->kind == 'b' ? u->target_ver : u->hub_ver;
}

/* Send one node its CMD_UPGRADE_COMMIT.  A node that dropped off in the
 * meantime is marked unable rather than failing the run — Task 7 rolls it up
 * when it reconnects. */
static bool upgrade_commit_node(hub_state_t *state, upgrade_node_t *n) {
  pending_upgrade_t *u = &state->upgrade;
  const char *ver = upgrade_node_target(u, n);
  char payload[192];
  snprintf(payload, sizeof(payload), "%s|%s|%s", u->id, ver, u->variant);

  if (n->kind == 's') {
    /* This hub is the last node of its own run, so there is no frame and no
     * ack: hub_update_commit() either does not return (the process is
     * replaced and the marker file carries the run into it) or it fails here
     * with nothing touched.  Either way the run is over — a successful
     * restart lands in UPG_ABORTED/DONE nowhere, because the table is
     * volatile; the freeze is lifted BEFORE the exec so the network is not
     * left frozen by a hub that never comes back. */
    n->state = UPG_NODE_COMMITTED;
    n->committed_at = time(NULL);
    hub_log_info("[UPGRADE] COMMIT %s -> this hub (%s)\n", u->id, ver);
    char done_msg[192];
    snprintf(done_msg, sizeof(done_msg),
             "%d node(s) on %s; this hub is restarting onto it last",
             upgrade_count(u, UPG_NODE_DONE, 0), u->target_ver);
    upgrade_finish(state, UPG_DONE, done_msg);

    const char *err = NULL;
    if (!hub_update_commit(state, u->id, ver, u->variant, u->hub_base,
                           &err)) {
      /* The other nodes are already on the target and the freeze is lifted;
       * only this hub stayed behind.  Say so in the summary rather than
       * leaving the run reading "done" with no explanation. */
      n->state = UPG_NODE_FAILED;
      snprintf(n->reason, sizeof(n->reason), "%s", err ? err : "failed");
      char why[192];
      snprintf(why, sizeof(why),
               "%d node(s) upgraded, but this hub stayed on %s: %s",
               upgrade_count(u, UPG_NODE_DONE, 0), HUB_VERSION,
               err ? err : "unknown error");
      upgrade_clean(u->summary, sizeof(u->summary), why);
      u->phase = UPG_FAILED;
      hub_log_warning("[UPGRADE] This hub could not take %s: %s\n", ver,
              err ? err : "unknown error");
      return false;
    }
    return true; /* unreachable: hub_update_commit() exec'd */
  }

  bool sent = false;
  if (n->via[0]) {
    /* A node somewhere below a peer hub — a bot homed on it, or a hub further
     * out in the mesh.  Route COMMIT through that peer, naming the node in a
     * 4th field; each hop either recognises the uuid (itself or one of its
     * own bots) or forwards the frame on along the route it learned at
     * PREPARE time. */
    hub_client_t *peer = upgrade_find_peer(state, n->via);
    char relay[256];
    snprintf(relay, sizeof(relay), "%s|%s", payload, n->uuid);
    sent = peer && peer_send_urgent(state, peer, CMD_UPGRADE_COMMIT, relay);
  } else if (n->kind == 'b') {
    hub_client_t *c = upgrade_find_client(state, n->uuid, CLIENT_BOT);
    sent = c && send_cmd_to_bot(c, CMD_UPGRADE_COMMIT, payload);
  } else if (n->kind == 'h') {
    hub_client_t *c = upgrade_find_peer(state, n->uuid);
    sent = c && peer_send_urgent(state, c, CMD_UPGRADE_COMMIT, payload);
  }
  if (!sent) {
    n->state = UPG_NODE_UNABLE;
    snprintf(n->reason, sizeof(n->reason), "disconnected before commit");
    return false;
  }
  n->state = UPG_NODE_COMMITTED;
  n->committed_at = time(NULL);
  hub_log_info("[UPGRADE] COMMIT %s -> %s (%s)\n", u->id, n->uuid, ver);
  return true;
}

/* hub_admin asked for a network upgrade.  Freeze the config, enumerate the
 * nodes and fan PREPARE out; the rolling plan itself runs on the maintenance
 * tick.  Returns false with `msg` filled in when the run could not start. */
static bool hub_upgrade_start(hub_state_t *state, hub_client_t *admin,
                              const char *target_ver, const char *variant,
                              const char *kind, const char *min_from,
                              const char *base, const char *hub_ver,
                              const char *hub_base, char *msg,
                              size_t msg_size) {
  pending_upgrade_t *u = &state->upgrade;
  if (u->active) {
    snprintf(msg, msg_size, "ERROR: upgrade %s already running (%s)", u->id,
             upgrade_phase_name(u->phase));
    return false;
  }
  if (!target_ver || !target_ver[0] || strlen(target_ver) >= 64) {
    snprintf(msg, msg_size, "ERROR: bad target version");
    return false;
  }
  /* The base travels to every node and ends up in a shell-free download path
   * there, but reject the obvious shapes here rather than at each node. */
  if (base && base[0] &&
      (strlen(base) >= sizeof(u->base) || strpbrk(base, ";|&`$ \t\r\n"))) {
    snprintf(msg, msg_size, "ERROR: bad manifest base");
    return false;
  }
  if (hub_ver && (strlen(hub_ver) >= sizeof(u->hub_ver) ||
                  strpbrk(hub_ver, "|;&`$ \t\r\n"))) {
    snprintf(msg, msg_size, "ERROR: bad hub target version");
    return false;
  }
  if (hub_base && hub_base[0] &&
      (!hub_ver || !hub_ver[0] || strlen(hub_base) >= sizeof(u->hub_base) ||
       strpbrk(hub_base, ";|&`$ \t\r\n"))) {
    snprintf(msg, msg_size, "ERROR: bad hub manifest base");
    return false;
  }

  memset(u, 0, sizeof(*u));
  generate_request_id(u->id, sizeof(u->id));
  /* Seed the PREPARE seen-ring: our own PREPARE coming back to us around a
   * cycle of peers is then dropped silently instead of being answered. */
  op_forward_seen_check_and_add(state, u->id);
  snprintf(u->target_ver, sizeof(u->target_ver), "%s", target_ver);
  snprintf(u->variant, sizeof(u->variant), "%s", variant ? variant : "");
  snprintf(u->kind, sizeof(u->kind), "%s", kind ? kind : "");
  snprintf(u->min_from, sizeof(u->min_from), "%s",
           (min_from && min_from[0]) ? min_from : "*");
  snprintf(u->base, sizeof(u->base), "%s", base ? base : "");
  snprintf(u->hub_ver, sizeof(u->hub_ver), "%s", hub_ver ? hub_ver : "");
  snprintf(u->hub_base, sizeof(u->hub_base), "%s", hub_base ? hub_base : "");
  u->origin_fd = admin ? admin->fd : -1;
  u->started = u->phase_started = time(NULL);
  u->phase = UPG_PREPARE;
  u->active = true;

  /* Freeze first: a config change that lands between PREPARE and the last
   * COMMIT would reach half the mesh on one build and half on another. */
  hub_opt_flag_set(state, OPT_CONFIG_FROZEN, true);

  /* Two shapes of the same PREPARE.  A bot gets the six fields it has always
   * read; a peer hub also needs the hubs' own target and base, appended so
   * the bot prefix stays byte-identical and a follower can relay it on. */
  char prepare[1024], prepare_peer[1600];
  snprintf(prepare, sizeof(prepare), "%s|%s|%s|%s|%s|%s", u->id, u->target_ver,
           u->variant, u->kind, u->min_from, u->base);
  snprintf(prepare_peer, sizeof(prepare_peer), "%s|%s|%s", prepare, u->hub_ver,
           u->hub_base);

  int bots = 0, peers = 0;
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (!c->authenticated) continue;
    if (c->type == CLIENT_BOT) {
      upgrade_node_t *n =
          upgrade_add_node(u, c->id, 'b', c->fd, c->bot_version);
      if (!n) break;
      if (send_cmd_to_bot(c, CMD_UPGRADE_PREPARE, prepare)) {
        bots++;
      } else {
        n->state = UPG_NODE_UNABLE;
        snprintf(n->reason, sizeof(n->reason), "could not deliver PREPARE");
      }
    } else if (c->type == CLIENT_HUB) {
      /* No version to seed: a peer's version lives on hub_peer_config_t, not
       * on the connection.  Its READY ack carries the authoritative one. */
      /* Keyed by the peer's OWN hub uuid: that is what its UPGRADE_READY and
       * UPGRADE_RESULT carry.  c->id (the friendly name) is kept for display
       * only — see upgrade_peer_uuid(). */
      const char *puuid = upgrade_peer_uuid(state, c);
      if (!puuid[0]) {
        hub_log_warning("[UPGRADE] Peer %s has no uuid yet — left out of run %s\n",
                c->id, u->id);
        continue;
      }
      upgrade_node_t *n = upgrade_add_node(u, puuid, 'h', c->fd, NULL);
      if (!n) break;
      snprintf(n->name, sizeof(n->name), "%s", c->id);
      if (peer_send_urgent(state, c, CMD_UPGRADE_PREPARE, prepare_peer)) {
        peers++;
      } else {
        n->state = UPG_NODE_UNABLE;
        snprintf(n->reason, sizeof(n->reason), "could not deliver PREPARE");
      }
    }
  }
  /* This hub goes last, and answers its own PREPARE without a round trip. */
  upgrade_node_t *self =
      upgrade_add_node(u, state->hub_uuid, 's', -1, HUB_VERSION);
  if (self) {
    char why[192] = "";
    bool can = u->hub_ver[0]
                   ? hub_update_can_take(u->hub_ver, u->min_from, u->hub_base,
                                         why, sizeof(why))
                   : (snprintf(why, sizeof(why), "no hub target in this run"),
                      false);
    self->state = can ? UPG_NODE_READY : UPG_NODE_UNABLE;
    /* Explicit precision: a long reason is truncated on purpose. */
    snprintf(self->reason, sizeof(self->reason), "%.*s",
             (int)sizeof(self->reason) - 1, why);
    snprintf(self->variant, sizeof(self->variant), "%s",
             hub_update_host_variant());
    hub_update_host_arch(self->arch, sizeof(self->arch));
    hub_update_host_libc(self->libc, sizeof(self->libc));
  }

  hub_log_info("[UPGRADE] Run %s -> %s: PREPARE to %d bot(s) and %d peer hub(s); "
          "this hub is %s\n", u->id, u->target_ver, bots, peers,
          self ? upgrade_node_state_name(self->state) : "not in the run");
  snprintf(msg, msg_size,
           "OK:upgrade %s started for %s — %d bot(s) and %d peer hub(s) asked "
           "to prepare, this hub last; config frozen until it finishes", u->id,
           u->target_ver, bots, peers);
  return true;
}

/* CMD_UPGRADE_READY: id|uuid|cur_ver|variant|arch|libc|ready|reason */
static void hub_upgrade_note_ready(hub_state_t *state, const char *payload,
                                   hub_client_t *from_peer) {
  pending_upgrade_t *u = &state->upgrade;
  char id[64] = "", uuid[64] = "", cur[64] = "", variant[8] = "";
  /* Sized above what a node can send (upgrade_clean caps a reason at 192), so
   * an honest long reason is truncated into node->reason rather than rejected
   * as a malformed field. */
  char arch[32] = "", libc[16] = "", okbuf[8] = "", reason[200] = "";
  if (!wire_field(payload, 0, id, sizeof(id)) ||
      !wire_field(payload, 1, uuid, sizeof(uuid)) ||
      !wire_field(payload, 2, cur, sizeof(cur)) ||
      !wire_field(payload, 3, variant, sizeof(variant)) ||
      !wire_field(payload, 4, arch, sizeof(arch)) ||
      !wire_field(payload, 5, libc, sizeof(libc)) ||
      !wire_field(payload, 6, okbuf, sizeof(okbuf)) ||
      !id[0] || !uuid[0] || !okbuf[0]) {
    hub_log_warning("[UPGRADE] Malformed UPGRADE_READY\n");
    return;
  }
  wire_field(payload, 7, reason, sizeof(reason));
  char kindbuf[8] = "", relbuf[8] = "";
  wire_field(payload, 8, kindbuf, sizeof(kindbuf));
  wire_field(payload, 9, relbuf, sizeof(relbuf));
  if (hub_rollup_note_ready(state, payload)) return;
  if (!u->active || strcmp(u->id, id) != 0) {
    hub_log_debug("[UPGRADE] READY for unknown run %s from %s — ignoring\n", id, uuid);
    return;
  }
  upgrade_node_t *node = upgrade_find_node(u, uuid);
  if (!node) {
    /* A READY the origin has not seen this uuid for, forwarded up a peer
     * link, is a bot homed on that peer: the peer PREPARE'd it for us.  Add
     * it as a remote node reached through the peer so the rolling plan drives
     * it and CMD_ADMIN_UPGRADE_STATUS accounts for it network-wide. */
    if (from_peer) {
      char nkind = (kindbuf[0] == 'h') ? 'h' : 'b';
      node = upgrade_add_node(u, uuid, nkind, -1, cur);
      if (!node) {
        hub_log_warning("[UPGRADE] No room for remote node %s in run %s\n", uuid, id);
        return;
      }
      snprintf(node->via, sizeof(node->via), "%.63s",
               upgrade_peer_uuid(state, from_peer));
    } else {
      hub_log_warning("[UPGRADE] READY from %s which is not in run %s\n", uuid, id);
      return;
    }
  } else if (from_peer && !node->via[0] && node->kind != 's') {
    /* Learned locally first, then forwarded: remember the route. */
    snprintf(node->via, sizeof(node->via), "%s",
             upgrade_peer_uuid(state, from_peer));
  }
  /* Explicit precision: a version longer than the roster field is truncated
   * on purpose, exactly as roster_clean does it for the tree. */
  snprintf(node->cur_version, sizeof(node->cur_version), "%.*s",
           (int)sizeof(node->cur_version) - 1, cur);
  snprintf(node->variant, sizeof(node->variant), "%s", variant);
  snprintf(node->arch, sizeof(node->arch), "%s", arch);
  snprintf(node->libc, sizeof(node->libc), "%s", libc);
  upgrade_clean(node->reason, sizeof(node->reason), reason);
  node->state = (okbuf[0] == '1') ? UPG_NODE_READY : UPG_NODE_UNABLE;
  if (node->ready_seq == 0) node->ready_seq = ++u->ready_seq_next;
  if (node->kind == 'h' && relbuf[0]) {
    long rel = strtol(relbuf, NULL, 10);
    node->relayed = (rel > 0 && rel <= MAX_UPGRADE_NODES) ? (int)rel : 0;
  }
  hub_log_debug("[UPGRADE] %s is %s (%s %s/%s)%s%s\n", uuid,
          upgrade_node_state_name(node->state), cur, arch, libc,
          node->reason[0] ? ": " : "", node->reason);
}

/* CMD_UPGRADE_RESULT: id|uuid|status|version|detail */
static void hub_upgrade_note_result(hub_state_t *state, const char *payload) {
  pending_upgrade_t *u = &state->upgrade;
  char id[64] = "", uuid[64] = "", status[32] = "", ver[64] = "";
  char detail[128] = "";
  if (!wire_field(payload, 0, id, sizeof(id)) ||
      !wire_field(payload, 1, uuid, sizeof(uuid)) ||
      !wire_field(payload, 2, status, sizeof(status)) ||
      !wire_field(payload, 3, ver, sizeof(ver)) ||
      !id[0] || !uuid[0] || !status[0]) {
    hub_log_warning("[UPGRADE] Malformed UPGRADE_RESULT\n");
    return;
  }
  wire_tail(payload, 4, detail, sizeof(detail));
  if (hub_rollup_note_result(state, payload)) return;
  if (strcmp(u->id, id) != 0) return;
  upgrade_node_t *node = upgrade_find_node(u, uuid);
  if (!node) return;

  snprintf(node->cur_version, sizeof(node->cur_version), "%.*s",
           (int)sizeof(node->cur_version) - 1, ver);
  upgrade_clean(node->reason, sizeof(node->reason), detail);
  if (strcmp(status, "ok") == 0) {
    node->state = UPG_NODE_DONE;
  } else if (strcmp(status, "aborted") == 0) {
    /* Answer to our own ABORT; the run is already over. */
    node->state = UPG_NODE_FAILED;
  } else {
    node->state = UPG_NODE_FAILED;
    if (!node->reason[0])
      snprintf(node->reason, sizeof(node->reason), "%s", status);
  }
  hub_log_debug("[UPGRADE] %s reports %s (%s)%s%s\n", uuid, status, ver,
          node->reason[0] ? ": " : "", node->reason);
}

/* A bot that just announced its version may be a committed node coming back
 * on the new build — that, not the RESULT frame, is the authoritative signal
 * (the RESULT can be lost, the presence cannot: without it the bot is not on
 * the mesh at all). */
static void hub_upgrade_note_presence(hub_state_t *state, const char *uuid,
                                      const char *version) {
  pending_upgrade_t *u = &state->upgrade;
  if (!u->active || u->phase != UPG_ROLLING) return;
  upgrade_node_t *node = upgrade_find_node(u, uuid);
  if (!node || node->state != UPG_NODE_COMMITTED) return;
  snprintf(node->cur_version, sizeof(node->cur_version), "%.*s",
           (int)sizeof(node->cur_version) - 1, version ? version : "");
  if (version && strcmp(version, upgrade_node_target(u, node)) == 0) {
    node->state = UPG_NODE_DONE;
    hub_log_info("[UPGRADE] %s is back on %s\n", uuid, version);
  }
}

bool hub_upgrade_plan_field_ok(const char *s) {
  return s && strlen(s) < 512 && !strpbrk(s, "|;&`$ \t\r\n");
}

/* A roll-up only chases a target the mesh is demonstrably running: some bot
 * other than the one being considered announces it — locally, or through the
 * presence gossip.  A follower learns the plan at PREPARE, before it can know
 * how the run ends, and only committed nodes are told of an abort; without
 * this gate an aborted run's target (a bad artifact, say) would be chased by
 * every follower the moment the freeze lifted, and — now that the plan is
 * persisted — again after every restart.  An aborted run leaves no bot on its
 * target (they roll back, or never installed it), so nothing is chased. */
static bool hub_rollup_target_proven(const hub_state_t *state,
                                     const char *target, const char *except) {
  for (int i = 0; i < state->client_count; i++) {
    const hub_client_t *c = state->clients[i];
    if (c->type == CLIENT_BOT && c->authenticated &&
        strcmp(c->id, except) != 0 && strcmp(c->bot_version, target) == 0)
      return true;
  }
  for (int i = 0; i < state->roster_count; i++) {
    const bot_roster_t *e = &state->roster[i];
    if (strcmp(e->bot_uuid, except) != 0 && strcmp(e->version, target) == 0)
      return true;
  }
  return false;
}

/* ---- Offline roll-up ---------------------------------------------------
 * A node that was down, or homed on a hub the run never reached, comes back
 * on the old build.  Rather than making an admin notice and re-run the whole
 * thing, the hub walks that ONE node up to the last completed run's target on
 * its own: a single-node PREPARE/COMMIT, no config freeze (a late bot is not
 * a reason to hold the whole network's config still) and a hard retry bound,
 * or a node that cannot take the build is re-committed on every reconnect.
 * When the node sits below the target's min_from_version the walk is taken
 * one release at a time, reading the steps out of the manifest. */

static rollup_try_t *rollup_try_for(hub_state_t *state, const char *uuid,
                                    bool create) {
  for (int i = 0; i < state->rollup_try_count; i++)
    if (strcmp(state->rollup_tries[i].uuid, uuid) == 0)
      return &state->rollup_tries[i];
  if (!create) return NULL;
  if (state->rollup_try_count >= MAX_ROLLUP_TRIES) {
    /* The ledger is a bound, not a record: drop the oldest attempt so a
     * long-lived hub keeps rolling recent arrivals up. */
    memmove(&state->rollup_tries[0], &state->rollup_tries[1],
            sizeof(state->rollup_tries[0]) * (size_t)(MAX_ROLLUP_TRIES - 1));
    state->rollup_try_count = MAX_ROLLUP_TRIES - 1;
  }
  rollup_try_t *t = &state->rollup_tries[state->rollup_try_count++];
  memset(t, 0, sizeof(*t));
  snprintf(t->uuid, sizeof(t->uuid), "%s", uuid);
  return t;
}

/* End the attempt in flight and charge it to the node's ledger. */
static void hub_rollup_end(hub_state_t *state, const char *why, bool charge) {
  pending_rollup_t *r = &state->rollup;
  if (!r->active) return;
  if (charge) {
    rollup_try_t *t = rollup_try_for(state, r->uuid, true);
    if (t) {
      t->tries++;
      t->last_try = time(NULL);
    }
  }
  hub_log_info("[ROLLUP] %s -> %s: %s\n", r->uuid, r->step, why);
  r->active = false;
  r->committed = false;
  r->id[0] = r->uuid[0] = r->step[0] = '\0';
}

/* Drop the roll-up plan (and any attempt in flight) from memory and from
 * .irchub.cnf.  Returns true when there was a plan to drop. */
static bool hub_rollup_forget(hub_state_t *state, const char *why) {
  pending_rollup_t *r = &state->rollup;
  hub_rollup_end(state, why, false);
  bool had = r->have_plan;
  if (had)
    hub_log_info("[ROLLUP] Plan %s (hubs %s) dropped: %s\n", r->target,
            r->hub_target[0] ? r->hub_target : "-", why);
  memset(r, 0, sizeof(*r));
  state->rollup_try_count = 0;
  if (had) hub_config_write(state);
  return had;
}

/* CMD_UPGRADE_FORGET from a peer: drop our plan and pass it on. */
static void process_peer_upgrade_forget(hub_state_t *state, hub_client_t *peer,
                                        const char *payload) {
  char id[64] = "", ts[24] = "";
  if (!wire_field(payload, 0, id, sizeof(id)) ||
      !wire_field(payload, 1, ts, sizeof(ts)) || !id[0] ||
      !hub_upgrade_plan_field_ok(id)) {
    hub_log_warning("[ROLLUP] Malformed UPGRADE_FORGET from peer %s\n", peer->ip);
    return;
  }
  long long age = (long long)time(NULL) - atoll(ts);
  if (atoll(ts) <= 0 || age > UPGRADE_FORGET_TTL || age < -UPGRADE_FORGET_TTL)
    return;
  if (op_forward_seen_check_and_add(state, id)) return;
  /* A plan is never dropped under a run: the freeze is replicated, so every
   * hub sees the same answer the admin's own hub gave. */
  if (!state->upgrade.active && !hub_config_frozen(state))
    hub_rollup_forget(state, "forgotten by an admin on another hub");
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type == CLIENT_HUB && c->authenticated && c != peer)
      peer_send_urgent(state, c, CMD_UPGRADE_FORGET, payload);
  }
}

/* Is this uuid a node worth catching up, and may we try it now? */
static bool hub_rollup_may_try(hub_state_t *state, const char *uuid,
                               const char *version) {
  pending_rollup_t *r = &state->rollup;
  if (!r->have_plan || r->active) return false;
  if (state->upgrade.active) return false; /* a real run owns the mesh */
  /* The freeze is the mesh-wide "a run is in flight" signal: it is set at
   * PREPARE, replicated with the rest of the opt record, and lifted when the
   * run ends.  A follower learns a run finished from it — nothing else tells
   * it — and neither end may chase a straggler while it holds. */
  if (hub_config_frozen(state)) return false;
  if (!uuid || !uuid[0] || !version || !version[0]) return false;
  if (hub_update_version_cmp(version, r->target) >= 0) return false;
  if (!hub_rollup_target_proven(state, r->target, uuid)) return false;
  time_t now = time(NULL);
  if (now - r->plan_set < ROLLUP_SETTLE) return false;
  const rollup_try_t *t = rollup_try_for(state, uuid, false);
  if (!t) return true;
  if (t->tries >= ROLLUP_MAX_TRIES) return false;
  return now - t->last_try >= ROLLUP_COOLDOWN;
}

/* A node announced a version older than the last completed run's target.
 * Start a single-node PREPARE for the next step it can take. */
static void hub_rollup_consider(hub_state_t *state, const char *uuid,
                                char node_kind, const char *version) {
  pending_rollup_t *r = &state->rollup;
  if (!hub_rollup_may_try(state, uuid, version)) return;

  /* Stepping: when the node is below the target's min_from it cannot jump
   * straight there, so ask the manifest for the highest release it may take
   * from where it is.  A manifest this hub cannot read (no curl, no key, no
   * network) is not fatal — aim straight at the target and let the node's own
   * updater refuse if it must. */
  char step[64], why[192] = "";
  if (!hub_update_next_step(r->base, r->variant, version, r->target, step,
                            sizeof(step), why, sizeof(why))) {
    snprintf(step, sizeof(step), "%s", r->target);
    if (why[0])
      hub_log_info("[ROLLUP] No step read for %s (%s); aiming at %s\n", uuid, why,
              r->target);
  }

  r->active = true;
  r->committed = false;
  r->node_kind = node_kind;
  generate_request_id(r->id, sizeof(r->id));
  snprintf(r->uuid, sizeof(r->uuid), "%s", uuid);
  snprintf(r->step, sizeof(r->step), "%s", step);
  r->started = time(NULL);

  /* min_from is "*": the step was already chosen against the manifest, and a
   * second check at the node would only re-answer the same question. */
  char prepare[1024];
  snprintf(prepare, sizeof(prepare), "%s|%s|%s|%s|*|%s", r->id, r->step,
           r->variant, r->kind, r->base);

  /* Local bots only (see the peer-gossip presence hook): a roll-up PREPARE
   * sent to a peer hub would be taken for a run's and fanned mesh-wide. */
  hub_client_t *c =
      node_kind == 'b' ? upgrade_find_client(state, uuid, CLIENT_BOT) : NULL;
  bool sent = c && send_cmd_to_bot(c, CMD_UPGRADE_PREPARE, prepare);
  if (!sent) {
    hub_rollup_end(state, "could not deliver PREPARE", true);
    return;
  }
  hub_log_info("[ROLLUP] %s is on %s, the network is on %s: PREPARE %s -> %s\n",
          uuid, version, r->target, r->id, r->step);
}

/* CMD_UPGRADE_READY carrying a roll-up id.  Returns true when it was one. */
static bool hub_rollup_note_ready(hub_state_t *state, const char *payload) {
  pending_rollup_t *r = &state->rollup;
  char id[64] = "", uuid[64] = "", okbuf[8] = "", reason[200] = "";
  wire_field(payload, 0, id, sizeof(id));
  if (!r->active || !id[0] || strcmp(r->id, id) != 0) return false;
  wire_field(payload, 1, uuid, sizeof(uuid));
  wire_field(payload, 6, okbuf, sizeof(okbuf));
  wire_field(payload, 7, reason, sizeof(reason));
  if (strcmp(uuid, r->uuid) != 0) return true; /* not the node we asked */

  if (okbuf[0] != '1') {
    hub_rollup_end(state, reason[0] ? reason : "node cannot take it", true);
    return true;
  }
  char commit[192];
  snprintf(commit, sizeof(commit), "%s|%s|%s", r->id, r->step, r->variant);
  hub_client_t *c = upgrade_find_client(state, r->uuid, CLIENT_BOT);
  bool sent = c && send_cmd_to_bot(c, CMD_UPGRADE_COMMIT, commit);
  if (!sent) {
    hub_rollup_end(state, "disconnected before commit", true);
    return true;
  }
  r->committed = true;
  r->started = time(NULL);
  hub_log_info("[ROLLUP] COMMIT %s -> %s (%s)\n", r->id, r->uuid, r->step);
  return true;
}

/* CMD_UPGRADE_RESULT carrying a roll-up id.  Returns true when it was one. */
static bool hub_rollup_note_result(hub_state_t *state, const char *payload) {
  pending_rollup_t *r = &state->rollup;
  char id[64] = "", status[32] = "", detail[128] = "";
  wire_field(payload, 0, id, sizeof(id));
  if (!r->active || !id[0] || strcmp(r->id, id) != 0) return false;
  wire_field(payload, 2, status, sizeof(status));
  wire_field(payload, 4, detail, sizeof(detail));
  if (strcmp(status, "ok") == 0)
    hub_rollup_end(state, "node reports it installed the step", false);
  else
    hub_rollup_end(state, detail[0] ? detail : status, true);
  return true;
}

/* A node's presence is the authoritative signal here too: it came back on the
 * step, so this attempt succeeded and the NEXT one (if the target is further
 * on) may start on the following tick. */
static void hub_rollup_note_presence(hub_state_t *state, const char *uuid,
                                     char node_kind, const char *version) {
  pending_rollup_t *r = &state->rollup;
  if (r->active && strcmp(r->uuid, uuid) == 0 && version &&
      hub_update_version_cmp(version, r->step) >= 0) {
    hub_rollup_end(state, "back on the step it was given", false);
    /* A walk of several releases keeps going from the new version. */
    hub_rollup_consider(state, uuid, node_kind, version);
    return;
  }
  hub_rollup_consider(state, uuid, node_kind, version);
}

/* Time out an attempt that went nowhere.  Runs on the maintenance clock. */
static void hub_rollup_tick(hub_state_t *state, time_t now) {
  pending_rollup_t *r = &state->rollup;
  if (!r->active) return;
  if (now - r->started <= ROLLUP_TIMEOUT) return;
  hub_rollup_end(state, r->committed ? "did not come back on the step in time"
                                     : "no answer to PREPARE", true);
}

/* The rolling plan, one step per maintenance tick. */
void hub_upgrade_tick(hub_state_t *state, time_t now) {
  hub_rollup_tick(state, now);
  pending_upgrade_t *u = &state->upgrade;
  if (!u->active) return;

  if (u->phase == UPG_PREPARE) {
    bool timed_out = (now - u->phase_started > UPGRADE_PREPARE_TIMEOUT);
    if (!timed_out &&
        (upgrade_count(u, UPG_NODE_PENDING, 0) > 0 || upgrade_relays_owed(u) > 0 ||
         now - u->last_added < UPGRADE_PREPARE_SETTLE))
      return;
    for (int i = 0; i < u->node_count; i++) {
      if (u->nodes[i].state != UPG_NODE_PENDING) continue;
      u->nodes[i].state = UPG_NODE_UNABLE;
      snprintf(u->nodes[i].reason, sizeof(u->nodes[i].reason),
               "no answer to PREPARE");
    }
    int ready = upgrade_count(u, UPG_NODE_READY, 0);
    if (ready == 0) {
      upgrade_finish(state, UPG_DONE, "no node needed the upgrade");
      return;
    }
    u->phase = UPG_ROLLING;
    u->phase_started = now;
    hub_log_info("[UPGRADE] Run %s rolling: %d node(s) ready\n", u->id, ready);
    return;
  }

  if (u->phase != UPG_ROLLING) return;

  /* A committed node that never came back fails the whole run: the rest of
   * the mesh must not keep marching onto a build that does not come up. */
  for (int i = 0; i < u->node_count; i++) {
    upgrade_node_t *n = &u->nodes[i];
    if (n->state != UPG_NODE_COMMITTED) continue;
    if (now - n->committed_at <= UPGRADE_COMMIT_TIMEOUT) continue;
    n->state = UPG_NODE_FAILED;
    snprintf(n->reason, sizeof(n->reason), "did not return on %s in time",
             upgrade_node_target(u, n));
    char why[192];
    snprintf(why, sizeof(why), "%s did not come back on %s", n->uuid,
             upgrade_node_target(u, n));
    hub_upgrade_abort(state, why);
    return;
  }
  if (upgrade_count(u, UPG_NODE_FAILED, 0) > 0) {
    hub_upgrade_abort(state, "a node reported the upgrade failed");
    return;
  }

  int in_flight = upgrade_count(u, UPG_NODE_COMMITTED, 0);
  int ready_bots = upgrade_count(u, UPG_NODE_READY, 'b');

  if (ready_bots > 0) {
    /* Wave size: never more than a quarter of the bots this run touches, and
     * never more than UPGRADE_BOT_WAVE_MAX, so the channels a botnet holds
     * keep a quorum of bots up throughout. */
    int touched = ready_bots + upgrade_count(u, UPG_NODE_COMMITTED, 'b') +
                  upgrade_count(u, UPG_NODE_DONE, 'b');
    int wave = touched / UPGRADE_BOT_WAVE_DIVISOR;
    if (wave < 1) wave = 1;
    if (wave > UPGRADE_BOT_WAVE_MAX) wave = UPGRADE_BOT_WAVE_MAX;
    for (int i = 0; i < u->node_count && in_flight < wave; i++) {
      upgrade_node_t *n = &u->nodes[i];
      if (n->state != UPG_NODE_READY || n->kind != 'b') continue;
      if (upgrade_commit_node(state, n)) in_flight++;
    }
    return;
  }

  /* Bots are settled.  Peer hubs go one at a time, and only once nothing is
   * mid-restart, so the mesh never drops below one reachable hub.
   *
   * Deepest first: a follower's run state (follow_id, its COMMIT routes) is
   * volatile, so a hub that restarts can no longer carry a COMMIT to the hubs
   * it routes for.  The latest READY is always from a hub no other pending
   * hub routes through (see upgrade_node_t.ready_seq).  This hub goes after
   * every peer hub: it restarts last and its run table goes with it. */
  if (in_flight > 0) return;
  upgrade_node_t *next = NULL;
  for (int i = 0; i < u->node_count; i++) {
    upgrade_node_t *n = &u->nodes[i];
    if (n->state == UPG_NODE_READY && n->kind == 'h' &&
        (!next || n->ready_seq > next->ready_seq))
      next = n;
  }
  for (int i = 0; i < u->node_count && !next; i++) {
    upgrade_node_t *n = &u->nodes[i];
    if (n->state == UPG_NODE_READY && n->kind == 's') next = n;
  }
  if (next) {
    upgrade_commit_node(state, next);
    return;
  }

  char done_msg[192];
  snprintf(done_msg, sizeof(done_msg),
           "%d node(s) now on %s, %d could not take it",
           upgrade_count(u, UPG_NODE_DONE, 0), u->target_ver,
           upgrade_count(u, UPG_NODE_UNABLE, 0));
  upgrade_finish(state, UPG_DONE, done_msg);
}

/* ---- Follower side: this hub as a node of another hub's run -------------
 * Symmetrical to the bot handlers in ircbot/hub_client.c, and reachable only
 * on an authenticated peer link.  A hub is a follower and a driver at the
 * same time — the mesh is flat — so the two halves are kept apart: `upgrade`
 * holds the run THIS hub drives, while the fields below are about a run
 * someone else drives. */

/* ---- Follower routing table (upgrade_route_t) --------------------------
 * A run reaches every hub in the mesh, whatever topology it is wired in: a
 * follower re-broadcasts PREPARE to its own peers and forwards their answers
 * back toward the driver.  For that to work in reverse, each hop remembers
 * which peer it heard a given node from; COMMIT and ABORT then walk the same
 * tree back down.  Suppression is by run id: a hub joins a run exactly once,
 * through the first peer that told it about the run, so a cycle in the peer
 * graph cannot make the fan-out loop. */

static void upgrade_routes_clear(hub_state_t *state) {
  memset(state->follow_routes, 0, sizeof(state->follow_routes));
  state->follow_route_count = 0;
}

/* Remember (or refresh) "frames for <uuid> go out through <via>". */
static void upgrade_route_note(hub_state_t *state, const char *uuid,
                               const char *via) {
  if (!uuid || !uuid[0] || !via || !via[0]) return;
  for (int i = 0; i < state->follow_route_count; i++) {
    if (strcmp(state->follow_routes[i].uuid, uuid) != 0) continue;
    snprintf(state->follow_routes[i].via, sizeof(state->follow_routes[i].via),
             "%s", via);
    return;
  }
  if (state->follow_route_count >= MAX_UPGRADE_ROUTES) {
    hub_log_warning("[UPGRADE] No room to route %s — it stays out of the run\n", uuid);
    return;
  }
  upgrade_route_t *r = &state->follow_routes[state->follow_route_count++];
  snprintf(r->uuid, sizeof(r->uuid), "%s", uuid);
  snprintf(r->via, sizeof(r->via), "%s", via);
}

/* The next hop toward `uuid`, or NULL when this hub never saw it. */
static const char *upgrade_route_via(const hub_state_t *state,
                                     const char *uuid) {
  if (!uuid || !uuid[0]) return NULL;
  for (int i = 0; i < state->follow_route_count; i++)
    if (strcmp(state->follow_routes[i].uuid, uuid) == 0)
      return state->follow_routes[i].via;
  return NULL;
}

/* id|uuid|cur_ver|variant|arch|libc|ready|reason|kind */
static void hub_upgrade_answer_ready(hub_state_t *state, hub_client_t *peer,
                                     const char *id, bool ready,
                                     const char *reason, int relayed) {
  char arch[32], libc[16], clean_reason[192];
  hub_update_host_arch(arch, sizeof(arch));
  hub_update_host_libc(libc, sizeof(libc));
  upgrade_clean(clean_reason, sizeof(clean_reason), reason);

  /* The trailing "h" is the node KIND.  A bot's READY stops at the reason, so
   * an absent field still means "bot" and bot.h is untouched; a hub several
   * hops from the driver has no other way to say what it is, and the driver
   * has to know to route its COMMIT through the peer that forwarded this.
   * upgrade_clean() has already turned any '|' in the reason into '/', so the
   * field after it is unambiguous.  After the kind: how many local bots this
   * hub relayed the PREPARE to, so the driver waits for their answers. */
  char payload[640];
  snprintf(payload, sizeof(payload), "%s|%s|%s|%s|%s|%s|%d|%s|h|%d", id,
           state->hub_uuid, HUB_VERSION, hub_update_host_variant(), arch, libc,
           ready ? 1 : 0, clean_reason, relayed);
  peer_send_urgent(state, peer, CMD_UPGRADE_READY, payload);
  hub_log_info("[UPGRADE] %s upgrade %s%s%s\n", ready ? "Ready for" : "Cannot take",
          id, clean_reason[0] ? ": " : "", clean_reason);
}

/* id|uuid|status|version|detail */
/* Report a result upstream on behalf of `uuid` — this hub itself, or a local
 * bot the driver reaches through it.  `version` is the version to attribute
 * to that node ("" leaves it unknown). */
static void hub_upgrade_answer_result_uuid(hub_state_t *state,
                                           hub_client_t *peer, const char *id,
                                           const char *uuid, const char *status,
                                           const char *detail) {
  char clean_detail[192];
  upgrade_clean(clean_detail, sizeof(clean_detail), detail);
  char payload[640];
  snprintf(payload, sizeof(payload), "%s|%s|%s|%s|%s", id, uuid, status,
           HUB_VERSION, clean_detail);
  peer_send_urgent(state, peer, CMD_UPGRADE_RESULT, payload);
}

static void hub_upgrade_answer_result(hub_state_t *state, hub_client_t *peer,
                                      const char *id, const char *status,
                                      const char *detail) {
  hub_upgrade_answer_result_uuid(state, peer, id, state->hub_uuid, status,
                                 detail);
}

/* CMD_UPGRADE_PREPARE from a peer: a capability question.  Nothing is
 * downloaded and nothing on disk is touched until COMMIT. */
static void process_peer_upgrade_prepare(hub_state_t *state,
                                         hub_client_t *peer,
                                         const char *payload) {
  /* id|ver|variant|kind|min_from|base|hub_ver|hub_base — the bots' six
   * fields, then the hubs' own target and base (see hub_upgrade_start). */
  char id[64] = "", ver[64] = "", variant[8] = "", kind[8] = "";
  char min_from[64] = "", base[512] = "", hub_ver[64] = "", hub_base[512] = "";
  if (!wire_field(payload, 0, id, sizeof(id)) ||
      !wire_field(payload, 1, ver, sizeof(ver)) || !id[0] || !ver[0]) {
    hub_log_warning("[UPGRADE] Malformed UPGRADE_PREPARE from peer %s\n", peer->ip);
    return;
  }
  wire_field(payload, 2, variant, sizeof(variant));
  wire_field(payload, 3, kind, sizeof(kind));
  wire_field(payload, 4, min_from, sizeof(min_from));
  wire_field(payload, 5, base, sizeof(base));
  wire_field(payload, 6, hub_ver, sizeof(hub_ver));
  wire_tail(payload, 7, hub_base, sizeof(hub_base));
  /* Every field lands in this hub's config (the persisted roll-up plan) and
   * in a download path, so a peer's PREPARE is held to the same shape the
   * driver enforced on its admin: nothing that could split a line. */
  if (!hub_upgrade_plan_field_ok(id) || !hub_upgrade_plan_field_ok(ver) ||
      !hub_upgrade_plan_field_ok(variant) || !hub_upgrade_plan_field_ok(kind) ||
      !hub_upgrade_plan_field_ok(min_from) || !hub_upgrade_plan_field_ok(base) ||
      !hub_upgrade_plan_field_ok(hub_ver) ||
      !hub_upgrade_plan_field_ok(hub_base)) {
    hub_log_warning("[UPGRADE] Malformed UPGRADE_PREPARE from peer %s\n", peer->ip);
    return;
  }
  /* Loop suppression: a hub joins a run exactly ONCE, through the first peer
   * that told it about it.  Re-broadcasting means the same PREPARE arrives
   * again around every cycle in the peer graph; answering or relaying it a
   * second time would both duplicate the node and keep the frame circulating
   * forever.  Silence is the right answer — the driver already has ours.
   *
   * The id goes through the same seen-ring as OP_FORWARD, not a compare
   * against follow_id alone: follow_id holds ONE id and is cleared on abort,
   * refusal and expiry, so two runs in flight at once flip it back and forth
   * and a late copy after a clear is taken as new — either way the frames
   * circulate forever.  The driver seeds the ring with its own id at start,
   * so its PREPARE coming back around a cycle is dropped here too. */
  if (op_forward_seen_check_and_add(state, id)) {
    hub_log_debug("[UPGRADE] PREPARE %s already seen — not relaying it again\n", id);
    return;
  }
  /* Refuse to be a follower while driving a run of our own: two plans moving
   * the same mesh is exactly what the one-run-at-a-time rule prevents. */
  if (state->upgrade.active) {
    hub_upgrade_answer_ready(state, peer, id, false,
                             "already driving an upgrade of its own", 0);
    return;
  }

  /* Remember the plan whether or not this hub itself can take it: even a hub
   * that cannot upgrade must still relay the run to its own local bots and
   * carry their COMMITs, so `follow_*` is set unconditionally and
   * `follow_self_ready` records only whether the hub itself may commit. */
  char why[192] = "";
  bool ready = false;
  if (hub_ver[0])
    ready = hub_update_can_take(hub_ver, min_from, hub_base, why, sizeof(why));
  else
    snprintf(why, sizeof(why), "no hub target in this run");
  snprintf(state->follow_id, sizeof(state->follow_id), "%s", id);
  {
    char origin[64];
    snprintf(origin, sizeof(origin), "%s", upgrade_peer_uuid(state, peer));
    snprintf(state->follow_origin, sizeof(state->follow_origin), "%s", origin);
  }
  snprintf(state->follow_target, sizeof(state->follow_target), "%s", ver);
  snprintf(state->follow_variant, sizeof(state->follow_variant), "%s",
           variant[0] ? variant : hub_update_host_variant());
  snprintf(state->follow_hub_target, sizeof(state->follow_hub_target), "%s",
           hub_ver);
  snprintf(state->follow_hub_base, sizeof(state->follow_hub_base), "%s",
           hub_base);
  state->follow_self_ready = ready;
  state->follow_prepared = time(NULL);
  upgrade_routes_clear(state);

  /* Record the driver's plan as this hub's roll-up plan too.  A bot that was
   * down while the run went through reconnects to whichever hub it likes, so
   * every hub has to know what the network is supposed to be running; the
   * replicated config freeze is what keeps any of them from acting on it
   * before the run is over (see hub_rollup_may_try). */
  {
    pending_rollup_t *r = &state->rollup;
    r->have_plan = true;
    snprintf(r->target, sizeof(r->target), "%s", ver);
    snprintf(r->variant, sizeof(r->variant), "%s", variant);
    snprintf(r->kind, sizeof(r->kind), "%s", kind);
    snprintf(r->min_from, sizeof(r->min_from), "%s",
             min_from[0] ? min_from : "*");
    snprintf(r->base, sizeof(r->base), "%s", base);
    snprintf(r->hub_target, sizeof(r->hub_target), "%s", hub_ver);
    snprintf(r->hub_base, sizeof(r->hub_base), "%s", hub_base);
    r->plan_set = time(NULL);
    state->rollup_try_count = 0;
    hub_config_write(state); /* the plan survives a restart (Task 13) */
  }

  /* Fan PREPARE out to this hub's own local bots.  Each answers READY to us
   * (its hub); we forward that up to the origin, which records it as a remote
   * node reached through this hub.  That is what makes one run reach a bot no
   * matter which hub it is homed on. */
  /* Bots get the six fields they read, not the hubs' two on the end. */
  char bot_prepare[1024];
  snprintf(bot_prepare, sizeof(bot_prepare), "%s|%s|%s|%s|%s|%s", id, ver,
           variant, kind, min_from, base);
  int relayed = 0;
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type == CLIENT_BOT && c->authenticated &&
        send_cmd_to_bot(c, CMD_UPGRADE_PREPARE, bot_prepare))
      relayed++;
  }
  if (relayed)
    hub_log_info("[UPGRADE] Relayed PREPARE %s to %d local bot(s)\n", id, relayed);

  /* ...and on to this hub's OWN peers, minus the one it came from.  This is
   * what carries a run past the driver's immediate neighbours: every hub the
   * mesh can reach joins the run, whatever shape the peer links are wired in
   * (a chain, a star, a partial mesh).  Their answers come back to us and we
   * forward them up, so the driver sees one flat node table. */
  int fanned = 0;
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type != CLIENT_HUB || !c->authenticated || c == peer) continue;
    if (peer_send_urgent(state, c, CMD_UPGRADE_PREPARE, payload)) fanned++;
  }
  if (fanned)
    hub_log_info("[UPGRADE] Re-broadcast PREPARE %s to %d peer hub(s)\n", id, fanned);

  hub_upgrade_answer_ready(state, peer, id, ready, why, relayed);
}

/* A frame this hub is only relaying: an answer from somewhere below it in the
 * fan-out tree, on its way to the driver.  Returns true when it was handled
 * as a relay (route remembered, frame forwarded), false when the frame
 * belongs to a run this hub drives itself and should be noted locally. */
static bool hub_upgrade_relay_upstream(hub_state_t *state, hub_client_t *from,
                                       int cmd, const char *payload) {
  char id[64] = "", uuid[64] = "";
  wire_field(payload, 0, id, sizeof(id));
  wire_field(payload, 1, uuid, sizeof(uuid));
  if (!state->follow_id[0] || !id[0] || strcmp(state->follow_id, id) != 0)
    return false;

  /* Taken by value: upgrade_peer_uuid() points into state->peers, and the
   * route table it would be copied into lives in the same object. */
  char from_uuid[64];
  snprintf(from_uuid, sizeof(from_uuid), "%s", upgrade_peer_uuid(state, from));
  /* A frame coming DOWN from the driver's direction is not an answer to
   * relay; nothing below us is reached through the hop we answer to. */
  if (from_uuid[0] && strcmp(from_uuid, state->follow_origin) == 0)
    return false;

  if (cmd == CMD_UPGRADE_READY) upgrade_route_note(state, uuid, from_uuid);

  hub_client_t *origin = upgrade_find_peer(state, state->follow_origin);
  if (!origin) {
    hub_log_debug("[UPGRADE] Driver of %s is gone — dropping a relayed answer for "
            "%s\n", id, uuid);
    return true;
  }
  peer_send_urgent(state, origin, cmd, payload);
  return true;
}

/* CMD_UPGRADE_COMMIT from a peer: go.  Only an id we acknowledged at PREPARE,
 * and only while that acknowledgement is still fresh, may commit. */
static void process_peer_upgrade_commit(hub_state_t *state, hub_client_t *peer,
                                        const char *payload) {
  char id[64] = "", ver[64] = "", variant[8] = "", target_uuid[64] = "";
  if (!wire_field(payload, 0, id, sizeof(id)) ||
      !wire_field(payload, 1, ver, sizeof(ver)) || !id[0] || !ver[0]) {
    hub_log_warning("[UPGRADE] Malformed UPGRADE_COMMIT from peer %s\n", peer->ip);
    return;
  }
  wire_field(payload, 2, variant, sizeof(variant));
  wire_field(payload, 3, target_uuid, sizeof(target_uuid));
  if (!state->follow_id[0] || strcmp(state->follow_id, id) != 0) {
    hub_upgrade_answer_result(state, peer, id, "fail",
                              "no matching UPGRADE_PREPARE");
    return;
  }
  /* The version must be one this run named: the bots' target for a frame
   * on its way to a bot, the hubs' own for this hub (checked again below). */
  bool for_self = !target_uuid[0] || strcmp(target_uuid, state->hub_uuid) == 0;
  if (strcmp(state->follow_target, ver) != 0 &&
      !(state->follow_hub_target[0] &&
        strcmp(state->follow_hub_target, ver) == 0)) {
    hub_upgrade_answer_result(state, peer, id, "fail",
                              "commit version differs from prepare");
    return;
  }
  if (time(NULL) - state->follow_prepared > UPGRADE_PREPARE_TTL) {
    state->follow_id[0] = '\0';
    hub_upgrade_answer_result(state, peer, id, "fail", "prepare expired");
    return;
  }

  /* A 4th field names the node the driver is addressing.  It is one of three
   * things, in order: this hub, one of its local bots, or something further
   * out that this hub relayed an answer for at PREPARE time — in which case
   * the frame goes on, unchanged, along the route it learned. */
  if (!for_self) {
    hub_client_t *bot = upgrade_find_client(state, target_uuid, CLIENT_BOT);
    if (bot) {
      char relay[192];
      snprintf(relay, sizeof(relay), "%s|%s|%s", id, ver, variant);
      if (!send_cmd_to_bot(bot, CMD_UPGRADE_COMMIT, relay))
        hub_upgrade_answer_result_uuid(state, peer, id, target_uuid, "fail",
                                       "bot not reachable through this hub");
      return;
    }
    const char *via = upgrade_route_via(state, target_uuid);
    hub_client_t *next = via ? upgrade_find_peer(state, via) : NULL;
    if (!next || !peer_send_urgent(state, next, CMD_UPGRADE_COMMIT, payload))
      hub_upgrade_answer_result_uuid(state, peer, id, target_uuid, "fail",
                                     "no route to that node from this hub");
    return;
  }

  /* No target uuid: this hub is the node being committed. */
  if (!state->follow_self_ready) {
    hub_upgrade_answer_result(state, peer, id, "fail",
                              "this hub cannot take the upgrade");
    return;
  }
  if (strcmp(state->follow_hub_target, ver) != 0) {
    hub_upgrade_answer_result(state, peer, id, "fail",
                              "commit version differs from prepare");
    return;
  }

  const char *err = NULL;
  if (!hub_update_commit(state, id, ver,
                         variant[0] ? variant : state->follow_variant,
                         state->follow_hub_base, &err)) {
    /* Nothing was changed on disk; stay on this build and say why. */
    hub_log_warning("[UPGRADE] Commit %s refused: %s\n", id,
            err ? err : "unknown error");
    hub_upgrade_answer_result(state, peer, id, "fail", err ? err : "failed");
    state->follow_id[0] = '\0';
  }
  /* On success hub_update_commit() does not return: the process is replaced
   * and hub_upgrade_report_pending() reports in after the restart. */
}

/* CMD_UPGRADE_ABORT from a peer: put the retained build back. */
static void process_peer_upgrade_abort(hub_state_t *state, hub_client_t *peer,
                                       const char *payload) {
  char id[64] = "", uuid[64] = "", reason[192] = "";
  wire_field(payload, 0, id, sizeof(id));
  wire_field(payload, 1, uuid, sizeof(uuid));
  wire_tail(payload, 2, reason, sizeof(reason));
  hub_log_info("[UPGRADE] Abort %s from peer %s%s%s: %s\n", id[0] ? id : "(no id)",
          peer->ip, uuid[0] ? " for bot " : "", uuid[0] ? uuid : "",
          reason[0] ? reason : "no reason given");

  /* A named node that is not this hub: one of its local bots (which gets the
   * plain id|reason frame), or something further out, which the route learned
   * at PREPARE time carries the frame on to unchanged.  Either way this hub's
   * own follower state belongs to its own node and is left alone. */
  if (uuid[0] && strcmp(uuid, state->hub_uuid) != 0) {
    hub_client_t *bot = upgrade_find_client(state, uuid, CLIENT_BOT);
    if (bot) {
      char relay[256];
      snprintf(relay, sizeof(relay), "%s|", id);
      upgrade_clean(relay + strlen(relay), sizeof(relay) - strlen(relay),
                    reason);
      send_cmd_to_bot(bot, CMD_UPGRADE_ABORT, relay);
      return;
    }
    const char *via = upgrade_route_via(state, uuid);
    hub_client_t *next = via ? upgrade_find_peer(state, via) : NULL;
    if (next) peer_send_urgent(state, next, CMD_UPGRADE_ABORT, payload);
    return;
  }

  state->follow_id[0] = '\0';
  state->follow_prepared = 0;
  state->follow_self_ready = false;
  upgrade_routes_clear(state);
  if (!hub_update_rollback(state, reason[0] ? reason : "the upgrade was aborted"))
    hub_upgrade_answer_result(state, peer, id[0] ? id : "-", "aborted",
                              "nothing retained to roll back to");
  /* A successful rollback execs; the driver sees the old version reappear. */
}

/* Called once per authenticated peer link.  If this process is the product of
 * an upgrade another hub drove, the marker left behind by hub_update_commit()
 * says which run it belongs to; report whether we came up on the version that
 * run was aiming at.  The driver also infers success from the roster gossip,
 * so a lost RESULT costs nothing. */
void hub_upgrade_report_pending(hub_state_t *state, hub_client_t *peer) {
  char id[64], want[64];
  if (!hub_update_take_pending(id, sizeof(id), want, sizeof(want))) return;
  bool ok = (hub_update_version_cmp(HUB_VERSION, want) == 0);
  hub_log_warning("[UPGRADE] Restarted after %s: running %s (wanted %s)\n", id,
          HUB_VERSION, want);
  hub_upgrade_answer_result(state, peer, id, ok ? "ok" : "version-mismatch",
                            ok ? "" : want);
}

/* CMD_ADMIN_UPGRADE_STATUS: one line per node, for hub_admin to print. */
static void hub_upgrade_status(hub_state_t *state, char *out, size_t out_size) {
  pending_upgrade_t *u = &state->upgrade;
  /* The roll-up plan this hub holds, if any: what a bot that comes back is
   * walked up to, until an admin's "forget" drops it. */
  const pending_rollup_t *r = &state->rollup;
  char plan[256] = "";
  if (r->have_plan)
    snprintf(plan, sizeof(plan),
             "roll-up plan: bots -> %s%s%s (set %ld s ago; \"forget\" drops it)\n",
             r->target, r->hub_target[0] ? ", hubs -> " : "",
             r->hub_target, (long)(time(NULL) - r->plan_set));
  if (!u->id[0]) {
    snprintf(out, out_size, "No upgrade has run on this hub.%s%s%s",
             plan[0] ? "\n" : "", plan,
             hub_config_frozen(state)
                 ? "\nWARNING: config is frozen — clear opt flag 'F' to lift it."
                 : "");
    return;
  }
  int off = snprintf(out, out_size,
                     "--- Upgrade %s -> %s (%s) ---\nstarted %ld s ago%s%s\n",
                     u->id, u->target_ver, upgrade_phase_name(u->phase),
                     (long)(time(NULL) - u->started),
                     u->summary[0] ? "; " : "", u->summary);
  if (off < 0 || off >= (int)out_size) return;
  if (u->hub_ver[0]) {
    int w = snprintf(out + off, out_size - (size_t)off, "hubs -> %s\n",
                     u->hub_ver);
    if (w <= 0 || w >= (int)out_size - off) return;
    off += w;
  }
  if (plan[0]) {
    int w = snprintf(out + off, out_size - (size_t)off, "%s", plan);
    if (w <= 0 || w >= (int)out_size - off) return;
    off += w;
  }

  for (int i = 0; i < u->node_count && off < (int)out_size - 1; i++) {
    const upgrade_node_t *n = &u->nodes[i];
    const char *kind = (n->kind == 'b') ? "bot" : (n->kind == 'h') ? "hub" : "self";
    int w = snprintf(out + off, out_size - (size_t)off,
                     "%-4s %-36s %-10s %-8s %s%s%s\n", kind,
                     n->name[0] ? n->name : n->uuid,
                     upgrade_node_state_name(n->state),
                     n->cur_version[0] ? n->cur_version : "-",
                     n->variant[0] ? n->variant : "", n->reason[0] ? " " : "",
                     n->reason);
    if (w <= 0 || w >= (int)out_size - off) break;
    off += w;
  }
}

/* A local bot's CMD_UPGRADE_READY/RESULT.  If this hub is following a run
 * another hub drives and the frame belongs to it, the bot is a node of that
 * run reached through us — forward the frame up to the driver unchanged so it
 * records the bot as a remote node.  Otherwise it belongs to a run this hub
 * drives itself (or none), and is noted locally. */
static void hub_upgrade_bot_report(hub_state_t *state, int cmd,
                                   const char *payload) {
  char id[64] = "";
  wire_field(payload, 0, id, sizeof(id));
  if (state->follow_id[0] && id[0] && strcmp(state->follow_id, id) == 0) {
    hub_client_t *origin = upgrade_find_peer(state, state->follow_origin);
    if (origin) {
      peer_send_urgent(state, origin, cmd, payload);
      return;
    }
    /* Driver gone: fall through and note it locally so nothing is lost. */
  }
  if (cmd == CMD_UPGRADE_READY)
    hub_upgrade_note_ready(state, payload, NULL);
  else
    hub_upgrade_note_result(state, payload);
}

/* ---- Sealed bot-to-bot relay (CMD_BOT_RELAY / CMD_BOT_RELAY_FWD) ------- */

/* The authenticated local bot with this uuid, or NULL. */
static hub_client_t *bot_relay_local_target(hub_state_t *state,
                                            const char *uuid) {
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type == CLIENT_BOT && c->authenticated && strcmp(c->id, uuid) == 0)
      return c;
  }
  return NULL;
}

/* Hand a sealed payload to a local bot as CMD_BOT_MSG "<sender>|<sealed frame>".
 * The sender is the uuid the originating hub authenticated, which is what the
 * bot binds the GCM AAD to. */
static bool bot_relay_deliver(hub_client_t *target, const char *sender_uuid,
                              const char *sealed) {
  char forwarded[MAX_BUFFER];
  int len = snprintf(forwarded, sizeof(forwarded), "%s|%s", sender_uuid,
                     sealed);
  if (len <= 0 || len + 5 > MAX_BUFFER) {
    hub_log_warning("[HUB] CMD_BOT_RELAY: forwarded payload too long\n");
    return false;
  }
  if (!send_cmd_to_bot(target, CMD_BOT_MSG, forwarded)) {
    hub_log_warning("[HUB] CMD_BOT_RELAY: write to %s failed\n", target->id);
    return false;
  }
  hub_log_debug("[HUB] CMD_BOT_RELAY: forwarded to %s (%d bytes)\n",
          target->id, len);
  return true;
}

/* Flood one relay to every authenticated peer except `exclude_fd`.  Returns
 * how many peers took it. */
static int bot_relay_forward(hub_state_t *state, const char *request_id,
                             long long origin_ts, const char *sender_uuid,
                             const char *target_uuid, const char *sealed,
                             int exclude_fd) {
  char *fwd = malloc(MAX_BUFFER);
  if (!fwd) return 0;
  int len = snprintf(fwd, MAX_BUFFER, "%s|%lld|%s|%s|%s", request_id,
                     origin_ts, sender_uuid, target_uuid, sealed);
  int sent = 0;
  if (len > 0 && len + 5 <= MAX_BUFFER) {
    for (int i = 0; i < state->client_count; i++) {
      hub_client_t *c = state->clients[i];
      if (c->type != CLIENT_HUB || !c->authenticated || c->fd == exclude_fd)
        continue;
      if (peer_send_urgent(state, c, CMD_BOT_RELAY_FWD, fwd)) sent++;
    }
  } else {
    hub_log_warning("[HUB] CMD_BOT_RELAY: too long to forward to peers\n");
  }
  free(fwd);
  return sent;
}

/* A uuid a peer names in a forwarded relay: plain id characters only, so it
 * cannot smuggle a separator or a control byte into a bot frame or a log. */
static bool bot_relay_id_ok(const char *s) {
  if (!s || !s[0]) return false;
  for (; *s; s++)
    if (!isalnum((unsigned char)*s) && *s != '-' && *s != '_' && *s != '.')
      return false;
  return true;
}

/* CMD_BOT_RELAY_FWD from a peer: deliver it if the target is ours, else pass
 * it on.  Payload: id|origin_ts|sender_uuid|target_uuid|<sealed frame> */
static void process_peer_bot_relay(hub_state_t *state, hub_client_t *peer,
                                   const char *payload) {
  char id[64] = "", ts[24] = "", sender[64] = "", target[64] = "";
  if (!wire_field(payload, 0, id, sizeof(id)) ||
      !wire_field(payload, 1, ts, sizeof(ts)) ||
      !wire_field(payload, 2, sender, sizeof(sender)) ||
      !wire_field(payload, 3, target, sizeof(target)) ||
      !bot_relay_id_ok(id) || !bot_relay_id_ok(sender) ||
      !bot_relay_id_ok(target)) {
    hub_log_warning("[HUB] Invalid BOT_RELAY_FWD payload from peer %s\n", peer->ip);
    return;
  }
  /* The sealed blob is everything after the 4th '|'. */
  const char *sealed = payload;
  for (int n = 0; n < 4 && sealed; n++) {
    sealed = strchr(sealed, '|');
    if (sealed) sealed++;
  }
  /* Opaque to the hub (bots send "~B2 <b64>"): only require a non-empty
   * blob with no control bytes, so it cannot break a bot frame or a log. */
  bool blob_ok = sealed && *sealed;
  for (const unsigned char *b = (const unsigned char *)sealed; blob_ok && *b; b++)
    if (*b < 0x20 || *b == 0x7f) blob_ok = false;
  if (!blob_ok) {
    hub_log_warning("[HUB] BOT_RELAY_FWD without a sealed payload from peer %s\n",
            peer->ip);
    return;
  }
  long long origin_ts = atoll(ts);
  long long age = (long long)time(NULL) - origin_ts;
  if (origin_ts <= 0 || age > BOT_RELAY_FWD_TTL || age < -BOT_RELAY_FWD_TTL) {
    hub_log_debug("[HUB] Dropping stale BOT_RELAY_FWD (id:%s, age=%llds)\n", id,
            age);
    return;
  }
  if (op_forward_seen_check_and_add(state, id)) return; /* around a cycle */

  hub_client_t *t = bot_relay_local_target(state, target);
  if (t) {
    hub_log_debug("[HUB] BOT_RELAY_FWD %s: %s -> local bot %s\n", id, sender, target);
    bot_relay_deliver(t, sender, sealed);
    return;
  }
  int sent = bot_relay_forward(state, id, origin_ts, sender, target, sealed,
                               peer->fd);
  hub_log_debug("[HUB] BOT_RELAY_FWD %s for %s passed on to %d peer(s)\n", id,
          target, sent);
}

/* ---- Activity (CMD_ACTIVITY / CMD_ACTIVITY_QUERY) ----------------------- */

/* A user uuid as the config stores it: 36 chars, hex and dashes. */
static bool activity_uuid_ok(const char *s) {
  if (!s || strlen(s) != 36) return false;
  for (int i = 0; i < 36; i++) {
    bool dash = (i == 8 || i == 13 || i == 18 || i == 23);
    if (dash ? s[i] != '-' : !isxdigit((unsigned char)s[i])) return false;
  }
  return true;
}

static hub_user_record_t *activity_user(hub_state_t *state, const char *uuid) {
  for (int i = 0; i < state->user_record_count; i++)
    if (strcmp(state->user_records[i].uuid, uuid) == 0)
      return &state->user_records[i];
  return NULL;
}

static hub_mask_record_t *activity_mask(hub_state_t *state, const char *uuid,
                                        const char *mask) {
  for (int i = 0; i < state->mask_record_count; i++)
    if (strcmp(state->mask_records[i].uuid, uuid) == 0 &&
        strcasecmp(state->mask_records[i].mask, mask) == 0)
      return &state->mask_records[i];
  return NULL;
}

/* Send CMD_ACTIVITY lines to every authenticated peer except exclude_fd. */
static void activity_flood(hub_state_t *state, const char *lines, int len,
                           int exclude_fd) {
  if (len <= 0) return;
  for (int i = 0; i < state->client_count; i++) {
    hub_client_t *c = state->clients[i];
    if (c->type != CLIENT_HUB || !c->authenticated || c->fd == exclude_fd)
      continue;
    queued_msg_t *m = queued_msg_new(CMD_ACTIVITY, LANE_DELTA,
                                     (const unsigned char *)lines, len);
    if (!m) continue;
    if (!peer_enqueue(c, m))
      hub_log_warning("[ACTIVITY] enqueue failed for peer %s\n", c->ip);
  }
}

/* hub_admin login: stamp the admin's exact time; the first login in an
 * ACTIVITY_BUCKET is flooded to the peers.  Never a config change. */
static void hub_activity_stamp_user(hub_state_t *state, hub_user_record_t *u,
                                    time_t now) {
  if (!u || now <= u->last_seen) return;
  bool new_bucket = u->last_seen / ACTIVITY_BUCKET < now / ACTIVITY_BUCKET;
  u->last_seen = now;
  state->config_dirty = true;
  hub_log_debug("[ACTIVITY] %s last seen %lld%s\n", u->name, (long long)now,
                new_bucket ? " (first this hour: flooded to peers)" : "");
  if (!new_bucket) return;
  char line[80];
  int len = snprintf(line, sizeof(line), "a|%s|%lld\n", u->uuid,
                     (long long)now);
  if (len > 0 && len < (int)sizeof(line))
    activity_flood(state, line, len, -1);
}

/* CMD_ACTIVITY from a bot (from = the bot) or a peer (from = the peer).
 * Every line is validated on its own; a bad or unknown one is dropped.
 * Lines that raised our value go on to the other peers. */
static void process_activity(hub_state_t *state, hub_client_t *from,
                             const char *payload) {
  char *fwd = malloc(MAX_BUFFER);
  char *buf = strdup(payload ? payload : "");
  if (!fwd || !buf) {
    free(fwd);
    free(buf);
    return;
  }
  int fwd_len = 0, raised = 0, lines = 0;
  long long now = (long long)time(NULL);
  char *save = NULL;
  for (char *line = strtok_r(buf, "\n", &save); line;
       line = strtok_r(NULL, "\n", &save)) {
    if (++lines > MAX_HUB_USER_RECORDS + MAX_HUB_USER_MASKS) break;
    /* a|uuid|ts or m|uuid|mask|ts.  The time is always the last field, so
     * a mask may hold a '|' of its own. */
    char uuid[40] = "", mask[MAX_MASK_LEN] = "";
    bool is_mask = line[0] == 'm';
    const char *last = strrchr(line, '|');
    size_t mask_len = 0;
    bool ok = (line[0] == 'a' || is_mask) && line[1] == '|' &&
              wire_field(line, 1, uuid, sizeof(uuid)) && activity_uuid_ok(uuid);
    if (ok && is_mask) {
      const char *mstart = line + 2 + 36 + 1;
      ok = last > mstart && mstart[-1] == '|';
      mask_len = ok ? (size_t)(last - mstart) : 0;
      if (ok && mask_len < sizeof(mask)) {
        memcpy(mask, mstart, mask_len);
        mask[mask_len] = '\0';
      } else {
        ok = false;
      }
    } else if (ok) {
      ok = last == line + 2 + 36;
    }
    if (!ok) {
      hub_log_debug("[ACTIVITY] malformed line from %s\n", from->id);
      continue;
    }
    char *end = NULL;
    long long ts = strtoll(last + 1, &end, 10);
    if (!end || *end != '\0' || ts <= 0 || ts > now + ACTIVITY_MAX_FUTURE) {
      hub_log_debug("[ACTIVITY] bad time from %s\n", from->id);
      continue;
    }
    time_t *slot = NULL;
    if (is_mask) {
      hub_mask_record_t *m = activity_mask(state, uuid, mask);
      if (m) slot = &m->last_used;
    } else {
      hub_user_record_t *u = activity_user(state, uuid);
      if (u) slot = &u->last_seen;
    }
    if (!slot || (long long)*slot >= ts) continue; /* unknown or not newer */
    *slot = (time_t)ts;
    raised++;
    int w = is_mask
                ? snprintf(fwd + fwd_len, MAX_BUFFER - fwd_len,
                           "m|%s|%s|%lld\n", uuid, mask, ts)
                : snprintf(fwd + fwd_len, MAX_BUFFER - fwd_len, "a|%s|%lld\n",
                           uuid, ts);
    if (w > 0 && w < MAX_BUFFER - fwd_len - 5) fwd_len += w;
  }
  if (raised) {
    state->config_dirty = true;
    hub_log_debug("[ACTIVITY] %d record(s) raised by %s\n", raised, from->id);
    activity_flood(state, fwd, fwd_len,
                   from->type == CLIENT_HUB ? from->fd : -1);
  }
  free(buf);
  free(fwd);
}

/* Queue one CMD_ACTIVITY_REPLY chunk to a bot. */
static void activity_reply_send(hub_client_t *bot, const char *frame, int len) {
  queued_msg_t *m = queued_msg_new(CMD_ACTIVITY_REPLY, LANE_DELTA,
                                   (const unsigned char *)frame, len);
  if (!m) return;
  if (!peer_enqueue(bot, m))
    hub_log_warning("[ACTIVITY] reply enqueue failed for %s\n", bot->id);
}

/* CMD_ACTIVITY_QUERY from a bot: <req_id>|users or <req_id>|masks|<uuid|*>.
 * Answers every known time (records at 0 are left out), chunked. */
static void process_activity_query(hub_state_t *state, hub_client_t *bot,
                                   const char *payload) {
  char req[ACTIVITY_REQ_ID_MAX + 1] = "", kind[8] = "", who[40] = "";
  if (!wire_field(payload, 0, req, sizeof(req)) || !bot_relay_id_ok(req) ||
      !wire_field(payload, 1, kind, sizeof(kind))) {
    hub_log_warning("[ACTIVITY] invalid query from %s\n", bot->id);
    return;
  }
  bool masks = strcmp(kind, "masks") == 0;
  if (!masks && strcmp(kind, "users") != 0) {
    hub_log_warning("[ACTIVITY] unknown query kind from %s\n", bot->id);
    return;
  }
  if (masks && (!wire_field(payload, 2, who, sizeof(who)) ||
                (strcmp(who, "*") != 0 && !activity_uuid_ok(who)))) {
    hub_log_warning("[ACTIVITY] invalid masks query from %s\n", bot->id);
    return;
  }
  bool all = !masks || strcmp(who, "*") == 0;

  /* Frame budget: header + the longest line must always fit. */
  const int cap = MAX_BUFFER - 64;
  char *frame = malloc((size_t)cap);
  if (!frame) return;
  int hdr = snprintf(frame, (size_t)cap, "%s|1\n", req);
  int len = hdr;
  for (int pass = 0; pass < (masks ? 2 : 1); pass++) {
    int n = pass == 0 ? state->user_record_count : state->mask_record_count;
    for (int i = 0; i < n; i++) {
      char line[MAX_MASK_LEN + 96];
      int w = 0;
      if (pass == 0) {
        const hub_user_record_t *u = &state->user_records[i];
        if (u->last_seen <= 0 || (!all && strcmp(u->uuid, who) != 0)) continue;
        w = snprintf(line, sizeof(line), "a|%s|%lld\n", u->uuid,
                     (long long)u->last_seen);
      } else {
        const hub_mask_record_t *m = &state->mask_records[i];
        if (m->last_used <= 0 || (!all && strcmp(m->uuid, who) != 0)) continue;
        w = snprintf(line, sizeof(line), "m|%s|%s|%lld\n", m->uuid, m->mask,
                     (long long)m->last_used);
      }
      if (w <= 0 || w >= (int)sizeof(line)) continue;
      if (len + w > cap) {
        activity_reply_send(bot, frame, len);
        len = hdr;
      }
      memcpy(frame + len, line, (size_t)w);
      len += w;
    }
  }
  /* Last chunk: more=0. */
  frame[hdr - 2] = '0';
  activity_reply_send(bot, frame, len);
  free(frame);
}

static void process_bot_command(hub_state_t *state, hub_client_t *client,
                                int cmd, char *payload) {
  switch (cmd) {
  case CMD_PING:
    if (!HIDEPINGPONG)
      hub_log_debug("[HUB] Bot %s PING\n", client->id);
    break;

  case CMD_BOT_PRESENCE:
    process_bot_presence(state, client, payload);
    break;

  case CMD_ACTIVITY:
    process_activity(state, client, payload);
    break;

  case CMD_ACTIVITY_QUERY:
    process_activity_query(state, client, payload);
    break;

  case CMD_UPGRADE_READY:
    hub_upgrade_bot_report(state, CMD_UPGRADE_READY, payload);
    break;

  case CMD_UPGRADE_RESULT:
    hub_upgrade_bot_report(state, CMD_UPGRADE_RESULT, payload);
    break;

  case CMD_CONFIG_PUSH: {
    process_bot_config_push(state, client, payload);
  } break;

  case CMD_CONFIG_PULL:
    hub_log_debug("[HUB] Config PULL request from %s\n", client->id);
    send_config_to_bot(state, client, true);
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
    client->cfg_sent_valid = false; /* as for CMD_CONFIG_PUSH */
    if (sscanf(payload, "%31[^|]|%1023[^|]|%lld", key, val, &ts) < 2) {
      hub_log_warning("[HUB] Invalid CMD_BOT_DELTA from %s — ignoring\n", client->id);
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
      hub_log_warning("[HUB] opt 'h' active: REJECTED bot delta '%s' from %s "
              "(hub-authoritative)\n", key, client->id);
      break;
    }

    /* Task 6 — opt 'F' (OPT_CONFIG_FROZEN): while an upgrade run is open the
     * store does not move at all, or a node that restarts mid-roll comes back
     * against a config its neighbours have not seen. */
    if (hub_config_frozen(state)) {
      hub_log_warning("[UPGRADE] config frozen: REJECTED bot delta '%s' from %s\n",
              key, client->id);
      break;
    }

    /* Change 3b's per-bot key whitelist + value caps are enforced centrally in
     * hub_storage_update_entry (the single choke point shared by this delta
     * path, process_bot_config_push, process_peer_sync, and config load), so a
     * rejected key/value simply returns "not accepted" below. */

    hub_log_debug("[HUB] BOT_DELTA from %s: key=%s val=%.40s ts=%lld\n",
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

    sync_send_to_peers(state, delta_line, -1, false, LANE_DELTA, coalesce, seq);

    /* Also push fresh config to locally connected bots so they learn the
     * new hostmask / nick immediately without waiting for anti-entropy. */
    for (int i = 0; i < state->client_count; i++) {
      hub_client_t *c = state->clients[i];
      if (c->type == CLIENT_BOT && c->authenticated &&
          strcmp(c->id, client->id) != 0) {
        send_config_to_bot(state, c, false);
      }
    }
    break;
  }

  case CMD_OP_REQUEST: {
    // Payload format: target_uuid|channel
    char target_uuid[64];
    char channel[MAX_CHAN];

    if (sscanf(payload, "%63[^|]|%64s", target_uuid, channel) != 2) {
      hub_log_warning("[HUB] Invalid OP_REQUEST payload from %s\n", client->id);
      break;
    }

    hub_log_info("[HUB] OP_REQUEST from %s for target %s in %s\n", client->id,
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
      hub_log_info("[HUB] Target bot %s not connected locally\n", target_uuid);

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
          hub_log_warning("[HUB] No hostmask for requester %s — cannot forward OP_REQUEST\n",
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
                                       target_uuid, channel, req_hostmask, -1, op_origin_ts,
                                       false);
          hub_log_info("[HUB] Forwarded OP_REQUEST (id:%s) to %d peer hub(s)\n",
                  request_id, peer_count);
        } else {
          hub_log_warning("[HUB] Failed to add pending OP request - table full\n");
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
            hub_log_warning("[HUB] Failed to send OP_FAILED response to %s\n",
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
      hub_log_warning("[HUB] No hostmask stored for requesting bot %s\n", client->id);
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
          hub_log_warning("[HUB] Failed to send OP_FAILED to bot %s\n", client->id);
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
        hub_log_info("[HUB] Forwarded OP_GRANT to %s: grant ops to %s in %s\n",
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
      hub_log_warning("[HUB] Invalid INVITE_REQUEST payload from %s\n", client->id);
      break;
    }
    hub_log_info("[HUB] INVITE_REQUEST from %s: invite %s into %s\n",
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
            hub_log_warning("[HUB] Failed to forward INVITE_REQUEST to bot %s\n",
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
    /* Payload: target_uuid|<sealed frame> — forward to target bot. The hub
     * KNOWS the sender's identity from the authenticated session
     * (client->id == sender bot's UUID). It prepends that UUID to the
     * forwarded CMD_BOT_MSG payload so the receiver can verify the
     * sender's GCM AAD binding. */
    char target_uuid[64];
    char *pipe = strchr(payload, '|');
    if (!pipe) {
      hub_log_warning("[HUB] Invalid CMD_BOT_RELAY payload from %s\n", client->id);
      break;
    }
    size_t uuid_len = (size_t)(pipe - payload);
    if (uuid_len == 0 || uuid_len >= sizeof(target_uuid)) {
      hub_log_warning("[HUB] CMD_BOT_RELAY bad UUID len from %s\n", client->id);
      break;
    }
    memcpy(target_uuid, payload, uuid_len);
    target_uuid[uuid_len] = '\0';

    hub_log_debug("[HUB] CMD_BOT_RELAY from %s to %s\n", client->id, target_uuid);

    hub_client_t *target = bot_relay_local_target(state, target_uuid);
    if (target) {
      bot_relay_deliver(target, client->id, pipe + 1);
      break;
    }
    /* Not one of ours: the target may be homed on any hub in the mesh, as
     * many hops out as the peer links go.  Flood it under a fresh id — but
     * only for a bot the config knows, so a bot cannot make the whole mesh
     * carry frames for uuids nobody will ever deliver. */
    bool known = false;
    for (int i = 0; i < state->bot_count && !known; i++)
      known = state->bots[i].is_active &&
              strcmp(state->bots[i].uuid, target_uuid) == 0;
    if (!known) {
      hub_log_warning("[HUB] CMD_BOT_RELAY: target %s is not a known bot\n",
              target_uuid);
      break;
    }
    char request_id[64];
    generate_request_id(request_id, sizeof(request_id));
    op_forward_seen_check_and_add(state, request_id);
    int sent = bot_relay_forward(state, request_id, (long long)time(NULL),
                                 client->id, target_uuid, pipe + 1, -1);
    if (sent == 0)
      hub_log_warning("[HUB] CMD_BOT_RELAY: target %s not connected and no peer "
              "to forward to\n", target_uuid);
    else
      hub_log_debug("[HUB] CMD_BOT_RELAY: %s not local — forwarded (id:%s) to "
              "%d peer(s)\n", target_uuid, request_id, sent);
  } break;
  }
}

// NEW FUNCTION: Send hub's stored config back to bot
/* SHA-256 of a bot config, leaving out the pd| line: it is stamped with the
 * time it was built, and bots do not read it, so it alone never makes a push
 * worth sending.  Returns false if the digest could not be taken. */
static bool bot_config_hash(const char *payload, size_t len,
                            unsigned char out[32]) {
  const char *pd = NULL;
  if (len >= 3 && strncmp(payload, "pd|", 3) == 0) pd = payload;
  else {
    const char *hit = strstr(payload, "\npd|");
    if (hit) pd = hit + 1;
  }
  const char *after = NULL;
  if (pd) {
    const char *nl = strchr(pd, '\n');
    after = nl ? nl + 1 : payload + len;
  }
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  unsigned int olen = 0;
  bool ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
            EVP_DigestUpdate(ctx, payload, pd ? (size_t)(pd - payload) : len) == 1 &&
            (!pd || EVP_DigestUpdate(ctx, after,
                                     (size_t)(payload + len - after)) == 1) &&
            EVP_DigestFinal_ex(ctx, out, &olen) == 1 && olen == 32;
  EVP_MD_CTX_free(ctx);
  return ok;
}

/* Queue this bot its full config.  force=false (a broadcast) skips the push
 * when the bot was already sent this exact config and that push was not
 * lost; force=true always sends (the bot's first config, a PULL, a re-shape). */
static void send_config_to_bot(hub_state_t *state, hub_client_t *client,
                               bool force) {
  /* Change 5: heap the generation buffer — a full config can exceed MAX_BUFFER
   * at scale and is too large for the stack.  MAX_CONFIG_PAYLOAD is a hard
   * upper bound (see hub.h), so hub_generate_bot_payload never truncates. */
  char *payload = malloc(MAX_CONFIG_PAYLOAD);
  if (!payload) {
    hub_log_error("[HUB] send_config_to_bot: OOM for %s\n", client->id);
    return;
  }

  // Use the new payload generator that combines Global + Bot-specific
  // and omits "b|uuid|" prefix for correct bot parsing
  hub_generate_bot_payload(state, client->id,
                           client->bot_proto >= BOT_PROTO_PASSWORDLESS,
                           payload, MAX_CONFIG_PAYLOAD);

  int len = strlen(payload);
  if (len == 0) {
    hub_log_warning("[HUB] No config to send to %s\n", client->id);
    free(payload);
    return;
  }

  unsigned char hash[32];
  bool hashed = bot_config_hash(payload, (size_t)len, hash);
  if (!force && hashed && client->cfg_sent_valid &&
      memcmp(hash, client->cfg_sent_hash, sizeof(hash)) == 0) {
    g_hub_stats.cfg_same++;
    secure_wipe(payload, (size_t)len);
    free(payload);
    return;
  }

  hub_log_debug("[HUB-SYNC] Queueing config to %s (%d bytes)\n", client->id, len);

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
  secure_wipe(payload, (size_t)len);
  free(payload);
  client->cfg_sent_valid = false;
  if (!m) return;
  queued_msg_set_coalesce(m, state->hub_uuid,
                          hub_next_lamport_seq(state), coalesce);
  if (!peer_enqueue(client, m)) {
    g_hub_stats.cfg_lost++;
    return;
  }
  g_hub_stats.cfg_sent++;
  if (hashed) {
    memcpy(client->cfg_sent_hash, hash, sizeof(hash));
    client->cfg_sent_valid = true;
  }
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
      hub_log_warning("[HUB] Invalid packet length %d from %s (cap %d)\n", packet_len,
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
          hub_log_warning("[HUB] Repeated ADMIN-HELLO from %s — disconnecting\n",
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
                hub_log_warning("[HUB] Admin auth from %s: name '%s' too long for "
                        "client id — refusing\n", client->ip, auth_name);
                hub_disconnect_client(state, client);
                return false;
              }
              client->type = CLIENT_ADMIN;
              client->authenticated = true;
              /* D2: grow buffers now that the admin is authenticated. */
              if (!hub_client_promote_buffers(client)) {
                hub_log_error("[HUB] Buffer promotion OOM for admin %s — "
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

              /* Activity, not a config change: no peer sync, no bot push.
               * The first login in a clock hour is flooded to the peers. */
              hub_activity_stamp_user(state, admin_u, time(NULL));
              char afp[KEY_FP_LEN + 1];
              hub_crypto_key_fingerprint(admin_pub, afp);
              hub_log_info("[HUB] Admin Login (key %s): %s as '%s'\n",
                      afp, client->ip, auth_name);

              /* Tell hub_admin who it is logged in as (encrypted). */
              char ok_msg[96];
              snprintf(ok_msg, sizeof(ok_msg), "AUTH-OK|%s", auth_name);
              if (!send_response(state, client, ok_msg)) {
                secure_wipe(plain, sizeof(plain));
                return false;  /* send_response already disconnected */
              }
            } else {
              hub_log_warning("[HUB] Failed admin auth from %s: %s\n", client->ip, why);
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
            hub_log_warning("[HUB] Peer %s speaks HUBv2 (pre-passwordless) — refusing; "
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
              hub_log_warning("[HUB] v3 peer auth: malformed payload from %s\n",
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
              hub_log_warning("[HUB] v3 peer auth: no pubkey on file for uuid %s "
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
              hub_log_error("[HUB] v3 peer auth: transcript overflow\n");
              secure_wipe(plain, sizeof(plain));
              hub_disconnect_client(state, client);
              return false;
            }

            int sig_len = 0;
            unsigned char *sig = base64_decode(sig_b64, &sig_len);
            if (!sig || sig_len != ED25519_SIG_LEN) {
              hub_log_warning("[HUB] v3 peer auth: bad signature length %d\n", sig_len);
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
              hub_log_warning("[HUB] v3 peer auth: signature verify FAILED for uuid %s "
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
              hub_log_warning("[HUB] v3 peer auth: timestamp skew %lds (max 60) for %s\n",
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
              hub_log_error("[HUB] Buffer promotion OOM for peer %s — "
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

            hub_log_info("[HUB] v3 Peer authenticated by Ed25519 signature: %s (%s)\n",
                    peer_name[0] ? peer_name : client->ip, peer_uuid);

            /* If this process is the product of an upgrade this peer drove,
             * close that run out now that there is a peer to tell. */
            hub_upgrade_report_pending(state, client);

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
          hub_log_error("[HUB] OOM decrypting frame from %s\n", client->ip);
          hub_disconnect_client(state, client);
          return false;
        }

        memcpy(tag, data + packet_len - GCM_TAG_LEN, GCM_TAG_LEN);

        int pl = aes_gcm_decrypt(data, packet_len - GCM_TAG_LEN,
                                 client->session_key, plain, tag);

        if (pl <= 0) {
          hub_log_warning("[HUB] GCM tag verification failed from authenticated client %s\n",
                  client->ip);
        }

        if (pl > 0) {
          unsigned char cmd = plain[0];
          g_hub_stats.rx_frames[cmd]++;
          g_hub_stats.rx_bytes[cmd] += (uint64_t)packet_len + 4;

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
              if (cmd == CMD_PEER_SYNC || cmd == CMD_PEER_BCAST) {
                process_peer_sync(state, payload_ptr, client->fd,
                                  cmd == CMD_PEER_BCAST);
              } else if (cmd == CMD_MESH_STATE) {
                process_mesh_state(state, client, payload_ptr);
              } else if (cmd == CMD_BOT_ROSTER) {
                process_bot_roster(state, client, payload_ptr);
              } else if (cmd == CMD_OP_FORWARD_REQUEST) {
                process_forward_op_request(state, client, payload_ptr);
              } else if (cmd == CMD_OP_FORWARD_GRANT) {
                process_forward_op_grant(state, client, payload_ptr);
              } else if (cmd == CMD_OP_FORWARD_FAILED) {
                process_forward_op_failed(state, client, payload_ptr);
              } else if (cmd == CMD_UPGRADE_FORGET) {
                process_peer_upgrade_forget(state, client, payload_ptr);
              } else if (cmd == CMD_BOT_RELAY_FWD) {
                process_peer_bot_relay(state, client, payload_ptr);
              } else if (cmd == CMD_ACTIVITY) {
                process_activity(state, client, payload_ptr);
              } else if (cmd == CMD_CHAN_FWD_REQUEST) {
                process_forward_chan_request(state, client, payload_ptr);
              } else if (cmd == CMD_CHAN_FWD_REPLY) {
                process_forward_chan_reply(state, client, payload_ptr);
              } else if (cmd == CMD_UPGRADE_PREPARE) {
                process_peer_upgrade_prepare(state, client, payload_ptr);
              } else if (cmd == CMD_UPGRADE_COMMIT) {
                process_peer_upgrade_commit(state, client, payload_ptr);
              } else if (cmd == CMD_UPGRADE_ABORT) {
                process_peer_upgrade_abort(state, client, payload_ptr);
              } else if (cmd == CMD_UPGRADE_READY) {
                /* A peer answering a run WE drive — for itself, or forwarded
                 * on behalf of a node in its own subtree (registered as a
                 * remote node reached through this peer).  If instead we are
                 * only a hop on someone else's run, pass it further up. */
                if (!hub_upgrade_relay_upstream(state, client,
                                                CMD_UPGRADE_READY, payload_ptr))
                  hub_upgrade_note_ready(state, payload_ptr, client);
              } else if (cmd == CMD_UPGRADE_RESULT) {
                if (!hub_upgrade_relay_upstream(state, client,
                                                CMD_UPGRADE_RESULT,
                                                payload_ptr))
                  hub_upgrade_note_result(state, payload_ptr);
              } else if (cmd == CMD_PEER_REKEY_BOT) {
                /* v3: per-bot independent keys.  Peer-forwarded bot rekey
                 * is rejected because it would carry a private key. */
                hub_log_warning("[HUB] Rejected CMD_PEER_REKEY_BOT from peer %s: "
                        "per-bot independent keys; rekey is bot-local.\n",
                        client->ip);
              } else if (cmd == CMD_SYNC_REQUEST) {
                /* Peer is asking us for our full state immediately.
                 * Send our full sync packet to just this requesting peer. */
                hub_log_debug("[MESH] Sync request from peer %s — sending full state\n",
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
                hub_log_warning("[HUB] Rejected CMD_UPDATE_PUBKEY from peer %s: "
                        "per-hub independent keys; private keys do not "
                        "cross hub boundaries.\n", client->ip);
              }
            }
          }
        } else {
          hub_log_warning("[HUB] GCM decrypt failed from %s\n", client->ip);
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
