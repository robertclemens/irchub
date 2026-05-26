#ifndef HUB_H
#define HUB_H

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define HUB_CONFIG_FILE ".irchub.cnf"
#define MAX_CLIENTS 100
#define MAX_BOTS 100
#define MAX_PEERS 10
#define MAX_CHAN 65
#define MAX_NICK 32
#define MAX_KEY 31
#define MAX_MASK_LEN 256
#define MAX_PASS 128
#define MAX_BUFFER 16384
#define SALT_SIZE 16 // FIXED: Increased from 8 to 16 bytes (128 bits)
#define GCM_IV_LEN 12
#define GCM_TAG_LEN 16
#define HEADER_SIZE 4
#define MAX_PENDING_BOTS 10
#define MAX_PENDING_OP_REQUESTS 500
#define PBKDF2_ITERATIONS 100000 // For config-file key derivation
/* Admin-password hashing: ~250 ms on commodity hardware; much slower than
 * config-key derivation since this is an interactive auth path not a startup
 * hot path. Format on disk: "$pbkdf2$<salt_b64>$<hash_b64>" */
#define ADMIN_PBKDF2_ITERATIONS 500000
#define ADMIN_PASS_HASH_PREFIX "$pbkdf2$"
#define HUB_PID_FILE ".irchub.pid"
#define HUB_PASS_FILE ".irchub.pass"
#define HUB_CONFIG_PURGE_DAYS_KEY "purge_days"
#define HUB_LOG_FILE ".irchub.log"
#define HUB_LOG_FILE_SIZE (10 * 1024 * 1024)  // 10MB

// Curve25519 key constants
#define ED25519_KEY_LEN    32
#define X25519_KEY_LEN     32
#define ED25519_SIG_LEN    64
#define COMBINED_KEY_LEN   64
#define COMBINED_KEY_B64   88

// Log levels
#define LOG_NONE    0
#define LOG_ERROR   1
#define LOG_WARNING 2
#define LOG_INFO    3
#define LOG_DEBUG   4

#define HUB_DEFAULT_LOG_LEVEL LOG_DEBUG

// Rate Limiting Settings
#define MAX_IP_RATE_LIMITS 500
#define MAX_CONNECTIONS_PER_IP 5
#define MAX_FAILED_AUTH_ATTEMPTS 3
#define FAILED_AUTH_BLOCK_DURATION 300  // 5 minutes
#define FAILED_AUTH_RESET_TIME 3600     // 1 hour
#define MAX_RECENT_PURGES 5             // Track recent PURGE cutoffs to prevent loops
#define PURGE_DEDUP_WINDOW 60            // Seconds to remember PURGE (prevents loops)

// OP_FORWARD_REQUEST deduplication — prevents packet storms
#define OP_FORWARD_TTL_SECONDS 60        // Drop forwarded OP requests older than 60s
#define MAX_SEEN_FORWARD_IDS   256       // LRU ring of recently-seen OP forward request IDs

// Timeout Settings
#define PING_INTERVAL 60
#define CLIENT_TIMEOUT 180
#define CONNECT_TIMEOUT 5
#define PEER_RECONNECT_INTERVAL 120

// Protocol Commands
#define CMD_PING 0x01
#define CMD_CONFIG_PUSH 0x02
#define CMD_CONFIG_PULL 0x03
#define CMD_CONFIG_DATA 0x04
#define CMD_UPDATE_PUBKEY 0x05
#define CMD_PEER_SYNC 0x06
#define CMD_MESH_STATE 0x07
#define CMD_SYNC_REQUEST 0x08  // Hub -> Hub: request peer to immediately send its full sync
#define CMD_INVITE_REQUEST 0x09 // Bot -> Hub: Request invite for nick into channel

#define CMD_ADMIN_AUTH 0x10
#define CMD_ADMIN_LIST_FULL 0x11
#define CMD_ADMIN_ADD 0x12
#define CMD_ADMIN_DEL 0x13
#define CMD_ADMIN_REGEN_KEYS 0x14
#define CMD_ADMIN_LIST_SUMMARY 0x15
#define CMD_ADMIN_GET_PENDING 0x16
#define CMD_ADMIN_APPROVE 0x17
#define CMD_ADMIN_ADD_PEER 0x18
#define CMD_ADMIN_LIST_PEERS 0x19
#define CMD_ADMIN_DEL_PEER 0x1A
#define CMD_ADMIN_GET_PUBKEY 0x1B
#define CMD_ADMIN_SET_PRIVKEY 0x1C
#define CMD_ADMIN_GET_PRIVKEY 0x1D
#define CMD_ADMIN_SET_PUBKEY 0x1E
#define CMD_ADMIN_SYNC_MESH 0x1F
#define CMD_ADMIN_CREATE_BOT 0x32     // 50 decimal
#define CMD_ADMIN_REKEY_BOT 0x20      // Generate new bot keypair
#define CMD_ADMIN_DISCONNECT_BOT 0x21 // Force disconnect bot
#define CMD_ADMIN_BOT_STATUS 0x22     // Get bot connection info
#define CMD_BOT_KEY_UPDATE 0x40       // Hub -> Bot: New private key update

// Global Config Management Commands
#define CMD_ADMIN_LIST_CHANNELS 0x23  // List all channels
#define CMD_ADMIN_ADD_CHANNEL 0x24    // Add channel
#define CMD_ADMIN_DEL_CHANNEL 0x25    // Remove channel
#define CMD_ADMIN_LIST_MASKS 0x26     // List admin masks
#define CMD_ADMIN_ADD_MASK 0x27       // Add admin mask
#define CMD_ADMIN_DEL_MASK 0x2B       // Remove admin mask
#define CMD_ADMIN_LIST_OPERS 0x2C     // List oper masks
#define CMD_ADMIN_ADD_OPER 0x2D       // Add oper mask
#define CMD_ADMIN_DEL_OPER 0x2E       // Remove oper mask
#define CMD_ADMIN_SET_ADMIN_PASS 0x2F // Change admin password
#define CMD_ADMIN_SET_BOT_PASS 0x30   // Change bot password
#define CMD_ADMIN_OP_USER 0x31        // Op a user in a channel

// Bot-to-Bot Op Commands (via Hub)
#define CMD_OP_REQUEST 0x28 // Bot -> Hub: Request ops from another bot
#define CMD_OP_GRANT 0x29   // Hub -> Bot: Grant ops to requesting bot
#define CMD_OP_FAILED 0x2A  // Hub -> Bot: Op request failed
#define CMD_OP_FORWARD_REQUEST 0x33 // Hub -> Hub: Forward OP request to peer
#define CMD_OP_FORWARD_GRANT 0x34   // Hub -> Hub: Forward grant response back
#define CMD_OP_FORWARD_FAILED 0x35  // Hub -> Hub: Forward failure back
#define CMD_PEER_REKEY_BOT 0x42     // Hub -> Hub: Forward bot rekey to peer
#define CMD_BOT_RELAY 0x50  // Bot -> Hub: relay encrypted bot command to target bot by UUID
#define CMD_BOT_MSG   0x51  // Hub -> Bot: relayed encrypted bot command payload

// Tombstone Purge Commands
#define CMD_ADMIN_PURGE_TOMBSTONES 0x36 // Purge tombstoned entries (payload: days or "immediate")
#define CMD_ADMIN_SET_PURGE_DAYS 0x41   // Configure automatic purge (payload: days, 0=disabled)

// Bind IP and IP Access Control Commands
#define CMD_ADMIN_SET_BIND_IP 0x37
#define CMD_ADMIN_LIST_ALLOWLIST 0x38
#define CMD_ADMIN_ADD_ALLOWLIST 0x39
#define CMD_ADMIN_DEL_ALLOWLIST 0x3A
#define CMD_ADMIN_LIST_DENYLIST 0x3B
#define CMD_ADMIN_ADD_DENYLIST 0x3C
#define CMD_ADMIN_DEL_DENYLIST 0x3D
#define CMD_ADMIN_SET_HUB_NAME 0x3E
#define CMD_ADMIN_SET_BIND_PORT 0x3F
#define CMD_ADMIN_SET_LOG_LEVEL 0x43    // Set log level (payload: level 0-4)
#define CMD_ADMIN_SET_LOG_SIZE  0x44    // Set log size limit (payload: size in bytes)
#define CMD_BOT_DELTA           0x45    // Bot -> Hub: single-key change (mesh.md Phase 4)

// Named Admin/Oper/Usermask Commands (v2)
#define CMD_ADMIN_ADD_ADMIN      0x46   // Create admin record + first mask (payload: name|pass|mask)
#define CMD_ADMIN_DEL_ADMIN      0x47   // Soft-delete admin + all its m| lines (payload: name)
#define CMD_ADMIN_ADD_OPER_RECORD 0x48  // Create oper record + first mask (payload: name|pass|mask)
#define CMD_ADMIN_DEL_OPER_RECORD 0x49  // Soft-delete oper + all its m| lines (payload: name)
#define CMD_ADMIN_ADD_USERMASK   0x4A   // Add mask to admin or oper by name (payload: name|mask)
#define CMD_ADMIN_DEL_USERMASK   0x4B   // Soft-delete one mask for named user (payload: name|mask)
#define CMD_ADMIN_SET_USERPASS   0x4C   // Change password for named user (payload: name|newpassword)
#define CMD_ADMIN_MATCH          0x4D   // Query all records for user or * (payload: name or *)
#define CMD_ADMIN_LIST_ADMINS    0x4E   // List all admin records
#define CMD_ADMIN_LIST_OPERS_V2  0x4F   // List all oper records
#define CMD_ADMIN_SET_PEER_PUBKEY 0x52  // Set/replace pubkey on existing peer (payload: UUID:PUBKEY_B64)

#define MESH_ANTI_ENTROPY_INTERVAL 300
#define MAX_BOT_ENTRIES 64

#define MAX_HUB_USER_RECORDS 40   // max combined admin + oper records
#define MAX_HUB_USER_MASKS   200  // max total usermask records across all users

/* ==========================================================================
 * Mesh transport tuning (see docs/mesh.md)
 * ========================================================================== */
#define LANE_COUNT                3
#define MAX_QUEUE_PER_LANE        256          /* per peer/client, per lane */
#define MAX_QUEUED_BYTES_PER_PEER (256 * 1024) /* hard cap across all lanes */
#define MAX_DELTA_SEEN            8192
#define BULK_SOFT_BUDGET_BPS      (32 * 1024)
#define DELTA_HARD_BUDGET_BPS     (64 * 1024)
#define BOT_DELTA_RATE_LIMIT      10           /* deltas/s/bot before suspect */
#define BOT_DELTA_RATE_WINDOW     30           /* seconds */

/* Lane indices (lower = higher priority). LANE_URGENT must be 0 so the drain
 * loop can rely on numeric ordering. */
typedef enum {
  LANE_URGENT = 0,   /* CMD_OP_REQUEST/GRANT/FAILED, CMD_OP_FORWARD_*  */
  LANE_DELTA  = 1,   /* small per-key deltas (b|uuid|h|...), global add/del */
  LANE_BULK   = 2,   /* CMD_PEER_SYNC, CMD_MESH_STATE, CMD_CONFIG_DATA  */
} lane_t;

typedef struct {
  char key[32];
  char value[1024];
  time_t timestamp;
} config_entry_t;

typedef struct {
  char   uuid[37];
  char   name[64];
  char   password[MAX_PASS];
  char   type;         /* 'a' = admin, 'o' = oper */
  bool   is_active;    /* false when action == "del" */
  time_t last_seen;
  time_t timestamp;
} hub_user_record_t;

typedef struct {
  char   uuid[37];     /* matches hub_user_record_t.uuid */
  char   mask[MAX_MASK_LEN];
  bool   is_active;    /* false when action == "del" */
  time_t last_used;    /* 0 = never used */
  time_t timestamp;
} hub_mask_record_t;

typedef struct {
  char uuid[64];
  config_entry_t entries[MAX_BOT_ENTRIES];
  int entry_count;
  bool is_active;
  time_t last_sync_time;
} bot_config_t;

typedef struct {
  char uuid[64];
  char nick[32];
  char ip[64];
  time_t last_attempt;
} pending_bot_t;

typedef struct {
  char request_id[64];     // Unique ID for this request
  char requester_uuid[64]; // UUID of bot requesting ops
  char target_uuid[64];    // UUID of bot that should grant ops
  char channel[MAX_CHAN];  // Channel where ops are needed
  int origin_fd;           // FD to send response back to (-1 if local bot)
  time_t timestamp;        // When request was created
  bool active;             // Whether this slot is in use
} pending_op_request_t;

typedef struct {
  char ip[64];
  int active_connections;    // Current active connections from this IP
  int failed_auth_count;     // Failed authentication attempts
  time_t last_failed_auth;   // Timestamp of last failed auth
  time_t blocked_until;      // Temporary block expiration (0 if not blocked)
  time_t first_seen;         // For cleanup of old entries
} ip_rate_limit_t;

typedef struct {
  char ip[64];              // Configured/advertised IP
  int port;
  char uuid[64];            // Remote peer's UUID
  char friendly_name[64];   // Remote peer's friendly name
  char remote_ip[64];       // Actual connection IP (from socket)
  bool connected;
  int fd;
  int remote_connected_count;
  int remote_total_peers;
  time_t last_mesh_report;
  char last_gossip[MAX_BUFFER];

  /* v2 peer auth: per-peer Curve25519 public keys. When has_pubkey is true
   * the handshake uses Ed25519-signature-based auth and drops the shared
   * admin_password from the wire. */
  unsigned char ed_pub[ED25519_KEY_LEN];
  unsigned char x25519_pub[X25519_KEY_LEN];
  bool has_pubkey;
} hub_peer_config_t;

typedef enum { CLIENT_BOT, CLIENT_ADMIN, CLIENT_HUB } client_type_t;

/* Queued outbound message — pre-encryption.  payload is malloc'd. */
typedef struct queued_msg {
  uint8_t            cmd;                /* protocol opcode (CMD_*) */
  lane_t             lane;               /* which lane this lives in (for accounting) */
  /* Coalesce key: typically "<origin_hub_uuid>|<key>|<bot_uuid>" — up to
   * 36 + 16 + 36 + separators ≈ 90 chars. Sized with headroom. */
  char               coalesce_key[160];
  uint64_t           lamport_seq;        /* monotonic per origin_hub_uuid */
  char               origin_hub_uuid[64];
  int                payload_len;
  unsigned char     *payload;            /* malloc'd plaintext */
  struct queued_msg *next;
} queued_msg_t;

typedef struct {
  queued_msg_t *head;
  queued_msg_t *tail;
  int           count;
  int           bytes;     /* sum of payload_len in this lane */
} queue_lane_t;

typedef enum {
  BOT_AUTH_IDLE = 0,
  BOT_AUTH_UUID_RECEIVED,
  BOT_AUTH_CHALLENGE_SENT,
  BOT_AUTH_SIGNATURE_RECEIVED,
  BOT_AUTH_COMPLETE
} bot_auth_state_t;

typedef struct {
  int fd;
  char ip[64];
  char id[64];
  unsigned char session_key[32];
  bool authenticated;
  client_type_t type;
  time_t last_seen;
  time_t last_pong_sent;
  unsigned char recv_buf[MAX_BUFFER];
  bot_auth_state_t bot_auth_state;
  unsigned char challenge[32];
  unsigned char bot_eph_x25519_priv[32];
  unsigned char bot_eph_x25519_pub[32];
  bool bot_eph_priv_set;
  int recv_len;
  char admin_connect_ip[64];   // IP that hub_admin used to connect
  int admin_connect_port;      // Port that hub_admin used to connect

  /* ---- Outbound queue (per-lane FIFOs, drained on POLLOUT) ---- */
  queue_lane_t out_lanes[LANE_COUNT];
  int          out_total_bytes;

  /* In-flight cipher buffer for partial writes.  When non-empty the FD must
   * be watched for writability until offset == len, before any new message
   * is encrypted. */
  unsigned char writing_buf[MAX_BUFFER + 64];
  int           writing_len;
  int           writing_offset;

  /* Per-peer/client byte-rate accounting (1-second window). */
  time_t        bw_window_start;
  int           bw_bytes_in_window;
} hub_client_t;

// Track recently processed PURGE messages to prevent feedback loops
typedef struct {
  time_t cutoff;       // PURGE cutoff timestamp
  time_t received_at;  // When this PURGE was received/processed
} recent_purge_t;

// Track recently seen OP_FORWARD_REQUEST IDs to prevent packet storms
typedef struct {
  char   request_id[64]; // Unique request ID
  time_t seen_at;        // When we first processed this request
} seen_forward_t;

/* Loop-prevention seen-set: highest lamport_seq observed per (origin, bot). */
typedef struct {
  char     origin_hub_uuid[64];
  char     bot_uuid[64];
  uint64_t max_seq_seen;
  time_t   last_seen_at;
} delta_seen_t;

typedef struct {
  int listen_fd;
  int port;
  char bind_ip[64];          // IP this hub advertises itself as in mesh
  char hub_uuid[64];         // This hub's UUID
  char hub_friendly_name[64]; // This hub's friendly name
  char admin_password[128];
  /* config_pass holds the plaintext AES-GCM config-file password for the
   * lifetime of the process (needed on every config write).  It is mlock'd
   * so the OS cannot page it to swap, and OPENSSL_cleanse'd at shutdown.
   *
   * Threat model: mlock prevents swap-file / hibernate leaks.  A root process
   * with ptrace or /proc/<pid>/mem access CAN still read this field while the
   * hub is running — that is unavoidable without hardware-backed key storage.
   * The real defences are OS-level: ptrace_scope, process isolation, and
   * filesystem permissions on the config file itself. */
  char config_pass[128];

  unsigned char hub_ed25519_priv[32];
  unsigned char hub_ed25519_pub[32];
  unsigned char hub_x25519_priv[32];
  unsigned char hub_x25519_pub[32];
  bool hub_keys_loaded;

  hub_client_t *clients[MAX_CLIENTS];
  int client_count;

  bot_config_t bots[MAX_BOTS];
  int bot_count;

  // GLOBAL CONFIG STORE (Shared by all bots)
  config_entry_t global_entries[MAX_BOT_ENTRIES];
  int global_entry_count;

  // Named admin/oper records and their usermasks
  hub_user_record_t user_records[MAX_HUB_USER_RECORDS];
  int user_record_count;
  hub_mask_record_t mask_records[MAX_HUB_USER_MASKS];
  int mask_record_count;

  hub_peer_config_t peers[MAX_PEERS];
  int peer_count;

  pending_bot_t pending[MAX_PENDING_BOTS];
  int pending_head;
  int pending_count;

  pending_op_request_t pending_op_requests[MAX_PENDING_OP_REQUESTS];

  ip_rate_limit_t ip_limits[MAX_IP_RATE_LIMITS];
  int ip_limits_count;

  int purge_days_setting;  // Days threshold for tombstone purge (0 = disabled)
  int pid_fd;  // File descriptor for PID file lock
  volatile bool running;

  // PURGE deduplication: prevent feedback loops in peer mesh
  recent_purge_t recent_purges[MAX_RECENT_PURGES];
  int recent_purge_count;
  time_t last_scheduled_purge;  // Timestamp of last scheduled purge this hub initiated

  // OP_FORWARD_REQUEST deduplication: LRU ring prevents infinite re-broadcast storms
  seen_forward_t seen_forwards[MAX_SEEN_FORWARD_IDS];
  int seen_forward_head;  // Next slot to write (ring index)

  int log_level;       // Current log level (LOG_NONE, LOG_ERROR, etc.)
  int log_max_size;    // Max log file size in bytes (default 10MB)

  /* Debounced config write: set dirty flag instead of writing immediately.
   * hub_maintenance flushes at most once every CONFIG_WRITE_DEBOUNCE_S seconds.
   * This prevents N PBKDF2(100K) calls when N peer syncs arrive in a burst. */
  bool config_dirty;
  time_t last_config_write;
  bool mesh_state_dirty;    /* set on peer connect/disconnect; clears after gossip */
  bool anti_entropy_due;    /* set to force anti-entropy on next hub_maintenance tick */

  /* Mesh transport: monotonic Lamport sequence stamped onto outgoing deltas
   * (carried as the trailing field of the wire format). On load from disk we
   * bump this past any plausibly recent value to keep monotonicity even if
   * the system clock or stored value lags. */
  uint64_t next_lamport_seq;

  /* Loop prevention: deltas already observed per (origin_hub_uuid, bot_uuid).
   * LRU-evicted past MAX_DELTA_SEEN. */
  delta_seen_t delta_seen[MAX_DELTA_SEEN];
  int          delta_seen_count;
} hub_state_t;

#define CONFIG_WRITE_DEBOUNCE_S 5

// --- Prototypes ---
void hub_log(const char *format, ...);

// Log level filtering macros - these check the log level before calling hub_log
#define hub_log_error(format, ...) \
    do { if (g_state && g_state->log_level >= LOG_ERROR) hub_log("[ERROR] " format, ##__VA_ARGS__); } while(0)
#define hub_log_warning(format, ...) \
    do { if (g_state && g_state->log_level >= LOG_WARNING) hub_log("[WARNING] " format, ##__VA_ARGS__); } while(0)
#define hub_log_info(format, ...) \
    do { if (g_state && g_state->log_level >= LOG_INFO) hub_log("[INFO] " format, ##__VA_ARGS__); } while(0)
#define hub_log_debug(format, ...) \
    do { if (g_state && g_state->log_level >= LOG_DEBUG) hub_log("[DEBUG] " format, ##__VA_ARGS__); } while(0)

bool hub_config_load(hub_state_t *state, const char *password);
void hub_config_write(hub_state_t *state);
bool hub_admin_hash_password(const char *plaintext, char *out, size_t out_len);
bool hub_admin_verify_password(const char *plaintext, const char *stored);

// Curve25519 crypto functions
bool hub_crypto_generate_combined_keypair(unsigned char priv_out[64],
                                          unsigned char pub_out[64]);
void hub_crypto_split_combined(const unsigned char in[64],
                               unsigned char ed_out[32],
                               unsigned char x_out[32]);
bool hub_crypto_ed25519_sign(const unsigned char ed_priv[32],
                             const unsigned char *msg, size_t msg_len,
                             unsigned char sig_out[64]);
bool hub_crypto_ed25519_verify(const unsigned char ed_pub[32],
                               const unsigned char *msg, size_t msg_len,
                               const unsigned char sig[64]);
bool hub_crypto_x25519_derive(const unsigned char x_priv[32],
                              const unsigned char x_peer_pub[32],
                              unsigned char shared_out[32]);
bool hub_crypto_hkdf_sha256(const unsigned char *ikm, size_t ikm_len,
                            const unsigned char *salt, size_t salt_len,
                            const unsigned char *info, size_t info_len,
                            unsigned char *out, size_t out_len);

// AES-GCM
int aes_gcm_decrypt(const unsigned char *input, int input_len,
                    const unsigned char *key, unsigned char *output,
                    unsigned char *tag);
int aes_gcm_encrypt(const unsigned char *plain, int plain_len,
                    const unsigned char *key, unsigned char *output,
                    unsigned char *tag);

// Rate limiting and IP access control functions
bool is_ip_allowed(hub_state_t *state, const char *ip);
void increment_active_connections(hub_state_t *state, const char *ip);
void decrement_active_connections(hub_state_t *state, const char *ip);
void cleanup_old_ip_limits(hub_state_t *state);
bool check_ip_access_lists(hub_state_t *state, const char *ip);

void hub_storage_init(void);
bool hub_storage_update_entry(hub_state_t *state, const char *uuid,
                              const char *key, const char *value,
                              const char *extra, const char *op, time_t ts);
bool hub_storage_update_global_entry(hub_state_t *state, const char *key,
                                     const char *value, const char *extra,
                                     const char *op, time_t ts);
bool hub_storage_delete(hub_state_t *state, const char *uuid);
int hub_storage_get_full_list(hub_state_t *state, char *buffer, int max_len);
int hub_storage_get_summary_list(hub_state_t *state, char *buffer, int max_len);

void hub_generate_sync_packet(hub_state_t *state, char *buffer, int max_len);
void hub_generate_bot_payload(hub_state_t *state, const char *uuid,
                              char *buffer, int max_len);
void hub_broadcast_sync_to_peers(hub_state_t *state, const char *payload,
                                 int exclude_fd);

// cutoff==0: purge all tombstones; cutoff>0: purge tombstones older than cutoff
int hub_execute_purge(hub_state_t *state, time_t cutoff,
                      char *log_out, int log_max_len);

// Leader election: Check if this hub should initiate scheduled purges
// (Hub with smallest UUID in connected mesh leads)
bool hub_should_initiate_scheduled_purge(hub_state_t *state);

bool hub_handle_client_data(hub_state_t *state, hub_client_t *client);
bool handle_bot_authentication(hub_state_t *state, hub_client_t *client,
                               unsigned char *data, int packet_len);
void hub_disconnect_client(hub_state_t *state, hub_client_t *c);
void hub_broadcast_mesh_state(hub_state_t *state);

/* ---- Mesh transport: per-peer outbound queue (see docs/mesh.md) ---- */

/* Build a queued message from an opcode + plaintext payload.  Caller passes
 * payload data which is copied; ownership of the returned struct is
 * transferred to peer_enqueue.  Returns NULL on alloc failure. */
queued_msg_t *queued_msg_new(uint8_t cmd, lane_t lane,
                             const unsigned char *payload, int payload_len);
void queued_msg_set_coalesce(queued_msg_t *m, const char *origin_hub_uuid,
                             uint64_t lamport_seq, const char *coalesce_key);
void queued_msg_free(queued_msg_t *m);

/* Enqueue m on peer's lane.  Performs coalescing if m->coalesce_key[0] != 0
 * and a same-key message exists in the lane (replaces in place, frees the
 * passed-in m).  Returns true on success.  On URGENT lane overflow, returns
 * false and the caller should treat the peer as failed. */
bool peer_enqueue(hub_client_t *peer, queued_msg_t *m);

/* Drain queued messages to the socket; called when select() reports
 * writable.  Encrypts each message with peer->session_key just before send,
 * tracks partial writes via peer->writing_*. */
void peer_drain_writable(hub_state_t *state, hub_client_t *peer);

/* True if peer has anything pending — either a partial in-flight write or
 * any non-empty lane.  Used by main loop to decide whether to set POLLOUT. */
bool peer_has_pending_writes(hub_client_t *peer);

/* Free all queued messages (called from hub_disconnect_client). */
void peer_queue_destroy(hub_client_t *peer);

/* Allocate the next outgoing Lamport sequence number for this hub. */
uint64_t hub_next_lamport_seq(hub_state_t *state);

/* Loop-prevention seen-set helpers.  Returns true if (origin, bot, seq) is
 * new (and updates the set); false if seq <= last seen. */
bool hub_delta_seen_check_and_update(hub_state_t *state,
                                     const char *origin_hub_uuid,
                                     const char *bot_uuid,
                                     uint64_t seq);

// Bot credential generation
bool hub_crypto_generate_bot_creds(char **out_uuid, char **out_priv_b64,
                                   char **out_pub_b64);
void hub_set_config_pass(hub_state_t *s, const char *pass);
void hub_get_config_pass(const hub_state_t *s, char *out, size_t len);
void secure_wipe(void *ptr, size_t len);
void generate_uuid_v4(char *buffer, size_t len);

char *base64_encode(const unsigned char *input, int length);
unsigned char *base64_decode(const char *input, int *out_len);

#endif
