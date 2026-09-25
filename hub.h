#ifndef HUB_H
#define HUB_H

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>   /* PATH_MAX for hub_state_t.executable_path */
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
#define MAX_OPT_FLAGS 32

/* Network option flag letters (synced via the 'opt|' record).
 * Each option is a single [a-zA-Z0-9] character; the active set lives in
 * hub_state_t.opt_flags and replicates to bots in CMD_CONFIG_DATA / sync. */
#define OPT_HUB_ONLY_MUTATIONS 'h'
/* Set for the duration of a network upgrade window: config mutations (admin
 * commands + bot deltas) are refused until every node reports success and the
 * verification pass completes, or the run aborts.  Task 6 (upgrade freeze). */
#define OPT_CONFIG_FROZEN 'F'
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
/* Passwordless (docs/passwordless.md).  Admins/opers/bots authenticate with
 * their Curve25519 combined keys only; the config-file password is the one
 * password left.  A bot advertises protocol BOT_PROTO_PASSWORDLESS as "v|2"
 * in its CMD_CONFIG_PUSH; until a connection has done so it is sent legacy
 * record shapes with an empty password slot (old bots then fail closed). */
#define BOT_PROTO_PASSWORDLESS 2
#define KEY_FP_LEN 19              /* "ab12:cd34:ef56:7890" */
#define HUB_PID_FILE ".irchub.pid"
#define HUB_PASS_FILE ".irchub.pass"
#define HUB_CONFIG_PURGE_DAYS_KEY "purge_days"
#define HUB_LOG_FILE ".irchub.log"
#define HUB_LOG_FILE_SIZE (10 * 1024 * 1024)  // 10MB default; log_size| overrides
/* CMD_ADMIN_SET_LOG_SIZE / log_size| bounds (ircbot's L| takes the same). */
#define HUB_LOG_SIZE_MIN 1024
#define HUB_LOG_SIZE_MAX (1024 * 1024 * 1024)

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

/* D1 — churn-based (connect/close flood) throttle. Concurrency + failed-auth
 * limits don't catch a rapid connect/close flood; this sliding window does.
 * More than CHURN_MAX_CONNS new connections from one IP within
 * CHURN_WINDOW_SEC seconds triggers a CHURN_BLOCK_SEC temporary block. */
#define CHURN_WINDOW_SEC 10
#define CHURN_MAX_CONNS  30
#define CHURN_BLOCK_SEC  30
/* PURGE loop suppression.  A purge is flooded to every peer and forwarded on,
 * so on a big mesh each hub sees many copies, some of them minutes late when
 * peer queues back up.  An id is random and never reused, so it is remembered
 * long and in quantity: with 5 ids for 60 s, a late copy or one pushed out by
 * newer purges was taken as new, re-applied and re-flooded, and a 10-hub
 * mesh kept a dozen purges circulating for good.  An id-less purge (a hub
 * that predates the id) can only be told apart by time, so it keeps the short
 * window — a longer one would swallow a second, deliberate purge now. */
/* The full config push to bots is coalesced: however many updates land in a
 * burst (a mass reconnect sends two per bot, and each reaches every hub), the
 * bots get one push per this many seconds, carrying the latest state. */
#define BOT_CONFIG_PUSH_COALESCE 1
#define MAX_RECENT_PURGES 64
#define PURGE_DEDUP_WINDOW 3600          // seconds an id'd purge is remembered
#define PURGE_DEDUP_WINDOW_LEGACY 60     // seconds an id-less purge is remembered
#define PURGE_ID_HEX 16                  // PURGE|<cutoff>|<id>: 8 random bytes, hex

// OP_FORWARD_REQUEST deduplication — prevents packet storms
#define OP_FORWARD_TTL_SECONDS 60        // Drop forwarded OP requests older than 60s
#define MAX_SEEN_FORWARD_IDS   256       // LRU ring of recently-seen OP forward request IDs

/* Keepalive traffic (CMD_PING and the PONG it draws) is pure noise in the hub
 * log: with every bot and peer exchanging one a minute it buries the lines
 * that matter.  true = never log it; false = log it like any other frame.
 * Only the logging is suppressed -- the keepalives themselves still run.
 * Mirrors HIDEPINGPONG in ircbot/bot.h. */
#define HIDEPINGPONG true

/* This hub's version, reported in the bots tree beside each hub node and the
 * one every upgrade comparison is made against.  Keep in step with VERSION in
 * the Makefile; -D-overridable so a release build can stamp its own version
 * without editing the tree (mirrors BOT_VERSION in ircbot/bot.h). */
#ifndef HUB_VERSION
#define HUB_VERSION "2.4.1"
#endif

/* Signed-release channel for the hub (irchub-releases).  Same Ed25519 key as
 * ircbot's BOT_UPDATE_PUBKEY_B64: one key signs both repos.  All of these are
 * -D-overridable (the testnet injects a throwaway signing key), and at RUNTIME
 * IRCHUB_UPDATE_BASE repoints the updater at a local irchub-releases tree.
 * An empty pubkey DISABLES hub updates (fail-closed).
 *
 * HUB_UPDATE_BASE is the tree ROOT; one variant subdirectory below it holds
 * that build's manifest.  Keeping the root separate is what lets a
 * hub-orchestrated upgrade flip a hub between the C and Rust builds, exactly
 * as it does for a bot: hub_update_commit() appends the variant it was told
 * to install.  Mirrors BOT_UPDATE_BASE in ircbot/bot.h. */
#ifndef HUB_UPDATE_BASE
#define HUB_UPDATE_BASE                                                        \
  "https://raw.githubusercontent.com/robertclemens/irchub-releases/main/"      \
  "irchub"
#endif
/* The variant THIS build is.  The Rust hub answers "rs". */
#ifndef HUB_UPDATE_VARIANT
#define HUB_UPDATE_VARIANT "c"
#endif
#ifndef HUB_UPDATE_URL
#define HUB_UPDATE_URL HUB_UPDATE_BASE "/" HUB_UPDATE_VARIANT "/releases.txt"
#endif
/* Detached Ed25519 signature over releases.txt (raw 64-byte sig, base64). */
#ifndef HUB_UPDATE_SIG_URL
#define HUB_UPDATE_SIG_URL HUB_UPDATE_BASE "/" HUB_UPDATE_VARIANT "/releases.sig"
#endif
#ifndef HUB_UPDATE_PUBKEY_B64
#define HUB_UPDATE_PUBKEY_B64 "qkXMh/F8TC+cnKuIwrP5TJIynfrLBD+MDUwvkyh9lBU="
#endif
/* Hand-off note written just before a hub-driven upgrade execs the new binary:
 * the restarted process has no memory of the run that replaced it, so it reads
 * the upgrade id from here and answers CMD_UPGRADE_RESULT. */
#define HUB_UPGRADE_MARKER_FILE ".irchub.upgrade"
/* Retained previous binary/config, kept (not deleted) after an upgrade so
 * CMD_UPGRADE_ABORT can put this hub back. */
#define HUB_UPGRADE_PREV_SUFFIX ".prev"
/* The generated installer, written 0700 and exec'd once the old process has
 * let go of its pid lock. */
#define HUB_UPGRADE_SCRIPT "hub_upgrade.sh"
/* Ceilings on what the updater will pull down.  A manifest is a few KB and an
 * unbounded realloc loop against a hostile or broken server is a
 * memory-exhaustion hole; the archive cap is enforced by libcurl itself. */
#define HUB_UPDATE_MAX_MANIFEST (1024 * 1024)
#define HUB_UPDATE_MAX_ARCHIVE (256L * 1024 * 1024)
#define HUB_UPDATE_FETCH_TIMEOUT 300L

// Timeout Settings
#define PING_INTERVAL 60
#define CLIENT_TIMEOUT 180
#define CONNECT_TIMEOUT 5

/* D4 — pre-authentication handshake timeout. An accepted connection that has
 * not authenticated within this window is dropped, freeing its MAX_CLIENTS
 * slot far sooner than CLIENT_TIMEOUT (180s). Outbound CLIENT_HUB peers are
 * exempt (they are trusted, operator-configured endpoints). */
#define PREAUTH_TIMEOUT_SEC 10

/* D4b — extended pre-auth grace for interactive admin logins. A connection
 * that has spoken the ADMIN-HELLO discovery probe has positively identified
 * itself as hub_admin, but the sealed-box ADMIN auth that follows is gated on
 * a human typing an admin name + password at the prompt. 10s is too tight for
 * manual entry, so a HELLO-marked connection gets this longer window instead.
 * Bots, peers, and unidentified slowloris connections keep PREAUTH_TIMEOUT_SEC.
 * Still bounded (and < CLIENT_TIMEOUT) so an idle admin slot is not held open
 * indefinitely; the connection also remains subject to churn/concurrency caps. */
#define PREAUTH_ADMIN_TIMEOUT_SEC 120

/* D2 — two-tier client buffers. Unauthenticated clients get a small buffer
 * (enough for the handshake); it is grown to MAX_BUFFER on successful auth.
 * This keeps the unauthenticated footprint ~8KB instead of ~33KB. */
#define PREAUTH_BUF_SIZE 4096
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
/* 0x2F (SET_ADMIN_PASS) and 0x30 (SET_BOT_PASS) are retired — passwordless.
 * Kept as names so the hub can answer "retired"; never reuse the values. */
#define CMD_ADMIN_SET_ADMIN_PASS 0x2F // RETIRED
#define CMD_ADMIN_SET_BOT_PASS 0x30   // RETIRED
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
#define CMD_ADMIN_SET_USERPASS   0x4C   // RETIRED (passwordless); never reuse
#define CMD_ADMIN_MATCH          0x4D   // Query all records for user or * (payload: name or *)
#define CMD_ADMIN_LIST_ADMINS    0x4E   // List all admin records
#define CMD_ADMIN_LIST_OPERS_V2  0x4F   // List all oper records
#define CMD_ADMIN_SET_PEER_PUBKEY 0x52  // Set/replace pubkey on existing peer (payload: UUID:PUBKEY_B64)
#define CMD_ADMIN_SET_OPT_FLAGS   0x53  // Set network opt flag string (payload: <letters>)
#define CMD_ADMIN_GET_OPT_FLAGS   0x54  // Get current network opt flag string
#define CMD_ADMIN_SET_USERKEY     0x55  // Replace a user's public key (payload: name|pubkey_b64)

/* ---- Bot presence (the 'bots' tree) --------------------------------------
 * Deliberately OUTSIDE the config store.  Version / IRC server / uptime are
 * volatile runtime facts: parking them in the LWW config would persist them to
 * disk, replicate them with tombstones, drag them through the purge policy and
 * leave a dead hub's bots reading "online, uptime 40d" forever.  They also do
 * not belong in the per-bot ingest whitelist {t,n,h,pub,seen,d} -- that bound
 * is what makes the payload ceilings above provable, and it stays untouched.
 *
 * So presence rides its own gossip: every hub reports the bots currently
 * connected to IT, peers hold that in memory only, and an entry nobody has
 * refreshed within BOT_ROSTER_TTL is simply dropped.  Nothing to tombstone,
 * nothing to purge, and a hub that dies ages out of the tree on its own.
 * Identity (nick, last-seen) still comes from the persisted config -- read
 * only -- so disconnected bots can still be listed with a real timestamp. */
#define CMD_BOT_PRESENCE 0x56  // Bot -> Hub: version|server|started|variant (volatile)
#define CMD_BOT_ROSTER   0x57  // Hub <-> Hub: presence gossip (volatile)
#define CMD_BOT_TREE     0x58  // Hub -> Bot: rendered tree rows (volatile)

/* ---- Channel-access requests (unban / invite / key) ----------------------
 * A bot locked out of a managed channel (474 banned, 473 invite-only, 475 bad
 * key) asks the mesh to let it back in.  Routed exactly like CMD_OP_REQUEST:
 * stamp a request id, broadcast the action to local bots, forward to peers
 * under the same id (dropped on the second sighting via the shared
 * seen_forwards ring), and route any reply back down the fd the request
 * arrived on.  Only `key` produces a reply.
 *
 * The requesting bot supplies only `kind|channel`.  The hub fills in the
 * requester's nick and hostmask from its own `n`/`h` records for that
 * authenticated UUID, so a bot can neither request an unban for a mask that
 * is not its own nor have a third party invited.  Mirrors ircbot/bot.h. */
#define CMD_CHAN_REQUEST 0x59 // Bot -> Hub: kind|channel
#define CMD_CHAN_ACTION  0x5A // Hub -> Bot: id|kind|chan|uuid|nick|hostmask
#define CMD_CHAN_REPLY   0x5B // Bot <-> Hub: id|kind|chan|status|data
#define CMD_CHAN_FWD_REQUEST 0x5C // Hub -> Hub: forward the action
#define CMD_CHAN_FWD_REPLY   0x5D // Hub -> Hub: route a reply home

/* --- Network-wide upgrade coordination (hub_admin-initiated rolling upgrade).
 * Fan PREPARE out to bots + peer hubs, collect READY/UNABLE acks routed home by
 * origin_fd (like CMD_OP_*), then COMMIT node-by-node and await RESULT.  Mirror
 * in ircbot/bot.h, irchub.rs/consts.rs, ircbot.rs/consts.rs and
 * docs/ARCHITECTURE.md.  Payloads are '|'-delimited text. */
#define CMD_UPGRADE_PREPARE      0x5E // Hub -> Bot/Hub: id|ver|variant|kind|min_from|base
#define CMD_UPGRADE_READY        0x5F // Bot/Hub -> Hub: id|uuid|cur|variant|arch|libc|ok|reason
#define CMD_UPGRADE_COMMIT       0x60 // Hub -> node: id|ver|variant
#define CMD_UPGRADE_RESULT       0x61 // node -> Hub: id|uuid|status|new_ver|detail
#define CMD_UPGRADE_ABORT        0x62 // Hub -> all: id|reason
#define CMD_ADMIN_UPGRADE_NET    0x63 // hub_admin -> Hub: ver|variant|kind|min_from|base
#define CMD_ADMIN_UPGRADE_STATUS 0x64 // hub_admin -> Hub: ""=poll, "abort"=stop+roll back

/* Sealed bot-to-bot relay across hubs.  CMD_BOT_RELAY names its target by
 * uuid only; when that bot is not connected here the hub stamps the frame
 * with a request id and floods it to its peers, each of which delivers it
 * (as CMD_BOT_MSG) if the target is one of its own bots and otherwise passes
 * it on minus the link it came in on.  The id goes through the shared
 * seen_forwards ring, so a cycle in the peer graph cannot keep it moving,
 * and a frame older than BOT_RELAY_FWD_TTL is dropped.  The sender uuid is
 * the one the ORIGIN hub authenticated; the target bot still checks the
 * sealed payload against that sender's key (AAD binding), so a peer cannot
 * forge a command.  Hub <-> hub only: bots never see this opcode.
 * Payload: id|origin_ts|sender_uuid|target_uuid|cipher:tag */
#define CMD_BOT_RELAY_FWD 0x65
#define BOT_RELAY_FWD_TTL 30 /* seconds a forwarded relay stays deliverable */

/* Drop the roll-up plan mesh-wide.  Every hub that followed a run keeps that
 * run's plan in its own .irchub.cnf (a hub-local `rollup|` line) and walks any
 * bot that comes back behind it up to the target; an admin's
 * CMD_ADMIN_UPGRADE_STATUS "forget" drops it on the hub it is logged into and
 * floods this frame so every other hub drops its copy too.  Loop-suppressed
 * by the seen_forwards ring like CMD_BOT_RELAY_FWD, refused while the config
 * freeze (a run in flight) is up.  Hub <-> hub only.
 * Payload: id|origin_ts */
#define CMD_UPGRADE_FORGET 0x66
#define UPGRADE_FORGET_TTL 60 /* seconds a forwarded forget stays valid */

/* A config broadcast: the payload of CMD_PEER_SYNC, sent by a hub to EVERY
 * peer it is linked to (minus the one it forwards for).  What it adds is that
 * fact, which the receiver may rely on when it forwards what it accepted: a
 * peer the sender is linked to right now already has the frame first hand,
 * so the forwarder skips it (hub_broadcast_sync_to_peers' split horizon).  On
 * a full mesh that turns one copy of every accepted update from every hub
 * into none.  Point-to-point syncs (the reply to CMD_SYNC_REQUEST, the sync a
 * new link opens with) stay CMD_PEER_SYNC: a forwarder must reach everyone
 * with those.  Sent only to a peer whose roster gossip carries l| lines, i.e.
 * one that knows this opcode; an older peer gets CMD_PEER_SYNC as before. */
#define CMD_PEER_BCAST 0x67
/* After a peer link drops, ask the remaining peers for a full sync this many
 * seconds later: a forwarder may have skipped us on the strength of that
 * link in the moment before the drop reached its gossip. */
#define SYNC_RESYNC_AFTER_LINK_LOSS 5

/* Admin -> Hub: this hub's traffic counters since it started (read-only,
 * empty payload).  Reply lines, zero rows left out:
 *   stats|up=<s>
 *   cfg|sent=<n>|same=<n>|lost=<n>        full config pushes to bots
 *   sync|frames=<n>|noop=<n>|records=<n>|applied=<n>   PEER_SYNC/BCAST in
 *   op|0x<cc>|rx=<frames>/<bytes>|tx=<frames>/<bytes>
 * "same" = a push skipped because that bot was already sent the identical
 * config; "lost" = a queued push dropped on overflow (that bot is re-sent the
 * next one in full).  rx counts every authenticated frame this hub decrypted,
 * tx every frame it sent from its outbound queues (the ping/pong keepalive and
 * direct admin/bot replies are not queued and not counted). */
#define CMD_ADMIN_STATS 0x68

/* ---- Activity (last seen / last used) -----------------------------------
 * An admin/oper's last_seen and a usermask's last_used are max-merged values
 * OUTSIDE the LWW config: they only ever rise, a rise is never a config
 * change (no record forward, no bot push), and every hub converges on the
 * latest time any node saw.  A node reports a record only on its first use
 * within an ACTIVITY_BUCKET (a clock hour), with that use's exact time; later
 * uses in the same bucket stay local.  A hub that receives CMD_ACTIVITY keeps
 * max(stored, ts) and forwards to its other peers only the lines that raised
 * its value, so a flood dies out without a seen-set.  PEER_SYNC / CONFIG_PUSH
 * max-merge the same fields as a repair path (anti-entropy).
 * Mirrors ircbot/bot.h, irchub.rs + ircbot.rs consts.rs.
 *
 *   CMD_ACTIVITY        bot -> hub, hub <-> hub.  Lines:
 *                         a|<user_uuid>|<ts>          (admin or oper)
 *                         m|<user_uuid>|<mask>|<ts>
 *   CMD_ACTIVITY_QUERY  bot -> hub: <req_id>|users   or
 *                                   <req_id>|masks|<user_uuid or *>
 *                       ("masks" answers that user's a| line too)
 *   CMD_ACTIVITY_REPLY  hub -> bot: first line <req_id>|<more>, then a|/m|
 *                       lines; chunked under MAX_BUFFER, more=0 on the last. */
#define CMD_ACTIVITY       0x69
#define CMD_ACTIVITY_QUERY 0x6A
#define CMD_ACTIVITY_REPLY 0x6B
#define ACTIVITY_BUCKET    3600 /* report the first use per this many seconds */
/* A reported time this far ahead of our clock is refused: activity only
 * rises, so one bogus future stamp would stick for good. */
#define ACTIVITY_MAX_FUTURE 300
#define ACTIVITY_REQ_ID_MAX 32

#define MAX_PENDING_CHAN_REQUESTS 200
#define CHAN_REQUEST_TIMEOUT 45   // Reap a pending request with no reply

/* ---- Network upgrade run (CMD_UPGRADE_*, CMD_ADMIN_UPGRADE_NET) ----------
 * One run at a time per hub: the whole point is that exactly one plan drives
 * the mesh while the config is frozen. */
#define MAX_UPGRADE_NODES (MAX_CLIENTS + 1) /* every client, plus this hub */
/* Downstream routes a follower remembers for a run it is only relaying: one
 * per node it forwarded an answer for.  See upgrade_route_t. */
#define MAX_UPGRADE_ROUTES MAX_UPGRADE_NODES
#define UPGRADE_PREPARE_TIMEOUT 45  /* stop waiting for READY acks          */
/* PREPARE also stays open this long after the node table last grew: a hub
 * several hops out is unknown to the driver until its first READY arrives. */
#define UPGRADE_PREPARE_SETTLE 3
#define UPGRADE_COMMIT_TIMEOUT 420  /* a node must be back, upgraded, by now */
/* Bots go in waves so a channel never loses every bot at once, and peer hubs
 * go one at a time so the mesh never fully drops. */
#define UPGRADE_BOT_WAVE_MAX 4
#define UPGRADE_BOT_WAVE_DIVISOR 4  /* never commit more than 1/N of the bots */
/* How long a CMD_UPGRADE_PREPARE this hub acknowledged stays commitable.  A
 * driver that stalls mid-roll has to ask again rather than commit against a
 * stale plan.  Mirrors UPGRADE_PREPARE_TTL in ircbot/bot.h. */
#define UPGRADE_PREPARE_TTL 900

/* ---- Offline roll-up (upgrade plan, Task 7) ----------------------------
 * A node that was down, or homed elsewhere, when a run went through comes
 * back on the old build.  The hub brings it up to the last completed run's
 * target by itself, ONE node at a time and WITHOUT freezing the config: a
 * single late bot is not a reason to hold the whole network's config still.
 * Bounded on purpose — a node that keeps failing must not be re-committed on
 * every reconnect. */
#define ROLLUP_MAX_TRIES   3    /* per node, per hub lifetime               */
#define ROLLUP_COOLDOWN    900  /* seconds between attempts on one node     */
#define ROLLUP_SETTLE      20   /* seconds after a node appears before we try */
#define ROLLUP_TIMEOUT     300  /* give up on one attempt after this        */
#define MAX_ROLLUP_TRIES   64   /* nodes remembered in the attempt ledger   */

typedef struct {
  char request_id[64];
  char requester_uuid[64];  // Bot that is locked out
  char kind[8];             // "unban" | "invite" | "key"
  char channel[MAX_CHAN];
  int origin_fd;            // Peer fd the request came from, -1 if local bot
  time_t timestamp;
  bool active;
} pending_chan_request_t;

#define MESH_ANTI_ENTROPY_INTERVAL 300
#define MAX_BOT_ENTRIES 64

#define MAX_HUB_USER_RECORDS 40   // max combined admin + oper records
#define MAX_HUB_USER_MASKS   200  // max total usermask records across all users

/* ==========================================================================
 * Bulk-payload ceilings (Change 5) — hard upper bounds on generated config /
 * sync payloads, derived entirely from the record-count macros above so they
 * auto-track whatever an operator sets.  These bound the *allocation cap*, not
 * the bytes actually sent (payloads carry only real records at real sizes).
 *
 * These are true hard bounds because ingest is bounded: per-bot state is
 * restricted to the whitelist {t,n,h,pub,seen,d} with per-key value caps in
 * hub_storage_update_entry, so a bot has at most BOT_SYNC_FIELDS entries whose
 * lines never approach value[1024].  Keep this shared contract identical with
 * ircbot/bot.h (MAX_CONFIG_PAYLOAD).
 * ========================================================================== */
#define BOT_SYNC_FIELDS   8      /* {t,n,h,pub,seen,d} = 6, +slack */
#define GLOBAL_LINE_MAX   1088   /* config_entry_t: key[32]+value[1024]+ts+seps */
#define BOT_FIELD_LINE    320    /* per-bot line: capped value (<=MAX_MASK_LEN) */
#define USER_LINE_MAX     384    /* a|/o|: uuid+name+COMBINED_KEY_B64 (+legacy slot) */
#define MASK_LINE_MAX     352    /* m|: uuid+MAX_MASK_LEN */
#define BLINE_MAX         448    /* b|<mask>|<uuid>|<pubkey>|<ts> trusted-bot line */
#define PEER_LINE_MAX     256    /* peer|/opt| sync lines */
#define PAYLOAD_SLACK     8192

/* Bot config payload (hub_generate_bot_payload): globals + users + masks +
 * this bot's own fields + one b| line per other bot. */
#define MAX_CONFIG_PAYLOAD \
  ( MAX_BOT_ENTRIES      * GLOBAL_LINE_MAX + \
    MAX_HUB_USER_RECORDS * USER_LINE_MAX   + \
    MAX_HUB_USER_MASKS   * MASK_LINE_MAX   + \
    BOT_SYNC_FIELDS      * BOT_FIELD_LINE  + \
    MAX_BOTS             * BLINE_MAX       + \
    PAYLOAD_SLACK )

/* Hub<->hub full-state sync (hub_generate_sync_packet): globals + users +
 * masks + every bot's fields + peer/opt lines. */
#define MAX_SYNC_PAYLOAD \
  ( MAX_BOT_ENTRIES      * GLOBAL_LINE_MAX + \
    MAX_HUB_USER_RECORDS * USER_LINE_MAX   + \
    MAX_HUB_USER_MASKS   * MASK_LINE_MAX   + \
    MAX_BOTS * BOT_SYNC_FIELDS * BOT_FIELD_LINE + \
    MAX_PEERS            * PEER_LINE_MAX   + \
    PAYLOAD_SLACK )

/* hub_config_write() buffer: every serialized section at its bound, with the
 * per-bot term scaled by the bots actually present.  A config that does not
 * fit is NOT written (the old file is kept) — never a truncated one.
 * hub_tool.h's HUB_TOOL_MAX_CONFIG is this at MAX_BOTS; keep them in step. */
/* The persisted roll-up plan (see pending_rollup_t): rollup| + target,
 * variant, kind, min_from, hub_target, plan_set and both 512-byte bases. */
#define ROLLUP_LINE_MAX 1536
#define HUB_CONFIG_FIXED_MAX \
  ( (size_t)8192 + (size_t)ROLLUP_LINE_MAX + \
    (size_t)MAX_BOT_ENTRIES      * GLOBAL_LINE_MAX + \
    (size_t)MAX_HUB_USER_RECORDS * USER_LINE_MAX   + \
    (size_t)MAX_HUB_USER_MASKS   * MASK_LINE_MAX   + \
    (size_t)2 * MAX_IP_ACL_ENTRIES * IP_ACL_LINE_MAX + \
    (size_t)MAX_PEERS            * 512 )
#define HUB_CONFIG_PER_BOT_MAX ((size_t)MAX_BOT_ENTRIES * 1100)

/* Largest bulk lane payload — buffers on the config/sync paths size to this. */
#define MAX_BULK_PAYLOAD \
  ((MAX_CONFIG_PAYLOAD) > (MAX_SYNC_PAYLOAD) ? (MAX_CONFIG_PAYLOAD) \
                                             : (MAX_SYNC_PAYLOAD))

/* ==========================================================================
 * Bot-presence gossip sizing (the 'bots' tree).  Same macro-derived discipline
 * as the ceilings above: every bound below follows from MAX_BOTS / MAX_PEERS,
 * so raising either retracks the buffers automatically.  None of this touches
 * the config store — see the CMD_BOT_PRESENCE block near the opcodes.
 * ========================================================================== */
#define BOT_PRESENCE_INTERVAL 60   /* how often a hub gossips its own bots   */
#define BOT_TREE_REFRESH      300  /* unconditional re-push to bots          */
/* Change pushes are coalesced: news from the mesh (peer gossip, links, TTL
 * expiry) reaches bots at most once per BOT_TREE_COALESCE — it is already up
 * to a gossip interval old — while a change to this hub's own bots goes out
 * within BOT_TREE_COALESCE_LOCAL.  A quiet mesh pushes at once (leading edge);
 * the flag is held until the push, so the latest tree always lands. */
#define BOT_TREE_COALESCE       30
#define BOT_TREE_COALESCE_LOCAL 2
#define BOT_ROSTER_TTL        240  /* entry nobody refreshed since -> dropped */
#define ROSTER_VERSION_MAX    15   /* "2.3.0", with room to grow             */
#define ROSTER_VARIANT_MAX    7    /* code base: "c" / "rs"                  */
#define ROSTER_SERVER_MAX     63   /* host:port of the bot's IRC link        */
#define ROSTER_FRAME_BUDGET   8192 /* chunk gossip well under MAX_BUFFER     */
#define TREE_ROW_MAX          256  /* one tree row at its field caps         */
/* One entry per (reporting hub, bot).  A hub only ever reports bots connected
 * to itself, so the mesh-wide worst case is every hub carrying MAX_BOTS. */
#define MAX_BOT_ROSTER        ((MAX_PEERS + 1) * MAX_BOTS)
/* Hubs the tree can know mesh-wide, direct peers or not.  Each hub's roster
 * gossip is relayed hop by hop (see CMD_BOT_ROSTER), so a chain or a star
 * still draws every hub; this bounds the per-origin relay bookkeeping. */
#define MAX_MESH_HUBS         64
/* Hops a relayed roster frame may still travel when its origin sends it. */
#define ROSTER_RELAY_HOPS     16
/* Hub rows are hung no deeper than this; the bots render up to depth 32. */
#define MAX_TREE_DEPTH        30
/* A forwarder trusts a sender's reported links (for the sync split horizon)
 * only while the report is this fresh: past one missed gossip round it
 * forwards to everyone, as a hub that never reported links is. */
#define SYNC_SPLIT_HORIZON_FRESH (2 * BOT_PRESENCE_INTERVAL + 10)
/* Tree rows: every hub node, every bot beneath one, plus the disconnected
 * tail (bounded by the bots the config knows about). */
#define MAX_TREE_ROWS         (MAX_MESH_HUBS + MAX_PEERS + 1 + MAX_BOT_ROSTER + MAX_BOTS)
#define MAX_TREE_PAYLOAD      ((MAX_TREE_ROWS) * TREE_ROW_MAX + PAYLOAD_SLACK)

/* ==========================================================================
 * Mesh transport tuning (see docs/mesh.md)
 * ========================================================================== */
#define LANE_COUNT                3
#define MAX_QUEUE_PER_LANE        256          /* per peer/client, per lane */
/* Must hold one full bulk payload plus concurrent small-lane traffic (deltas,
 * op grants) on a connection — a multiple of the bulk ceiling.  Enforced cap,
 * not a reservation, so a large value costs nothing until actually queued. */
#define MAX_QUEUED_BYTES_PER_PEER (3 * (MAX_BULK_PAYLOAD))

/* Change 5 guard: a single bulk payload must fit within a connection's queue
 * byte budget, else a full config/sync could never be enqueued.  Compile-time
 * so a future macro change that breaks the relationship fails the build rather
 * than silently dropping payloads at runtime. */
_Static_assert(MAX_QUEUED_BYTES_PER_PEER >= MAX_BULK_PAYLOAD,
               "per-peer queue budget must hold at least one bulk payload");
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
  /* Per-user Curve25519 combined pubkey (Ed25519 + X25519), base64-encoded
   * (88 chars + NUL) — the user's only credential: hub_admin logins and bot
   * ~A2 commands verify against it.  Empty (has_pubkey false) for a legacy
   * record not yet given a key; such a user can authenticate nowhere.  The
   * matching private key lives only on the user's machine. */
  char   pubkey_b64[COMBINED_KEY_B64 + 1];
  bool   has_pubkey;
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

/* ---- Network upgrade orchestration --------------------------------------
 * Modeled on pending_op_request_t: a run carries its own id, routes its
 * status back down origin_fd, and every node it touches gets a row here.
 * Volatile on purpose — a hub that restarts mid-run has no business resuming
 * someone else's plan; it comes back with the freeze flag still set in the
 * replicated opt record and an admin clears it explicitly. */
typedef enum {
  UPG_NODE_PENDING = 0, /* PREPARE sent, no answer yet                   */
  UPG_NODE_READY,       /* answered ready; waiting for its turn          */
  UPG_NODE_UNABLE,      /* answered not-ready (reason says why)          */
  UPG_NODE_COMMITTED,   /* COMMIT sent; waiting for the restart          */
  UPG_NODE_DONE,        /* back on the target version                    */
  UPG_NODE_FAILED       /* said fail, or never came back in time         */
} upgrade_node_state_t;

typedef struct {
  char uuid[64];        /* bot uuid, or a peer hub's OWN hub uuid         */
  /* Display label: a peer hub is known to the mesh by its friendly name,
   * while every upgrade frame it sends is keyed by its uuid, so the table is
   * keyed by uuid and prints this.  "" for a bot (its uuid is its name). */
  char name[64];
  char kind;            /* 'b' bot, 'h' peer hub, 's' this hub           */
  char via[64];         /* peer hub a remote bot is reached through, else "" */
  int  fd;              /* the connection it was reached on, -1 if gone  */
  char cur_version[ROSTER_VERSION_MAX + 1];
  char variant[8];      /* "c" / "rs"                                    */
  char arch[32];
  char libc[16];
  upgrade_node_state_t state;
  char reason[128];
  time_t committed_at;
  /* A hub node's READY says how many of ITS local bots it relayed PREPARE
   * to; the driver holds PREPARE open until that many relayed READYs are in,
   * so a peer's bots are never missed for answering a moment after it. */
  int relayed;
  /* Order its READY reached the driver in (1, 2, ...; 0 = none yet).  A
   * follower answers before it relays anything from below it, and every
   * answer travels the same FIFO peer links up, so a hub's READY always
   * lands ahead of any hub it routes for: descending ready_seq is
   * deepest-first along the COMMIT routes (see hub_upgrade_tick). */
  int ready_seq;
} upgrade_node_t;

/* One downstream node a FOLLOWER relays for.  A run reaches every hub in the
 * mesh, whatever shape it is wired in: each follower re-broadcasts PREPARE to
 * its own peers and forwards the answers back toward the driver, so a node
 * several hops away is still a node of the run.  COMMIT and ABORT travel the
 * same path in reverse, hop by hop, and this is the hop: "the peer I heard
 * <uuid> from is where a frame for <uuid> goes next". */
typedef struct {
  char uuid[64];  /* the node the driver is addressing                     */
  char via[64];   /* hub uuid of the peer it was learned from (next hop)   */
} upgrade_route_t;

typedef enum {
  UPG_IDLE = 0,
  UPG_PREPARE,  /* PREPARE fanned out, collecting READY/UNABLE           */
  UPG_ROLLING,  /* committing nodes wave by wave                         */
  UPG_DONE,
  UPG_FAILED,
  UPG_ABORTED
} upgrade_phase_t;

typedef struct {
  bool   active;
  char   id[64];              /* generate_request_id()                   */
  char   target_ver[64];
  char   variant[8];          /* "" = keep each node's own variant       */
  char   kind[8];             /* "" = let each node pick bin/src         */
  char   min_from[64];        /* "*" = any                               */
  char   base[512];           /* release base override, "" = compiled-in */
  /* The hubs' own target.  ircbot and irchub are separate products with
   * separate version lines and separate release trees, so a hub node is
   * never checked against `target_ver`/`base` — those are the bots'.  An
   * empty hub_ver leaves every hub on the build it runs. */
  char   hub_ver[64];
  char   hub_base[512];       /* irchub-releases override, "" = compiled-in */
  int    origin_fd;           /* admin connection that started it, or -1 */
  time_t started;
  time_t phase_started;
  upgrade_phase_t phase;
  upgrade_node_t nodes[MAX_UPGRADE_NODES];
  int    node_count;
  time_t last_added;          /* when the node table last grew           */
  int    ready_seq_next;      /* last upgrade_node_t.ready_seq handed out */
  char   summary[192];        /* why it ended, shown by UPGRADE_STATUS   */
} pending_upgrade_t;

/* The plan a completed run left behind, and the one node being walked up to
 * it right now.  The plan is persisted in this hub's own .irchub.cnf (a
 * `rollup|` line, hub-local and never replicated — its base may be a test
 * hook's file:// URL) so a restart does not forget what the network is
 * supposed to be running; the attempt in flight and the retry ledger stay
 * volatile.  The roll-up is a convenience, never the record of what the
 * network runs (that is each node's own presence), and it only ever chases a
 * target some other bot is demonstrably running (hub_rollup_target_proven). */
typedef struct {
  bool   have_plan;
  char   target[64];
  char   variant[8];
  char   kind[8];
  char   min_from[64];
  char   base[512];
  char   hub_target[64];  /* the run's hub target, "" = hubs were not moved */
  char   hub_base[512];
  time_t plan_set;

  /* The attempt in flight, if any. */
  bool   active;
  char   id[64];          /* its own run id, distinct from any real run  */
  char   uuid[64];        /* the node being rolled up                    */
  char   node_kind;       /* 'b' bot — the only kind rolled up           */
  char   step[64];        /* the version THIS attempt installs           */
  time_t started;
  bool   committed;
} pending_rollup_t;

typedef struct {
  char   uuid[64];
  time_t last_try;
  int    tries;
} rollup_try_t;

typedef struct {
  char ip[64];
  int active_connections;    // Current active connections from this IP
  int failed_auth_count;     // Failed authentication attempts
  time_t last_failed_auth;   // Timestamp of last failed auth
  time_t blocked_until;      // Temporary block expiration (0 if not blocked)
  time_t first_seen;         // For cleanup of old entries
  time_t churn_window_start; // D1: start of current connect-rate window
  int    churn_count;        // D1: new connections counted in current window
} ip_rate_limit_t;

/* IP allow/deny list entry (hub_admin 0x38-0x3D).  The lists are local to
 * this hub: never replicated to peers, never pushed to bots; config lines
 * w|<pattern>|<ts> (allow) and x|<pattern>|<ts> (deny).  IPv4 only (the hub
 * listens on AF_INET).  pattern is canonical: a bare address, or network/N
 * with the host bits cleared; net/mask are its parsed form. */
#define MAX_IP_ACL_ENTRIES 64          /* per list */
#define IP_ACL_PATTERN_MAX 19          /* "255.255.255.255/32" + NUL */
#define IP_ACL_LINE_MAX    48          /* w|<pattern>|<ts>\n */
typedef struct {
  char     pattern[IP_ACL_PATTERN_MAX];
  uint32_t net;              /* host byte order */
  uint32_t mask;             /* host byte order */
  time_t   added;
} hub_ip_acl_t;

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
  /* What the remote hub reported in its CMD_BOT_ROSTER header.  Volatile and
   * never serialized: these only feed the bots tree's uptime/version columns. */
  time_t remote_started;
  char   remote_version[ROSTER_VERSION_MAX + 1];
  /* Its code base ("c" / "rs"), from the roster's v| line; "" until a hub
   * that sends one reports in. */
  char   remote_variant[ROSTER_VARIANT_MAX + 1];
  char last_gossip[MAX_BUFFER];

  /* Peer auth (HUBv3): per-peer Curve25519 public keys. has_pubkey is
   * required — a peer without one is refused (there is no shared secret). */
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
  time_t connected_at;             // D4: when the socket was accepted/created
  bool inbound;                    // accepted on the listener (subject to the IP lists)
  bool admin_hello_seen;           // D4b: sent ADMIN-HELLO → longer pre-auth grace
  /* Admin login v2: the one-time challenge handed out in HUB-PUBKEY2.  Set on
   * ADMIN-HELLO, consumed (wiped) by the first ADMIN2 attempt either way. */
  unsigned char admin_nonce[32];
  bool admin_nonce_set;
  /* Protocol version this bot connection advertised ("v|N" in its config
   * push): 0 = not known yet, 1 = its push carried no v| (a pre-passwordless
   * build; it was sent the legacy-shaped config at once), >= 2 = advertised.
   * Per connection on purpose: a downgraded binary reconnecting is never
   * mistaken for a passwordless one. */
  int bot_proto;
  unsigned char *recv_buf;         // D2: heap; PREAUTH_BUF_SIZE then MAX_BUFFER
  int           recv_cap;          // D2: allocated capacity of recv_buf
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
  unsigned char *writing_buf;      // D2: heap; PREAUTH_BUF_SIZE then MAX_BUFFER+64
  int           writing_cap;       // D2: allocated capacity of writing_buf
  int           writing_len;
  int           writing_offset;

  /* Per-peer/client byte-rate accounting (1-second window). */
  time_t        bw_window_start;
  int           bw_bytes_in_window;

  /* Presence this bot reported via CMD_BOT_PRESENCE.  Per connection, and
   * volatile on purpose: a bot that reconnects re-reports, and a bot that
   * never reports simply shows blank fields in the tree.  Never persisted. */
  char   bot_version[ROSTER_VERSION_MAX + 1];
  char   bot_server[ROSTER_SERVER_MAX + 1];
  char   bot_variant[ROSTER_VARIANT_MAX + 1]; /* "c" / "rs", "" = unreported */
  time_t bot_started;              /* bot's own start time, 0 = unreported  */

  /* SHA-256 of the last full config queued to this bot (CMD_CONFIG_DATA), so
   * a broadcast push that would repeat it is skipped.  Only valid while that
   * push is known to be on its way: cleared when a queued config is dropped
   * on overflow and whenever the bot sends a config push of its own. */
  unsigned char cfg_sent_hash[32];
  bool          cfg_sent_valid;

  /* SHA-256 of the last bot tree queued to this bot (CMD_BOT_TREE): a change
   * push that would repeat it is skipped (the BOT_TREE_REFRESH one never is).
   * Cleared when a queued tree is dropped on overflow. */
  unsigned char tree_sent_hash[32];
  bool          tree_sent_valid;
} hub_client_t;

// Track recently processed PURGE messages to prevent feedback loops
typedef struct {
  time_t cutoff;       // PURGE cutoff timestamp
  char id[PURGE_ID_HEX + 1]; // origin's purge id ("" from pre-id hubs)
  time_t received_at;  // When this PURGE was received/processed
} recent_purge_t;

// Track recently seen OP_FORWARD_REQUEST IDs to prevent packet storms
typedef struct {
  char   request_id[64]; // Unique request ID
  time_t seen_at;        // When we first processed this request
} seen_forward_t;

/* One bot's live presence, as reported by the hub it is connected to.  Purely
 * in-memory: never written to the config, never tombstoned, never purged.  An
 * entry whose reported_at falls behind BOT_ROSTER_TTL is dropped, so a bot
 * that disconnects — or a whole hub that dies — ages out on its own. */
typedef struct {
  char   hub_uuid[64];                    /* hub that reported this bot   */
  char   hub_name[64];                    /* its friendly name, for display */
  char   bot_uuid[64];
  char   nick[MAX_NICK];
  char   version[ROSTER_VERSION_MAX + 1];
  char   variant[ROSTER_VARIANT_MAX + 1]; /* code base: "c" / "rs" / ""  */
  char   server[ROSTER_SERVER_MAX + 1];   /* the bot's IRC link           */
  time_t connected_at;                    /* bot -> hub, for uptime       */
  time_t reported_at;                     /* local clock: drives the TTL  */
} bot_roster_t;

/* One peer link a hub reports in its roster gossip (an l| line): a peer it is
 * configured with and whether that link is up right now. */
typedef struct {
  char uuid[64];
  char name[64];
  bool online;
} mesh_link_t;

/* What this hub knows about another hub anywhere in the mesh, from that
 * hub's own roster gossip — direct or relayed.  Volatile like the roster:
 * dropped once nothing refreshed it within BOT_ROSTER_TTL.  `gen` and
 * `chunks_seen` suppress relay loops: a hub applies and passes on a given
 * frame (origin, generation, chunk) exactly once. */
typedef struct {
  char        uuid[64];
  char        name[64];
  time_t      started;
  char        version[ROSTER_VERSION_MAX + 1];
  char        variant[ROSTER_VARIANT_MAX + 1];
  mesh_link_t links[MAX_PEERS];
  int         link_count;
  bool        have_links;   /* it has sent an l| list (a hub that relays) */
  long long   gen;          /* newest gossip generation seen from it      */
  uint64_t    chunks_seen;  /* chunks of `gen` already applied (bit n)    */
  time_t      reported_at;  /* local clock: drives the TTL                */
} mesh_hub_t;

/* Loop-prevention seen-set: highest lamport_seq observed per (origin, bot). */
typedef struct {
  char     origin_hub_uuid[64];
  char     bot_uuid[64];
  uint64_t max_seq_seen;
  time_t   last_seen_at;
} delta_seen_t;

/* Traffic counters since start, answered by CMD_ADMIN_STATS.  Monotonic:
 * whoever reads them diffs two snapshots. */
typedef struct {
  uint64_t rx_frames[256], rx_bytes[256];  /* by opcode, decrypted frames   */
  uint64_t tx_frames[256], tx_bytes[256];  /* by opcode, queued frames sent */
  uint64_t cfg_sent;      /* full configs queued to a bot                  */
  uint64_t cfg_same;      /* skipped: that bot already has this exact one  */
  uint64_t cfg_lost;      /* queued config dropped on lane overflow        */
  uint64_t sync_frames;   /* PEER_SYNC / PEER_BCAST frames processed       */
  uint64_t sync_noop;     /* ... of which changed nothing                  */
  uint64_t sync_records;  /* record lines in them                          */
  uint64_t sync_applied;  /* ... of which were new and applied             */
} hub_stats_t;
/* One per process (the daemon is single-threaded); defined in hub_logic.c. */
extern hub_stats_t g_hub_stats;

typedef struct {
  int listen_fd;
  int port;
  char bind_ip[64];          // IP this hub advertises itself as in mesh
  char hub_uuid[64];         // This hub's UUID
  char hub_friendly_name[64]; // This hub's friendly name
  /* realpath(argv[0]) — the binary an upgrade replaces, and the one
   * <exe>.prev sits beside.  Resolved once in main(); see hub_update.c. */
  char executable_path[PATH_MAX];
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
  pending_chan_request_t pending_chan_requests[MAX_PENDING_CHAN_REQUESTS];

  /* The network upgrade this hub is driving, if any (one at a time). */
  pending_upgrade_t upgrade;

  /* The upgrade this hub has agreed to take from ANOTHER hub, if any.  The
   * mesh is flat, so a hub is a follower and a driver at the same time and the
   * two must not share state: `upgrade` above is the run this hub drives,
   * these fields are a run someone else drives.  CMD_UPGRADE_COMMIT carries
   * only the id and the version, so the release base the driver named at
   * PREPARE time is remembered here; an id that never went through PREPARE, or
   * one older than UPGRADE_PREPARE_TTL, is refused.  Volatile — the upgrade
   * itself hands over through HUB_UPGRADE_MARKER_FILE because exec() takes all
   * of this with it. */
  char   follow_id[64];
  char   follow_origin[64];  /* uuid of the hub driving the followed run  */
  char   follow_target[64];     /* the bots' target (relayed COMMITs)    */
  char   follow_hub_target[64]; /* this hub's own target, "" = stay put  */
  char   follow_variant[8];
  char   follow_hub_base[512];  /* irchub-releases base for this hub     */
  bool   follow_self_ready;  /* this hub itself can take the followed run */
  time_t follow_prepared;
  /* Nodes below this hub in the followed run's fan-out tree (its own peers'
   * subtrees).  Rebuilt for every run; see upgrade_route_t. */
  upgrade_route_t follow_routes[MAX_UPGRADE_ROUTES];
  int    follow_route_count;

  /* Offline roll-up (see pending_rollup_t). */
  pending_rollup_t rollup;
  rollup_try_t     rollup_tries[MAX_ROLLUP_TRIES];
  int              rollup_try_count;

  ip_rate_limit_t ip_limits[MAX_IP_RATE_LIMITS];
  int ip_limits_count;

  /* IP allow/deny lists (local only, see hub_ip_acl_t).  ip_acl_changed makes
   * hub_maintenance close inbound connections the lists no longer permit. */
  hub_ip_acl_t ip_allow[MAX_IP_ACL_ENTRIES];
  int ip_allow_count;
  hub_ip_acl_t ip_deny[MAX_IP_ACL_ENTRIES];
  int ip_deny_count;
  bool ip_acl_changed;

  int purge_days_setting;  // Days threshold for tombstone purge (0 = disabled)
  bool trust_loopback;     // D3: if true, 127.0.0.1/::1 bypass rate limiting
                           //     (default false — secure by default)
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

  /* Network options pushed to bots/peers via the 'opt|' record. Each letter
   * in opt_flags is an enabled flag (see OPT_* in this header). */
  char opt_flags[MAX_OPT_FLAGS + 1];
  time_t opt_flags_ts;

  /* Debounced config write: set dirty flag instead of writing immediately.
   * hub_maintenance flushes at most once every CONFIG_WRITE_DEBOUNCE_S seconds.
   * This prevents N PBKDF2(100K) calls when N peer syncs arrive in a burst. */
  bool config_dirty;
  /* A full config push to every local bot is owed (see
   * hub_flush_bot_config): set by every change bots must see, sent at most
   * once per BOT_CONFIG_PUSH_COALESCE by the maintenance loop. */
  bool bot_config_pending;
  time_t last_bot_config_push;
  time_t last_config_write;
  bool mesh_state_dirty;    /* set on peer connect/disconnect; clears after gossip */

  /* Mesh transport: monotonic Lamport sequence stamped onto outgoing deltas
   * (carried as the trailing field of the wire format). On load from disk we
   * bump this past any plausibly recent value to keep monotonicity even if
   * the system clock or stored value lags. */
  uint64_t next_lamport_seq;

  /* Loop prevention: deltas already observed per (origin_hub_uuid, bot_uuid).
   * LRU-evicted past MAX_DELTA_SEEN. */
  delta_seen_t delta_seen[MAX_DELTA_SEEN];
  int          delta_seen_count;

  /* ---- Bot presence (volatile; never serialized) ---- */
  bot_roster_t roster[MAX_BOT_ROSTER];
  int          roster_count;
  time_t       hub_started;        /* this hub's own uptime base           */
  time_t       last_presence_gossip;
  time_t       last_tree_push;
  bool         tree_dirty;         /* roster changed: push to bots next tick */
  bool         tree_dirty_local;   /* ...by one of our own bots (short gap)  */
  time_t       last_tree_change_push; /* coalescing clock (BOT_TREE_COALESCE) */
  mesh_hub_t   mesh_hubs[MAX_MESH_HUBS]; /* every hub heard from, any hop  */
  int          mesh_hub_count;
  long long    roster_gen;         /* last generation this hub gossiped     */
  uint32_t     gossip_link_mask;   /* peers linked at the last gossip (bit p) */
  time_t       resync_due_at;      /* ask peers for a sync then (0 = none)  */
} hub_state_t;

#define CONFIG_WRITE_DEBOUNCE_S 5

// --- Prototypes ---
void hub_log(const char *format, ...);
/* Send the owed full config push to every local bot (maintenance loop). */
void hub_flush_bot_config(hub_state_t *state, time_t now);
/* The running hub's state (hub_main.c): the level macros below read
 * g_state->log_level, and stay silent while it is NULL. */
extern hub_state_t *g_state;

// Log level filtering macros - these check the log level before calling hub_log.
// The tag is glued to the caller's format by string-literal concatenation, so a
// message with no varargs stays warning-free under -Wpedantic (an empty
// __VA_ARGS__ after a named parameter is not valid C11).
#define hub_log_error(...) \
    do { if (g_state && g_state->log_level >= LOG_ERROR) hub_log("[ERROR] " __VA_ARGS__); } while(0)
#define hub_log_warning(...) \
    do { if (g_state && g_state->log_level >= LOG_WARNING) hub_log("[WARNING] " __VA_ARGS__); } while(0)
#define hub_log_info(...) \
    do { if (g_state && g_state->log_level >= LOG_INFO) hub_log("[INFO] " __VA_ARGS__); } while(0)
#define hub_log_debug(...) \
    do { if (g_state && g_state->log_level >= LOG_DEBUG) hub_log("[DEBUG] " __VA_ARGS__); } while(0)
/* Periodic runtime counters. Carries its own [STATUS] tag but is gated at the
 * LOG_INFO level, so it disappears together with the rest of the INFO traffic. */
#define hub_log_status(...) \
    do { if (g_state && g_state->log_level >= LOG_INFO) hub_log("[STATUS] " __VA_ARGS__); } while(0)

bool hub_config_load(hub_state_t *state, const char *password);
void hub_config_write(hub_state_t *state);

/* a|/o| record codec (docs/passwordless.md §3.1), shared by config load,
 * peer sync and bot pushes.  Field 3 decides: a valid key = new format;
 * anything else is a legacy password, dropped, key taken from field 7.
 * *legacy (optional) reports which shape was seen. */
bool hub_parse_user_record(const char *data, char type, hub_user_record_t *out,
                           bool *legacy);
/* Full line incl. "\n".  legacy_v1 emits the fail-closed shape for bots that
 * have not advertised v|2: a|uuid|name||act|seen|ts|pubkey. */
int hub_format_user_record(const hub_user_record_t *u, bool legacy_v1,
                           char *buf, size_t len);
/* Timestamp for changing an EXISTING replicated record: now, but always past
 * its previous stamp.  Peers and bots accept only a strictly newer timestamp,
 * so an add and a remove in the same second would tie and the remove would
 * never replicate (a removed admin staying active elsewhere). */
static inline time_t hub_lww_next_ts(time_t prev) {
  time_t now = time(NULL);
  return now > prev ? now : prev + 1;
}

/* LWW acceptance for a replicated add/del record: a strictly newer stamp wins,
 * and on an exact tie a delete beats an add.  hub_lww_next_ts only separates
 * writes made on ONE node; two nodes stamping the same second (a bot's part
 * reaching one hub while another hub still holds the add) tie, and with a
 * plain "newer wins" each side keeps its own copy and refuses the other's
 * forever.  Delete-over-add is deterministic, so every node converges.
 * Mirrored in ircbot bot.h (lww_accepts) -- the rule must match on both. */
static inline bool hub_lww_accepts(time_t in_ts, bool in_active,
                                   time_t cur_ts, bool cur_active) {
  return in_ts > cur_ts || (in_ts == cur_ts && cur_active && !in_active);
}

/* LWW acceptance for the network opt flags (one value, no add/del).  Newer
 * stamp wins; on a tie the byte-wise greater flag string wins, so every node
 * picks the same side -- and a set ("h") beats a clear (""), the stricter
 * policy.  Mirrored in ircbot bot.h (opt_accepts). */
static inline bool hub_opt_accepts(time_t in_ts, const char *in_flags,
                                   time_t cur_ts, const char *cur_flags) {
  return in_ts > cur_ts ||
         (in_ts == cur_ts && strcmp(in_flags, cur_flags) > 0);
}

/* Whether a stored c/m/o global value ("...|add" / "...|del") is live: its op
 * is the last '|' field. */
static inline bool hub_global_value_active(const char *value) {
  const char *last = value ? strrchr(value, '|') : NULL;
  return !(last && strcmp(last + 1, "del") == 0);
}

/* Value of an opt line, "<letters>|<ts>" — including the "|<ts>" form a
 * clear produces, which a plain "%[^|]|%lld" scan rejects.  flags gets only
 * [a-zA-Z0-9]; false if the timestamp is missing or not positive. */
bool hub_parse_opt_value(const char *v, char flags[MAX_OPT_FLAGS + 1],
                         time_t *ts);

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
/* Combined public key (ed_pub || x_pub) from a combined private key. */
bool hub_crypto_combined_pub_from_priv(const unsigned char priv[64],
                                       unsigned char pub[64]);
/* Strict: canonical base64 of exactly 64 bytes, neither half all zero. */
bool hub_crypto_pubkey_b64_decode(const char *b64, unsigned char out[64]);
/* "ab12:cd34:ef56:7890" — first 8 bytes of SHA-256(pub64). */
void hub_crypto_key_fingerprint(const unsigned char pub[64],
                                char out[KEY_FP_LEN + 1]);
/* Fingerprint of an 88-char key string, or "(no key)"/"(bad key)". */
void hub_crypto_key_fingerprint_b64(const char *b64, char out[KEY_FP_LEN + 1]);

// AES-GCM
int aes_gcm_decrypt(const unsigned char *input, int input_len,
                    const unsigned char *key, unsigned char *output,
                    unsigned char *tag);
int aes_gcm_encrypt(const unsigned char *plain, int plain_len,
                    const unsigned char *key, unsigned char *output,
                    unsigned char *tag);

// Rate limiting and IP access control functions
bool is_ip_allowed(hub_state_t *state, const char *ip);
/* D2: allocate a client's recv/writing buffers at `size` (and writing at
 * size+64). Returns false on OOM. Used at accept/connect time. */
bool hub_client_alloc_buffers(hub_client_t *c, int size);
/* D2: grow a client's buffers to MAX_BUFFER on successful authentication.
 * Idempotent (no-op if already full size). Returns false on OOM. */
bool hub_client_promote_buffers(hub_client_t *c);
void increment_active_connections(hub_state_t *state, const char *ip);
void decrement_active_connections(hub_state_t *state, const char *ip);
void cleanup_old_ip_limits(hub_state_t *state);
/* Accept-time allow/deny decision; logs a refusal. */
bool check_ip_access_lists(hub_state_t *state, const char *ip);
/* Same decision, silent: deny wins; a non-empty allowlist must match; an
 * address that does not parse is refused whenever either list has entries. */
bool hub_ip_acl_permits(const hub_state_t *state, const char *ip);
/* "a.b.c.d" or "a.b.c.d/N" (N = 0..32, no sign or leading zero) into a
 * canonical entry (added = 0).  False on anything else. */
bool hub_ip_acl_parse(const char *in, hub_ip_acl_t *out);
/* Strict unsigned decimal for admin numeric fields (indices, days, ports):
 * 1-10 ASCII digits, nothing else -- no sign, space, suffix or empty string --
 * and value <= max.  atoi() read "7d" as 7, "c3cd..." as 0 and "" as 0; in
 * DEL_PEER a UUID starting with digits deleted the peer at that index, and in
 * PURGE_TOMBSTONES a typo meant "purge every tombstone now". */
bool hub_parse_uint(const char *s, unsigned long max, unsigned long *out);
/* A hub friendly name: 1-63 bytes of [A-Za-z0-9._-].  The name travels inside
 * '|'-separated config lines and handshakes, ':'/','-separated mesh gossip and
 * the ':'-separated ADD_PEER payload, so any other byte could forge a field or
 * a whole record ("x|203.0.113.77|0" after a newline).  Applied to
 * SET_HUB_NAME, the setup wizard and names learned from peers. */
bool hub_name_valid(const char *name);
/* list: 'w' (allow) or 'x' (deny).  Add refuses a duplicate (same network
 * and prefix) or a full list; remove matches the same way. */
typedef enum { IP_ACL_ADDED, IP_ACL_DUPLICATE, IP_ACL_FULL, IP_ACL_BAD_LIST } ip_acl_add_t;
ip_acl_add_t hub_ip_acl_add(hub_state_t *state, char list, const hub_ip_acl_t *e);
bool hub_ip_acl_remove(hub_state_t *state, char list, const hub_ip_acl_t *e);

void hub_storage_init(void);
bool hub_storage_update_entry(hub_state_t *state, const char *uuid,
                              const char *key, const char *value,
                              const char *extra, const char *op, time_t ts);
bool hub_storage_update_global_entry(hub_state_t *state, const char *key,
                                     const char *value, const char *extra,
                                     const char *op, time_t ts);
/* Stored timestamp of the global entry that `value` under `key` addresses
 * (same match as the update above), or 0 if there is none. */
time_t hub_storage_global_ts(const hub_state_t *state, const char *key,
                             const char *value);
/* Soft-delete a registered bot: a d|1 tombstone stamped past any earlier 'd'.
 * False when the uuid is unknown or already deleted; *ts_out = the stamp. */
bool hub_storage_delete(hub_state_t *state, const char *uuid, time_t *ts_out);
int hub_storage_get_full_list(hub_state_t *state, char *buffer, int max_len);
int hub_storage_get_summary_list(hub_state_t *state, char *buffer, int max_len);

void hub_generate_sync_packet(hub_state_t *state, char *buffer, int max_len);
/* proto_v2: the receiving connection advertised v|2 (new a|/o|/b| shapes);
 * false sends the fail-closed legacy shapes. */
void hub_generate_bot_payload(hub_state_t *state, const char *uuid,
                              bool proto_v2, char *buffer, int max_len);
void hub_broadcast_sync_to_peers(hub_state_t *state, const char *payload,
                                 int exclude_fd);

// cutoff==0: purge all tombstones; cutoff>0: purge tombstones older than cutoff
int hub_execute_purge(hub_state_t *state, time_t cutoff,
                      char *log_out, int log_max_len);

/* Send PURGE|<cutoff>|<id> to every peer hub, under a fresh random id that
 * this hub records as seen.  False (nothing sent) if no id could be drawn. */
bool hub_broadcast_purge(hub_state_t *state, time_t cutoff);

// Leader election: Check if this hub should initiate scheduled purges
// (Hub with smallest UUID in connected mesh leads)
bool hub_should_initiate_scheduled_purge(hub_state_t *state);

bool hub_handle_client_data(hub_state_t *state, hub_client_t *client);
bool handle_bot_authentication(hub_state_t *state, hub_client_t *client,
                               unsigned char *data, int packet_len);
void hub_disconnect_client(hub_state_t *state, hub_client_t *c);
void hub_broadcast_mesh_state(hub_state_t *state);

/* ---- Bot presence / the 'bots' tree (hub_logic.c) ----
 * hub_presence_tick drives both halves on the maintenance clock: it gossips
 * this hub's own connected bots to the peers every BOT_PRESENCE_INTERVAL and
 * pushes a refreshed tree down to the bots when the roster changed (or every
 * BOT_TREE_REFRESH regardless).  hub_roster_expire drops entries past the
 * TTL; hub_roster_mark_dirty asks for a push (`local`: one of our own bots
 * changed, pushed within BOT_TREE_COALESCE_LOCAL). */
void hub_presence_tick(hub_state_t *state, time_t now);
/* One step of the rolling network upgrade per maintenance tick: collect
 * READY acks, commit the next wave, time out a node that never came back.
 * A no-op unless a run is active. */
void hub_upgrade_tick(hub_state_t *state, time_t now);
/* Report the outcome of an upgrade another hub drove, once there is a peer to
 * tell.  A no-op unless HUB_UPGRADE_MARKER_FILE says this process is that
 * upgrade's restart; the marker is read and removed exactly once, so whichever
 * peer link comes up first carries the answer. */
void hub_upgrade_report_pending(hub_state_t *state, hub_client_t *peer);

/* ---- The hub's own self-update (hub_update.c) ---------------------------
 * The hub side of the network upgrade: what a node needs in order to *be*
 * upgraded, as opposed to the orchestration that drives other nodes.  Built
 * with HAVE_CURL; without it every entry point reports the feature
 * unavailable rather than falling back to anything. */
/* Could this hub move to `target_ver`?  Answered at PREPARE time, before
 * anything is downloaded.  `min_from` is what the driving hub sent ("" or "*"
 * = let the manifest decide); `reason` explains a false. */
bool hub_update_can_take(const char *target_ver, const char *min_from,
                         const char *base, char *reason, size_t reason_size);
/* CMD_UPGRADE_COMMIT.  Returns false with *err set and nothing touched; on
 * success it does not return -- the process is replaced and reports the
 * outcome after the restart. */
/* Highest version `cur_ver` may take right now on the way to `target_ver`,
 * read from the release tree at <base>/<variant>.  Walks a node that sits
 * below a target's min_from_version there one release at a time. */
bool hub_update_next_step(const char *base, const char *variant,
                          const char *cur_ver, const char *target_ver,
                          char *out, size_t out_size, char *reason,
                          size_t reason_size);

bool hub_update_commit(hub_state_t *state, const char *upgrade_id,
                       const char *target_ver, const char *variant,
                       const char *base, const char **err);
/* CMD_UPGRADE_ABORT: restore <exe>.prev / .irchub.cnf.prev and restart onto
 * them.  False when there is nothing retained to go back to. */
bool hub_update_rollback(hub_state_t *state, const char *reason);
bool hub_upgrade_marker_write(const char *upgrade_id, const char *target_ver);
/* True when `s` may be one field of an upgrade plan: no '|', no line break,
 * no shell metacharacter or blank, and short enough for any plan field.  The
 * same rule gates what a follower accepts at PREPARE and what the rollup|
 * config line carries, so a peer can never split or inject a config line. */
bool hub_upgrade_plan_field_ok(const char *s);
/* Reads and removes the hand-off marker hub_update_commit() left behind. */
bool hub_update_take_pending(char *id_out, size_t id_size, char *ver_out,
                             size_t ver_size);
/* Compare two version strings, tolerating a leading 'v' on either side. */
int hub_update_version_cmp(const char *a, const char *b);
/* Host capability probe answered in CMD_UPGRADE_READY. */
void hub_update_host_arch(char *out, size_t out_size);
void hub_update_host_libc(char *out, size_t out_size);
const char *hub_update_host_variant(void);
/* irchub -checkupdate [variant]: verify the release channel, print, exit. */
int hub_update_check_cli(const char *variant);
void hub_roster_expire(hub_state_t *state, time_t now);
void hub_roster_mark_dirty(hub_state_t *state, bool local);

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

/* True when recv_buf already holds a whole frame (or a length prefix the pump
 * will refuse).  hub_handle_client_data takes at most 8 frames per call for
 * fairness; the main loop must come back for the rest without waiting for
 * new bytes, or they sit unread until the sender's next packet. */
bool hub_client_has_buffered_frame(const hub_client_t *c);

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

void hub_set_config_pass(hub_state_t *s, const char *pass);
void hub_get_config_pass(const hub_state_t *s, char *out, size_t len);
void secure_wipe(void *ptr, size_t len);
void generate_uuid_v4(char *buffer, size_t len);

char *base64_encode(const unsigned char *input, int length);
unsigned char *base64_decode(const char *input, int *out_len);

#endif
