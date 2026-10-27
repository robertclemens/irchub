#include "hub.h"
#include "hub_console.h"
#if defined(__GLIBC__)
#include <malloc.h>   /* for mallopt(); glibc-only, guarded like its use in main() */
#endif
#include <stdarg.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <inttypes.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <termios.h>
#include <pwd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <limits.h>


static FILE *log_fp = NULL;
hub_state_t *g_state = NULL;  // Global state pointer for use in hub_log() and other global functions

/* Open HUB_LOG_FILE at 0600. open(O_CREAT,0600)+fdopen is used rather than
 * fopen("a") so the mode never depends on the caller's umask, and the fchmod
 * tightens a log that already exists with looser permissions — mode= only
 * applies on creation, so an inherited 0644 file would otherwise stay 0644.
 * Same guard the codebase documents in keygen.c. */
static FILE *hub_log_open(bool truncate) {
    int flags = O_CREAT | O_WRONLY | (truncate ? O_TRUNC : O_APPEND);
    int fd = open(HUB_LOG_FILE, flags, 0600);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) == 0 && (st.st_mode & 0777) != 0600)
        (void)fchmod(fd, 0600);
    FILE *fp = fdopen(fd, "a");   /* "a" even after O_TRUNC: fd carries the flags */
    if (!fp) close(fd);
    return fp;
}

/* Length of the valid UTF-8 sequence starting at p (at most n bytes long), or
 * 0 when the bytes there are not one (overlong, surrogate, > U+10FFFF, cut). */
static size_t hub_log_utf8_len(const unsigned char *p, size_t n) {
    size_t len;
    unsigned min;
    unsigned cp;
    if (p[0] >= 0xC2 && p[0] <= 0xDF)      { len = 2; min = 0x80;    cp = p[0] & 0x1F; }
    else if (p[0] >= 0xE0 && p[0] <= 0xEF) { len = 3; min = 0x800;   cp = p[0] & 0x0F; }
    else if (p[0] >= 0xF0 && p[0] <= 0xF4) { len = 4; min = 0x10000; cp = p[0] & 0x07; }
    else return 0;
    if (n < len) return 0;
    for (size_t i = 1; i < len; i++) {
        if ((p[i] & 0xC0) != 0x80) return 0;
        cp = (cp << 6) | (p[i] & 0x3F);
    }
    if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return 0;
    return len;
}

/* Write one formatted log message with every byte an attacker could use to
 * forge or garble the log made inert.  Log arguments routinely carry
 * pre-authentication network input (a claimed bot UUID, a peer name), so:
 * control bytes and invalid UTF-8 become \xHH, and a newline inside the
 * message is followed by an indent so it can never start a line that looks
 * like a fresh "[timestamp]" entry.  Only the message's final newline is kept
 * as-is. */
static void hub_log_write_sanitized(FILE *fp, const char *msg, size_t n) {
    const unsigned char *p = (const unsigned char *)msg;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = p[i];
        if (c == '\n') {
            fputc('\n', fp);
            if (i + 1 < n) fputs("    ", fp);
        } else if (c == '\t' || (c >= 0x20 && c < 0x7F)) {
            fputc(c, fp);
        } else if (c >= 0x80) {
            size_t ul = hub_log_utf8_len(p + i, n - i);
            if (ul) {
                fwrite(p + i, 1, ul, fp);
                i += ul - 1;
            } else {
                fprintf(fp, "\\x%02X", c);
            }
        } else {
            fprintf(fp, "\\x%02X", c);
        }
    }
}

/* The file sink: the size-capped, inode-checked HUB_LOG_FILE.  Returns
 * without writing when the file cannot be opened. */
static void hub_log_file_write(const char *time_buf, const char *msg, size_t len) {
    if (!log_fp) {
        log_fp = hub_log_open(false);
        if (!log_fp) {
            return;  // Silent fail if can't open
        }
    }

    // Check if the path still points to the same inode as our open fd.
    // A plain stat() check misses the case where the file was deleted and
    // recreated (different inode) — the old fd silently writes to the
    // unlinked inode while the new path belongs to a different file.
    struct stat st_path, st_fd;
    bool need_reopen = false;
    if (stat(HUB_LOG_FILE, &st_path) != 0) {
        need_reopen = true;  // path gone
    } else if (fstat(fileno(log_fp), &st_fd) != 0 ||
               st_fd.st_ino != st_path.st_ino) {
        need_reopen = true;  // path replaced with a different file
    }
    if (need_reopen) {
        fclose(log_fp);
        log_fp = NULL;
    }

    // Reopen if not open
    if (!log_fp) {
        log_fp = hub_log_open(false);
        if (!log_fp) {
            return;  // Silent fail if can't open
        }
    }

    // Check file size using g_state->log_max_size if available
    int log_max_size = (g_state && g_state->log_max_size > 0) ?
                       g_state->log_max_size : HUB_LOG_FILE_SIZE;

    struct stat file_stat;
    if (stat(HUB_LOG_FILE, &file_stat) == 0 && file_stat.st_size >= log_max_size) {
        // File exceeded size limit, truncate it
        fclose(log_fp);
        log_fp = hub_log_open(true);
        if (!log_fp) {
            return;  // Silent fail if can't reopen
        }
        fprintf(log_fp, "[%s] Log file truncated (size limit reached)\n", time_buf);
        fflush(log_fp);
        /* fall through: the line that tripped the cap is kept, after it */
    }

    fprintf(log_fp, "[%s] ", time_buf);
    hub_log_write_sanitized(log_fp, msg, len);
    fflush(log_fp);
}

static void hub_log_v(int level, const char *format, va_list ap)
    __attribute__((format(printf, 2, 0)));
static void hub_log_v(int level, const char *format, va_list ap) {
    /* Which sinks take a line at this level.  Before g_state exists (early
     * startup) only the file does, as it always did. */
    bool to_file = !g_state || g_state->log_level >= level;
    bool to_ring = g_state && g_state->console_log_level >= level;
    if (!to_file && !to_ring) return;

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", t);

    char stack_msg[2048];
    char *msg = stack_msg;
    va_list ap2;
    va_copy(ap2, ap);
    int need = vsnprintf(stack_msg, sizeof(stack_msg), format, ap);
    if (need < 0) {
        va_end(ap2);
        return;
    }
    if ((size_t)need >= sizeof(stack_msg)) {
        msg = malloc((size_t)need + 1);
        if (!msg) {
            msg = stack_msg;  /* keep the (cut) message rather than nothing */
            need = (int)sizeof(stack_msg) - 1;
        } else {
            vsnprintf(msg, (size_t)need + 1, format, ap2);
        }
    }
    va_end(ap2);

    if (to_file) hub_log_file_write(time_buf, msg, (size_t)need);
    if (to_ring) {
        /* The SSH consoles' log view reads the same lines from memory; the
         * ring is fed whether or not the file could be written. */
        char ring_line[CONSOLE_LOG_LINE_MAX];
        int rl = snprintf(ring_line, sizeof(ring_line), "[%s] %.*s", time_buf,
                          need, msg);
        if (rl > 0)
            hub_console_log_append(level, ring_line,
                                   rl < (int)sizeof(ring_line)
                                       ? (size_t)rl
                                       : sizeof(ring_line) - 1);
        secure_wipe(ring_line, sizeof(ring_line));
    }
    if (msg != stack_msg) {
        secure_wipe(msg, (size_t)need);  /* log args can hold key material */
        free(msg);
    }
    secure_wipe(stack_msg, sizeof(stack_msg));
}

/* Level filtering is the caller's (the hub_log_error / _warning / _info /
 * _debug macros test hub_log_on() first); this only picks the sinks. */
void hub_log_at(int level, const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    hub_log_v(level, format, ap);
    va_end(ap);
}

void hub_log(const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    hub_log_v(LOG_ERROR, format, ap);
    va_end(ap);
}

static void daemonize(void) {
    pid_t pid;

    // First fork: detach from the calling process
    pid = fork();
    if (pid < 0) { perror("fork"); exit(1); }
    if (pid > 0) exit(0);   // parent exits

    // Become session leader, detach from controlling terminal
    if (setsid() < 0) { perror("setsid"); exit(1); }

    // Second fork: prevent re-acquisition of a controlling terminal
    pid = fork();
    if (pid < 0) { perror("fork"); exit(1); }
    if (pid > 0) exit(0);   // intermediate parent exits

    // Tighten umask; stay in the working directory so relative paths (.pid, .log) resolve
    umask(0077);

    // Redirect stdin/stdout/stderr to /dev/null
    int devnull = open("/dev/null", O_RDWR);
    if (devnull < 0) exit(1);
    dup2(devnull, STDIN_FILENO);
    dup2(devnull, STDOUT_FILENO);
    dup2(devnull, STDERR_FILENO);
    if (devnull > STDERR_FILENO) close(devnull);
}

/* Set by SIGTERM/SIGINT; the main loop exits and main() shuts down in order.
 * The handler itself does nothing else: stdio, unlink and exit() from a
 * handler are unsafe (the signal can land inside malloc or hub_log), and an
 * exit() there skipped the pending config write and the secret wipes. */
static volatile sig_atomic_t g_hub_stop_signal = 0;

static void handle_signal(int sig) {
    g_hub_stop_signal = sig;
}

/* Connection serials start at 1 and only grow: at one connection per
 * nanosecond a 64-bit counter would take ~584 years to wrap. */
uint64_t hub_next_conn_serial(void) {
    static uint64_t next = 0;
    return ++next;
}

void hub_disconnect_client(hub_state_t *state, hub_client_t *c) {
    if (!c) return;

    /* A console that goes away is owed nothing any more. */
    if (c->internal) hub_chan_elect_forget_admin(state, c);

    /* fd -1: a socket handed to the SSH console, not a disconnect */
    if (c->fd >= 0)
        hub_log_info("[HUB] Disconnecting client %s (FD: %d)\n", c->ip, c->fd);

    decrement_active_connections(state, c->ip);

    // 1. Update Peer Status FIRST
    for(int p = 0; p < state->peer_count; p++) {
        if (state->peers[p].fd == c->fd && c->fd != -1) {
            state->peers[p].connected = false;
            state->peers[p].fd = -1;
            state->peers[p].link_down_at = time(NULL);
            state->mesh_state_dirty = true;
            /* Its uptime stops being a fact the moment the link drops; the
             * bots beneath it age out of the roster on the TTL. */
            state->peers[p].remote_started = 0;
            hub_roster_mark_dirty(state, false); /* a whole branch just went away */
        }
    }
    /* A bot leaving changes the tree; gossip it on the next tick rather than
     * waiting for its roster entry to time out on the peers. */
    if (c->type == CLIENT_BOT && c->authenticated) {
        hub_roster_mark_dirty(state, true);
        state->last_presence_gossip = 0;
    }

    // 2. Close Socket
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;

    // 3. Remove from Array (Swap with last)
    for (int i = 0; i < state->client_count; i++) {
        if (state->clients[i] == c) {
            state->clients[i] = state->clients[--state->client_count];
            break;
        }
    }

    // 4. Wipe sensitive data and free memory
    if (c->internal) hub_console_link_free(c);
    secure_wipe(c->session_key, sizeof(c->session_key));
    secure_wipe(c->bot_eph_x25519_priv, sizeof(c->bot_eph_x25519_priv));
    c->bot_eph_priv_set = false;
    if (c->recv_buf) secure_wipe(c->recv_buf, (size_t)c->recv_len);
    /* Free per-peer outbound queues + in-flight ciphertext.  Done after the
     * fd is closed so no drain attempts can race. */
    peer_queue_destroy(c);
    /* D2: release the heap-allocated client buffers. */
    free(c->recv_buf);
    free(c->writing_buf);
    free(c);
}

// Sealed-box sender for peer and admin connections
static int hub_seal_send(const unsigned char hub_x25519_pub[32],
                         const unsigned char *plain_in, int plain_len,
                         const unsigned char *info, size_t info_len,
                         unsigned char *out, int out_max,
                         unsigned char session_key_out[32]) {
    if (out_max < 32 + GCM_IV_LEN + plain_len + GCM_TAG_LEN) return -1;

    // Generate ephemeral X25519 keypair
    unsigned char eph_priv[32], eph_pub[32];
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *pk = NULL;
    size_t len = 32;
    bool ok = ctx && EVP_PKEY_keygen_init(ctx) > 0
                  && EVP_PKEY_keygen(ctx, &pk) > 0
                  && EVP_PKEY_get_raw_private_key(pk, eph_priv, &len) > 0 && len == 32
                  && EVP_PKEY_get_raw_public_key(pk, eph_pub,  &len) > 0 && len == 32;
    if (pk)  EVP_PKEY_free(pk);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (!ok) { secure_wipe(eph_priv, 32); return -1; }

    unsigned char shared[32];
    ok = hub_crypto_x25519_derive(eph_priv, hub_x25519_pub, shared);
    secure_wipe(eph_priv, 32);
    if (!ok) return -1;

    unsigned char session_key[32];
    ok = hub_crypto_hkdf_sha256(shared, 32, eph_pub, 32, info, info_len, session_key, 32);
    secure_wipe(shared, 32);
    if (!ok) return -1;

    memcpy(out, eph_pub, 32);
    unsigned char tag[GCM_TAG_LEN];
    int enc_len = aes_gcm_encrypt(plain_in, plain_len, session_key, out + 32, tag);
    if (enc_len <= 0) { secure_wipe(session_key, 32); return -1; }
    memcpy(out + 32 + enc_len, tag, GCM_TAG_LEN);

    memcpy(session_key_out, session_key, 32);
    secure_wipe(session_key, 32);
    return 32 + enc_len + GCM_TAG_LEN;
}

static void hub_peer_handshake(hub_state_t *state, hub_client_t *c,
                                const hub_peer_config_t *peer) {
    if (!state->hub_keys_loaded) {
        hub_log_error("[PEER] No Curve25519 keys loaded; cannot handshake\n");
        hub_disconnect_client(state, c);
        return;
    }

    if (!peer || !peer->has_pubkey) {
        hub_log_warning("[PEER] Peer has no registered pubkey — refusing to connect. "
                "Re-add this peer with its Curve25519 pubkey (HUBv3 auth needs it).\n");
        hub_disconnect_client(state, c);
        return;
    }

    unsigned char pack[1024];
    int msg_len;

    {
        /* Build the transcript the signature commits to. The receiver
         * reconstructs the same transcript from the parsed fields and the
         * stored peer record before verifying. */
        time_t now = time(NULL);
        char ts_str[32];
        snprintf(ts_str, sizeof(ts_str), "%lld", (long long)now);

        char transcript[512];
        int tlen = snprintf(transcript, sizeof(transcript),
                            "irchub-peer-auth-v3|%s|%s|%d|%s|%s",
                            state->hub_uuid, ts_str, state->port,
                            state->hub_friendly_name, state->bind_ip);
        if (tlen < 0 || tlen >= (int)sizeof(transcript)) {
            hub_log_error("[PEER] v3 transcript too long\n");
            hub_disconnect_client(state, c);
            return;
        }

        unsigned char sig[ED25519_SIG_LEN];
        if (!hub_crypto_ed25519_sign(state->hub_ed25519_priv,
                                     (unsigned char *)transcript, (size_t)tlen,
                                     sig)) {
            hub_log_error("[PEER] v3 Ed25519 sign failed\n");
            hub_disconnect_client(state, c);
            return;
        }

        char *sig_b64 = base64_encode(sig, ED25519_SIG_LEN);
        if (!sig_b64) {
            hub_log_error("[PEER] v3 signature base64 encode failed\n");
            hub_disconnect_client(state, c);
            return;
        }

        msg_len = snprintf((char *)pack, sizeof(pack),
                           "HUBv3|%s|%d|%s|%s|%s|%s",
                           state->hub_uuid, state->port,
                           state->hub_friendly_name, state->bind_ip,
                           ts_str, sig_b64);
        secure_wipe(sig_b64, strlen(sig_b64));
        free(sig_b64);

        if (msg_len < 0 || msg_len >= (int)sizeof(pack)) {
            hub_log_error("[PEER] v3 packet too long\n");
            hub_disconnect_client(state, c);
            return;
        }
    }

    /* enc[0..3] is the frame length: the frame goes out in one write */
    unsigned char enc[4 + MAX_BUFFER];
    static const unsigned char PEER_INFO[] = "irchub-peer-session-v1";
    const unsigned char *seal_target = peer->x25519_pub;
    int enc_len = hub_seal_send(seal_target,
                                pack, msg_len + 1,
                                PEER_INFO, sizeof(PEER_INFO) - 1,
                                enc + 4, sizeof(enc) - 4, c->session_key);
    secure_wipe(pack, sizeof(pack));

    if (enc_len <= 0) {
        hub_log_error("[PEER] Sealed-box encryption failed\n");
        hub_disconnect_client(state, c);
        return;
    }

    uint32_t net_len = htonl((uint32_t)enc_len);
    memcpy(enc, &net_len, 4);
    if (write(c->fd, enc, (size_t)(4 + enc_len)) != (ssize_t)(4 + enc_len)) {
        hub_log_warning("[PEER] Handshake write failed\n");
        hub_disconnect_client(state, c);
        return;
    }

    c->authenticated = true;
    /* D2/Change 5: grow buffers to the per-type bulk size now that the peer is
     * authenticated (c->type == CLIENT_HUB → MAX_SYNC_PAYLOAD) — the full sync
     * below rides these.  Runs before any bulk frame is queued. */
    if (!hub_client_promote_buffers(c)) {
        hub_log_error("[PEER] Buffer promotion OOM for %s — disconnecting\n", c->ip);
        hub_disconnect_client(state, c);
        return;
    }
    hub_log_info("[PEER] Handshake complete with %s\n", c->ip);
    hub_link_offer(state, c, peer->uuid);
    /* If this process is the product of an upgrade a peer drove, close that
     * run out now that there is a peer to tell (no-op otherwise). */
    hub_upgrade_report_pending(state, c);
    /* Send a full config sync immediately via the BULK queue.  The queue
     * enforces a per-peer byte budget (BULK_SOFT_BUDGET_BPS = 32 KB/s) so
     * simultaneous startup of all 10 hubs no longer creates a cascade that
     * fills socket buffers.  Each hub's BULK drain is naturally staggered
     * by the select() cycle time.  This replaces the old approach of deferring
     * the first sync to anti-entropy (up to 90 s wait). */
    {
        /* Heap, sized to the sync ceiling like the accepting side: a 16 KB
         * stack buffer cut the dialing side's startup sync short. */
        char *full_sync = malloc(MAX_SYNC_PAYLOAD);
        if (!full_sync) {
            hub_log_error("[PEER] OOM building initial sync for %s\n", c->ip);
            return;
        }
        hub_generate_sync_packet(state, full_sync, MAX_SYNC_PAYLOAD);
        hub_peer_enqueue_sync(state, c, CMD_PEER_SYNC, LANE_BULK, full_sync, "handshake_sync",
                              hub_next_lamport_seq(state));
        free(full_sync);
    }
    hub_activity_send_bans(state, c);
}

/* Queued like every frame after the handshake: a ping sent straight to the
 * socket landed inside a part-sent sync frame and broke the link. */
static bool send_ping(hub_state_t *state, hub_client_t *c) {
    return hub_client_send(state, c, CMD_PING, NULL);
}

static void hub_maintenance(hub_state_t *state) {
    time_t now = time(NULL);

    if (state->last_mesh_gossip == 0) state->last_mesh_gossip = now;
    if (state->last_client_scan == 0) state->last_client_scan = now;
    if (state->last_ip_cleanup  == 0) state->last_ip_cleanup  = now;

    /* Bot presence: gossip our own bots to the peers, expire entries nobody
     * refreshed, and push the tree to bots when it changed.  All volatile —
     * see the CMD_BOT_PRESENCE block in hub.h. */
    hub_presence_tick(state, now);

    /* Rolling network upgrade: one step per tick (no-op unless running). */
    hub_upgrade_tick(state, now);

    /* Channel-request elections: probe windows and hand-off timeouts. */
    hub_chan_elect_tick(state, now);

    /* Expired bans: one `del` per ban, self-throttled to BAN_SWEEP_INTERVAL. */
    hub_bans_sweep(state, now);

    /* The full config push owed to the bots, coalesced across a burst. */
    hub_flush_bot_config(state, now);

    /* Mesh state gossip: every 5 min as heartbeat, or immediately when peer
     * topology changes (connect/disconnect sets mesh_state_dirty). */
    if (state->mesh_state_dirty || (now - state->last_mesh_gossip > 300)) {
        state->last_mesh_gossip = now;
        state->mesh_state_dirty = false;
        if (state->peer_count > 0)
            hub_broadcast_mesh_state(state);
    }

    /* Anti-entropy: stagger first fire 30–90 s, then every MESH_ANTI_ENTROPY_INTERVAL */
    if (state->last_anti_entropy == 0) {
        unsigned int jitter = 30 + (unsigned int)(rand() % 61);
        state->last_anti_entropy = now - (time_t)(MESH_ANTI_ENTROPY_INTERVAL - jitter);
    }
    if (now - state->last_anti_entropy > MESH_ANTI_ENTROPY_INTERVAL) {
        state->last_anti_entropy = now;
        if (state->peer_count > 0) {
            /* Heap, sized to the sync ceiling: a 16 KB buffer truncated
             * anti-entropy the same way it truncated the startup sync. */
            char *full_sync = malloc(MAX_SYNC_PAYLOAD);
            if (full_sync) {
                hub_generate_sync_packet(state, full_sync, MAX_SYNC_PAYLOAD);
                hub_broadcast_sync_to_peers(state, full_sync, -1);
                free(full_sync);
            } else {
                hub_log_error("[MESH] OOM building anti-entropy sync\n");
            }
        }
    }

    /* Config write debounce */
    if (state->config_dirty &&
        (now - state->last_config_write) >= CONFIG_WRITE_DEBOUNCE_S) {
        hub_config_write(state);
        state->config_dirty = false;
        state->last_config_write = now;
    }

    /* IP allow/deny lists changed: the accept-time check only sees new
     * connections, so close the inbound ones the lists no longer permit.
     * (The admin who made the change is permitted: the change is refused
     * otherwise.)  Outbound peer links are operator-configured, not listed. */
    if (state->ip_acl_changed) {
        state->ip_acl_changed = false;
        for (int i = 0; i < state->client_count; i++) {
            hub_client_t *c = state->clients[i];
            if (c->inbound && !hub_ip_acl_permits(state, c->ip)) {
                hub_log_warning("[ACCESS_CONTROL] Closing %s: no longer permitted by "
                        "the allow/deny lists\n", c->ip);
                hub_disconnect_client(state, c);
                i--;
            }
        }
    }

    /* IP rate-limit cleanup: every 5 minutes */
    if (now - state->last_ip_cleanup > 300) {
        cleanup_old_ip_limits(state);
        state->last_ip_cleanup = now;
    }

    /* Scheduled tombstone purge: daily, leader only */
    if (state->purge_days_setting > 0) {
        if (state->last_purge == 0) state->last_purge = now;
        if (now - state->last_purge > 86400) {
            state->last_purge = now;
            state->config_dirty = true;   /* purge_last|: a restart keeps the day */
            if (hub_should_initiate_scheduled_purge(state)) {
                hub_log_info("[HUB] Running scheduled purge (older than %d days)\n",
                        state->purge_days_setting);
                time_t cutoff = now - ((time_t)state->purge_days_setting * 86400);
                int purged = hub_execute_purge(state, cutoff, NULL);
                if (purged > 0)
                    hub_log_info("[HUB] Scheduled purge removed %d tombstones\n", purged);
                hub_broadcast_purge(state, cutoff);
            } else {
                hub_log_info("[HUB] Scheduled purge skipped (not elected leader in mesh)\n");
            }
        }
    }

    /* Client timeout/ping scan: every 5 s (was every 250 ms — no need to scan
     * 50+ clients 4x/sec when the ping window is 60 s and timeout is 180 s). */
    if (now - state->last_client_scan >= 5) {
        state->last_client_scan = now;
        for (int i = 0; i < state->client_count; i++) {
            hub_client_t *c = state->clients[i];
            /* An SSH console has no pings: the console thread owns its idle
             * timeout, and the socketpair closes when the session does. */
            if (c->internal) continue;
            if ((now - c->last_seen) > CLIENT_TIMEOUT) {
                hub_log_warning("[HUB] Client %s timed out.\n", c->ip);
                hub_disconnect_client(state, c);
                i--;
                continue;
            }
            /* Output queued and none of it taken for WRITE_STALL_TIMEOUT: the
             * other end stopped reading (14b).  It reconnects once healthy. */
            if (peer_has_pending_writes(c) && c->write_wait_since > 0 &&
                (now - c->write_wait_since) > WRITE_STALL_TIMEOUT) {
                hub_log_warning("[HUB] %s took no output for %lds — dropping\n",
                                hub_who_client(state, c), (long)(now - c->write_wait_since));
                hub_disconnect_client(state, c);
                i--;
                continue;
            }
            /* D4: reap connections that never authenticated within the pre-auth
             * window. Uses connected_at (not last_seen) so a slowloris that
             * dribbles bytes to keep last_seen fresh is still dropped. Outbound
             * CLIENT_HUB peers are trusted, operator-configured endpoints and
             * are exempt. */
            if (!c->authenticated && c->type != CLIENT_HUB &&
                (now - c->connected_at) > PREAUTH_TIMEOUT_SEC) {
                if (c->bot_auth_state == BOT_AUTH_QUARANTINE)
                    hub_log_info("[REVOKE] Revoked %s did not answer the wipe (an "
                                 "older build?); closed\n", hub_who_client(state, c));
                else
                    hub_log_warning("[HUB] Pre-auth timeout for %s (%lds, no handshake) — "
                            "dropping\n", c->ip, (long)(now - c->connected_at));
                hub_disconnect_client(state, c);
                i--;
                continue;
            }
            /* A deleted bot told CMD_BOT_RETIRE that never answered. */
            if (c->retiring && (now - c->retire_sent) > RETIRE_GRACE_SEC) {
                hub_log_info("[REVOKE] Deleted %s did not answer the wipe; closed\n",
                             hub_who_client(state, c));
                hub_disconnect_client(state, c);
                i--;
                continue;
            }
            if (c->authenticated && (now - c->last_seen) > PING_INTERVAL) {
                if (!send_ping(state, c)) {
                    hub_log_warning("[HUB] Ping failed to %s. Disconnecting.\n", c->ip);
                    hub_disconnect_client(state, c);
                    i--;
                    continue;
                }
            }
        }
    }
}

static bool peer_dialing(const hub_state_t *state, const char *uuid);

static void hub_check_peers(hub_state_t *state) {
    time_t now = time(NULL);

    if (now - state->last_peer_check < PEER_RECONNECT_INTERVAL) return;
    state->last_peer_check = now;

    for (int i = 0; i < state->peer_count; i++) {
        if (state->peers[i].connected || peer_dialing(state, state->peers[i].uuid))
            continue;
        hub_log_debug("[PEER] Attempting to connect to %s:%d...\n",
                      state->peers[i].ip, state->peers[i].port);

        /* Review 16: non-blocking, finished by hub_finish_dials from the
         * main loop; a blocking connect() froze the hub for up to
         * CONNECT_TIMEOUT per unreachable peer. */
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) continue;
        int fl = fcntl(sockfd, F_GETFL, 0);
        if (fl < 0 || fcntl(sockfd, F_SETFL, fl | O_NONBLOCK) < 0) {
            close(sockfd);
            continue;
        }

        struct sockaddr_in peer_addr;
        memset(&peer_addr, 0, sizeof(peer_addr));
        peer_addr.sin_family = AF_INET;
        peer_addr.sin_port = htons((uint16_t)state->peers[i].port);
        if (inet_pton(AF_INET, state->peers[i].ip, &peer_addr.sin_addr) != 1) {
            hub_log_warning("[PEER] Bad address %s for peer %s\n", state->peers[i].ip,
                            hub_who(state, 'h', state->peers[i].uuid));
            close(sockfd);
            continue;
        }
        if (connect(sockfd, (struct sockaddr *)&peer_addr, sizeof(peer_addr)) != 0 &&
            errno != EINPROGRESS) {
            hub_log_warning("[PEER] Failed to connect to %s:%d\n",
                            state->peers[i].ip, state->peers[i].port);
            close(sockfd);
            continue;
        }
        if (state->client_count >= MAX_CLIENTS) {
            close(sockfd);
            hub_log_warning("[PEER] Client limit reached.\n");
            continue;
        }
        hub_client_t *c = calloc(1, sizeof(hub_client_t));
        /* D2: outbound peers immediately exchange bulk anti-entropy sync, so
         * allocate full-size buffers up front. */
        if (!c || !hub_client_alloc_buffers(c, MAX_BUFFER)) {
            free(c);
            close(sockfd);
            continue;
        }
        c->fd = sockfd;
        c->conn_serial = hub_next_conn_serial();
        snprintf(c->ip, sizeof(c->ip), "%s", state->peers[i].ip);
        c->type = CLIENT_HUB;
        /* Named as an inbound peer is once it authenticates, so what logs a
         * link's id names this one too. */
        snprintf(c->id, sizeof(c->id), "%s",
                 state->peers[i].friendly_name[0] ? state->peers[i].friendly_name : "HUB-PEER");
        c->last_seen = now;
        c->connected_at = now;  /* D4 (exempt: CLIENT_HUB) */
        c->dialing = true;
        c->dial_started = now;
        snprintf(c->dial_uuid, sizeof(c->dial_uuid), "%s", state->peers[i].uuid);
        state->clients[state->client_count++] = c;
    }
}

/* A dial to the peer with this uuid is in flight. */
static bool peer_dialing(const hub_state_t *state, const char *uuid) {
    for (int i = 0; i < state->client_count; i++)
        if (state->clients[i]->dialing && strcmp(state->clients[i]->dial_uuid, uuid) == 0)
            return true;
    return false;
}

/* Review 16: finish the dials hub_check_peers started.  Writable means the
 * connect() is done: SO_ERROR says how.  Up, the socket goes back to
 * blocking with the SO_SNDTIMEO the old blocking dial had (everything after
 * the connect is as before) and the HUBv3 handshake runs, unless the peer
 * linked to us meanwhile (then this dial is not needed).  Past
 * CONNECT_TIMEOUT it is given up, as the blocking connect gave up. */
static void hub_finish_dials(hub_state_t *state, fd_set *write_fds) {
    time_t now = time(NULL);
    for (int i = 0; i < state->client_count; i++) {
        hub_client_t *c = state->clients[i];
        if (!c->dialing) continue;
        int p = -1;
        for (int k = 0; k < state->peer_count && p < 0; k++)
            if (strcmp(state->peers[k].uuid, c->dial_uuid) == 0) p = k;
        bool ready = fd_isset(c->fd, write_fds);
        if (!ready && now - c->dial_started <= CONNECT_TIMEOUT && p >= 0) continue;
        int err = 0;
        socklen_t el = sizeof(err);
        if (ready && getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0) err = errno;
        c->dialing = false;
        if (p < 0 || state->peers[p].connected) {
            /* the peer was deleted, or it linked to us first */
            hub_disconnect_client(state, c);
            i--;
            continue;
        }
        if (!ready || err != 0) {
            hub_log_warning("[PEER] Failed to connect to %s:%d%s%s\n", state->peers[p].ip,
                            state->peers[p].port, ready ? ": " : " (timed out)",
                            ready ? strerror(err) : "");
            hub_disconnect_client(state, c);
            i--;
            continue;
        }
        int fl = fcntl(c->fd, F_GETFL, 0);
        struct timeval timeout = {CONNECT_TIMEOUT, 0};
        if (fl < 0 || fcntl(c->fd, F_SETFL, fl & ~O_NONBLOCK) < 0 ||
            setsockopt(c->fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0)
            hub_log_error("[HUB] socket options failed for %s\n", c->ip);
        c->last_seen = now;
        state->peers[p].connected = true;
        state->peers[p].fd = c->fd;
        state->mesh_state_dirty = true;
        int before = state->client_count;
        hub_peer_handshake(state, c, &state->peers[p]);
        if (state->client_count < before) i--;  /* the handshake dropped it */
    }
}


static void read_pass_hidden(const char *prompt, char *buf, size_t len) {
    struct termios oldt, newt;
    int is_tty = (tcgetattr(STDIN_FILENO, &oldt) == 0);
    printf("%s", prompt);
    fflush(stdout);
    if (is_tty) {
        newt = oldt;
        newt.c_lflag &= ~(tcflag_t)(ECHO | ECHONL);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }
    if (!fgets(buf, (int)len, stdin)) buf[0] = 0;
    if (is_tty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    }
    printf("\n");
    buf[strcspn(buf, "\n")] = 0;
}

static void passfile_build_context(char *buf, size_t len) {
    struct stat home_st;
    struct utsname uts;
    struct passwd *pw = getpwuid(getuid());
    memset(&home_st, 0, sizeof(home_st));
    memset(&uts, 0, sizeof(uts));
    if (pw && pw->pw_dir) stat(pw->pw_dir, &home_st);
    uname(&uts);
    snprintf(buf, len, "%ju:%ju:%u:%u:%.64s",
             (uintmax_t)home_st.st_ino, (uintmax_t)home_st.st_dev,
             (unsigned int)getuid(), (unsigned int)getgid(), uts.machine);
}

static bool passfile_derive_key(const char *ctx, const unsigned char *salt,
                                int iterations, unsigned char *key) {
    return PKCS5_PBKDF2_HMAC(ctx, (int)strlen(ctx), salt, SALT_SIZE,
                             iterations, EVP_sha256(), 32, key) == 1;
}

static bool passfile_load(const char *path, char *out_pass, size_t out_len) {
    struct stat st;
    bool ok = false;
    if (stat(path, &st) != 0) return false;
    if (st.st_uid != getuid()) {
        fprintf(stderr, "[WARN] .irchub.pass: wrong owner, ignoring.\n");
        return false;
    }
    if ((st.st_mode & 0777) != 0600) {
        fprintf(stderr, "[WARN] .irchub.pass: must be 0600, ignoring.\n");
        return false;
    }
    int min_size = SALT_SIZE + GCM_IV_LEN + 1 + GCM_TAG_LEN;
    if (st.st_size < min_size) return false;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    size_t total = (size_t)st.st_size;
    unsigned char *buf = malloc(total);
    if (!buf) { close(fd); return false; }
    if (read(fd, buf, total) != (ssize_t)total) { close(fd); free(buf); return false; }
    close(fd);
    unsigned char *salt    = buf;
    unsigned char *enc_blk = buf + SALT_SIZE;
    int enc_len            = (int)(total - SALT_SIZE - GCM_TAG_LEN);
    unsigned char *tag     = buf + SALT_SIZE + enc_len;
    unsigned char key[32];
    char ctx[256];
    passfile_build_context(ctx, sizeof(ctx));
    mlock(out_pass, out_len);
    unsigned char *plain = malloc((size_t)enc_len);
    if (!plain) goto done;
    mlock(plain, (size_t)enc_len);
    int dec_len = -1;
    if (passfile_derive_key(ctx, salt, PBKDF2_ITERATIONS, key))
        dec_len = aes_gcm_decrypt(enc_blk, enc_len, key, plain, tag);
    if (dec_len > 0 && (size_t)dec_len < out_len) {
        plain[dec_len] = 0;
        memcpy(out_pass, plain, (size_t)dec_len + 1);
        ok = true;
    } else {
        fprintf(stderr, "[WARN] .irchub.pass: decryption failed "
                        "(wrong machine, tampered, or written before 2.5.0), "
                        "falling through.\n");
    }
    secure_wipe(plain, (size_t)enc_len);
    munlock(plain, (size_t)enc_len);
    free(plain);
done:
    secure_wipe(key, sizeof(key));
    secure_wipe(ctx, sizeof(ctx));
    munlock(out_pass, out_len);
    free(buf);
    return ok;
}

/* File layout: [SALT_SIZE][IV+ciphertext from aes_gcm_encrypt][GCM_TAG_LEN]
 * aes_gcm_encrypt prepends the random IV to its output automatically.
 * aes_gcm_decrypt expects that same IV+ciphertext block as input.        */
static bool passfile_create(const char *path, const char *password) {
    unsigned char salt[SALT_SIZE];
    unsigned char key[32];
    unsigned char tag[GCM_TAG_LEN];
    char ctx[256];
    bool ok = false;

    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        fprintf(stderr, "RNG failure.\n");
        goto done;
    }

    passfile_build_context(ctx, sizeof(ctx));
    if (!passfile_derive_key(ctx, salt, PBKDF2_ITERATIONS, key)) {
        fprintf(stderr, "Key derivation failed.\n");
        goto done;
    }

    int pass_len = (int)strlen(password);
    /* aes_gcm_encrypt output = GCM_IV_LEN (prepended) + ciphertext */
    unsigned char *enc_buf = malloc((size_t)(GCM_IV_LEN + pass_len));
    if (!enc_buf) goto done;

    int enc_len = aes_gcm_encrypt((const unsigned char *)password, pass_len,
                                  key, enc_buf, tag);
    if (enc_len <= 0) {
        fprintf(stderr, "Encryption failed.\n");
        free(enc_buf);
        goto done;
    }

    /* Written beside it and renamed over it, so a rewrite (-p) never leaves
     * a half-written pass file. */
    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) {
        free(enc_buf); goto done;
    }
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { perror("open"); free(enc_buf); goto done; }

    if (fchmod(fd, 0600) != 0) {
        perror("fchmod"); close(fd); remove(tmp); free(enc_buf); goto done;
    }

    ok = (write(fd, salt,    SALT_SIZE)   == SALT_SIZE &&
          write(fd, enc_buf, (size_t)enc_len)     == enc_len   &&
          write(fd, tag,     GCM_TAG_LEN) == GCM_TAG_LEN);

    if (!ok) perror("write .irchub.pass");
    if (close(fd) != 0) ok = false;
    if (ok && rename(tmp, path) != 0) { perror("rename .irchub.pass"); ok = false; }
    if (!ok) remove(tmp);
    free(enc_buf);

done:
    secure_wipe(key, sizeof(key));
    secure_wipe(ctx, sizeof(ctx));
    return ok;
}

/* Process hardening: keep secrets out of anything that lands on disk.
 *
 * PR_SET_DUMPABLE(0) suppresses the core dump on a crash.  Without it a crash
 * hands every admin/oper plaintext password in user_records[], plus
 * config_pass and both hub private keys, to core_pattern -- on a default
 * Ubuntu host that pipes to systemd-coredump, i.e. straight to disk.  It also
 * blocks same-uid ptrace attach, complementing kernel.yama.ptrace_scope.
 *
 * RLIMIT_CORE 0 covers the same ground and is inherited across exec.
 *
 * Neither defends against root.  Called before any config or key material is
 * loaded.  Mirrors harden_process() in ircbot/main.c. */
static void harden_process(void) {
    /* Private by default whatever the shell's umask (Ubuntu's is 002): the
     * setup wizard, pid, log and upgrade staging all inherit it. */
    umask(0077);
    struct rlimit rl = { 0, 0 };
    setrlimit(RLIMIT_CORE, &rl);
#ifdef PR_SET_DUMPABLE
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
}

/* Instance directory: .irchub.cnf/.pass/.pid/.log/.upgrade and hub_upgrade.sh
 * all live beside the binary, so the hub behaves the same whatever the
 * caller's cwd -- cron starts jobs in $HOME.  One binary per hub.  Our own
 * path comes from /proc/self/exe (argv[0] has no directory when launched
 * through PATH); fills `exe` with it and chdir()s to its directory.  That
 * directory holds the binary an upgrade replaces, its .prev and the upgrade
 * script, so refuse one another user owns and chmod go-w one group/other can
 * write -- they could swap any of them. */
static bool instance_dir_enter(char *exe, size_t exe_len) {
    ssize_t n = readlink("/proc/self/exe", exe, exe_len - 1);
    if (n <= 0 || (size_t)n >= exe_len - 1) {
        fprintf(stderr, "Cannot resolve my own path (/proc/self/exe)\n");
        return false;
    }
    exe[n] = '\0';
    char dir[PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", exe);
    char *slash = strrchr(dir, '/');
    if (!slash) {
        fprintf(stderr, "Cannot resolve my own directory from %s\n", exe);
        return false;
    }
    slash[slash == dir ? 1 : 0] = '\0';
    /* fd-based from here on: the directory inspected is the one fixed and
     * entered. */
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    struct stat st;
    if (dfd < 0 || fstat(dfd, &st) != 0) {
        if (dfd >= 0) close(dfd);
        fprintf(stderr, "Cannot stat my own directory %s\n", dir);
        return false;
    }
    if (st.st_uid != geteuid()) {
        close(dfd);
        fprintf(stderr, "Refusing to run from %s: it must be owned by this "
                        "user\n", dir);
        return false;
    }
    /* Group/other write (a 002 umask makes 0775 directories): we own it, so
     * close the hole rather than refuse -- refusing turned every upgrade on
     * such a host into a watchdog rollback and a fresh install into a dead
     * start.  Nothing is weakened: the directory was open before we ran. */
    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
        mode_t m = st.st_mode & 07777 & ~(mode_t)(S_IWGRP | S_IWOTH);
        if (fchmod(dfd, m) != 0) {
            fprintf(stderr, "Refusing to run from %s: group/other can write it "
                            "and chmod go-w failed (%s)\n", dir, strerror(errno));
            close(dfd);
            return false;
        }
        fprintf(stderr, "Removed group/other write from %s (now %04o)\n", dir,
                (unsigned)m);
    }
    if (fchdir(dfd) != 0) {
        close(dfd);
        fprintf(stderr, "Cannot change to my own directory %s\n", dir);
        return false;
    }
    close(dfd);
    return true;
}

/* -setup: read a user's public key — the pasted 88-char key, or a path to
 * their .public.b64 — show its fingerprint and confirm.  False on EOF. */
static bool setup_read_pubkey(const char *who, char out[COMBINED_KEY_B64 + 1]) {
    for (;;) {
        char in[PATH_MAX];
        unsigned char raw[COMBINED_KEY_LEN];
        out[0] = '\0';
        printf("Public key for '%s' (paste the 88 chars, or a path to the "
               ".public.b64): ", who);
        fflush(stdout);
        if (!fgets(in, sizeof(in), stdin)) return false;
        in[strcspn(in, "\r\n")] = '\0';
        if (in[0] == '\0') {
            printf("A public key is required (run ./keygen %s on the admin's "
                   "machine).\n", who);
            continue;
        }
        /* Private and public key files have the same shape; refuse a keygen
         * private file by name before it gets published in the a| record. */
        if (strstr(in, ".private.")) {
            printf("That is a PRIVATE key file — it stays with the admin. "
                   "Use the matching .public.b64.\n");
            continue;
        }
        if (hub_crypto_pubkey_b64_decode(in, raw)) {
            memcpy(out, in, COMBINED_KEY_B64);   /* validated: exactly 88 */
        } else {
            FILE *f = fopen(in, "r");
            char line[256] = {0};
            if (f) {
                if (!fgets(line, sizeof(line), f)) line[0] = '\0';
                fclose(f);
                line[strcspn(line, " \t\r\n")] = '\0';
            }
            if (!line[0] || !hub_crypto_pubkey_b64_decode(line, raw)) {
                printf("Not an 88-char public key%s. Use the .public.b64 — "
                       "never the .private.b64.\n", f ? " in that file" : "");
                continue;
            }
            memcpy(out, line, COMBINED_KEY_B64);
        }
        out[COMBINED_KEY_B64] = '\0';
        char fp[KEY_FP_LEN + 1], yn[16] = {0};
        hub_crypto_key_fingerprint(raw, fp);
        printf("  Key fingerprint: %s — use this key? (Y/n): ", fp);
        fflush(stdout);
        if (!fgets(yn, sizeof(yn), stdin)) return false;
        if (yn[0] != 'n' && yn[0] != 'N') return true;
    }
}

/* -id: print this hub's name, uuid, public key and fingerprints — what
 * another hub's `hub add` and a bot's -setup / +hub need — from the config
 * (the key lives there; hub_public.b64 is only -setup's copy), and exit.
 * Read-only: no daemon, no PID lock, no config rewrite. */
static int run_identity(hub_state_t *state, char *password) {
    g_hub_config_readonly = true;
    hub_set_config_pass(state, password);
    bool ok = hub_config_load(state, password);
    secure_wipe(password, MAX_PASS);
    OPENSSL_cleanse(state->config_pass, sizeof(state->config_pass));
    hub_config_key_forget(state);
    /* The public key is derived from the private key, not taken from the
     * stored pub| copy: that is what peers and bots must pin. */
    unsigned char priv64[64], pub64[64];
    memcpy(priv64, state->hub_ed25519_priv, 32);
    memcpy(priv64 + 32, state->hub_x25519_priv, 32);
    bool derived = ok && state->hub_keys_loaded &&
                   hub_crypto_combined_pub_from_priv(priv64, pub64);
    secure_wipe(priv64, sizeof(priv64));
    OPENSSL_cleanse(state->hub_ed25519_priv, sizeof(state->hub_ed25519_priv));
    OPENSSL_cleanse(state->hub_x25519_priv, sizeof(state->hub_x25519_priv));
    if (!ok) {
        fprintf(stderr, "Cannot load %s (wrong password?).\n", HUB_CONFIG_FILE);
        return 1;
    }
    if (!derived || !state->hub_uuid[0]) {
        fprintf(stderr, "%s has no hub key or uuid; re-run -setup.\n", HUB_CONFIG_FILE);
        return 1;
    }
    if (memcmp(pub64, state->hub_ed25519_pub, 32) != 0 ||
        memcmp(pub64 + 32, state->hub_x25519_pub, 32) != 0)
        fprintf(stderr, "Note: the stored public key does not match the private key; "
                        "the key below is the right one (console: hub set pubkey).\n");
    char *pub_b64 = base64_encode(pub64, 64);
    if (!pub_b64) return 1;
    char fp[KEY_FP_LEN + 1], ssh_fp[80];
    hub_crypto_key_fingerprint(pub64, fp);
    console_ssh_fingerprint(pub64, ssh_fp, sizeof(ssh_fp));
    /* bind_ip is what the mesh is told to dial; a wildcard tells nobody. */
    bool wild = !state->bind_ip[0] || strcmp(state->bind_ip, "0.0.0.0") == 0;
    const char *ip = wild ? "<this-hub's-address>" : state->bind_ip;
    const char *name = state->hub_friendly_name[0] ? state->hub_friendly_name : "-";
    printf("Hub name:        %s\n", name);
    printf("Hub UUID:        %s\n", state->hub_uuid);
    printf("Hub public key:  %s\n", pub_b64);
    printf("Key fingerprint: %s\n", fp);
    printf("SSH host key:    ssh-ed25519 %s\n", ssh_fp);
    printf("Listening:       %s:%d\n", wild ? "0.0.0.0" : state->bind_ip, state->port);
    printf("Other hubs:      hub add %s %d %s %s %s\n", ip, state->port,
           state->hub_uuid, name, pub_b64);
    printf("Bots:            +hub %s:%d %s\n", ip, state->port, pub_b64);
    free(pub_b64);
    return 0;
}

int main(int argc, char *argv[]) {
    harden_process();

    /* DoS hardening: each accepted connection allocates a ~33 KB hub_client_t.
     * glibc keeps freed chunks of that size in the arena (they exceed the
     * default trim threshold but sit below the dynamic mmap threshold), so a
     * rapid connect/close flood grows RSS unboundedly even though the structs
     * are freed.  Force allocations >= 32 KB through mmap so free() returns
     * them to the OS, and lower the trim threshold, bounding RSS under churn.
     * This tuning is glibc-arena-specific; other allocators (notably FreeBSD's
     * jemalloc) already return such allocations to the OS, so it is skipped
     * there. */
#if defined(__GLIBC__)
    mallopt(M_MMAP_THRESHOLD, 32 * 1024);
    mallopt(M_TRIM_THRESHOLD, 64 * 1024);
#endif

    bool setup_mode = false;
    bool passfile_mode = false;
    bool selftest_mode = false;
    bool identity_mode = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-setup") == 0) setup_mode = true;
        if (strcmp(argv[i], "-p")     == 0) passfile_mode = true;
        if (strcmp(argv[i], "-id")    == 0) identity_mode = true;
        /* -checkupdate [variant]: verify the release channel and exit; needs
         * no config, no password and no PID lock. */
        if (strcmp(argv[i], "-checkupdate") == 0)
            return hub_update_check_cli(i + 1 < argc ? argv[i + 1] : NULL);
        /* -selftest: could this binary run here, on this config?  No daemon,
         * no PID lock, no network, no config rewrite — run on a STAGED build
         * by the updater before anything is swapped. */
        if (strcmp(argv[i], "-selftest") == 0) selftest_mode = true;
    }

    /* -selftest stays in the caller's directory: the updater runs a staged
     * build from a scratch subdirectory, against this hub's config. */
    static char self_exe[PATH_MAX];
    if (!selftest_mode && !instance_dir_enter(self_exe, sizeof(self_exe)))
        return 1;

    static hub_state_t state;
    memset(&state, 0, sizeof(state));
    state.console_ctl_fd = -1;

    /* Lock the secret-bearing fields into RAM so they cannot reach swap or a
     * hibernation image.  hub_state_t is ~8.1 MB -- bots[] alone is 6.8 MB of
     * public config entries -- so it exceeds RLIMIT_MEMLOCK (4 MB here) and
     * cannot be locked wholesale the way ircbot's bot_state_t is.  Lock only
     * what is actually secret: ~14 KB total.  peers[] is deliberately absent,
     * it holds only public keys (hub_peer_config_t: ed_pub / x25519_pub).
     * Best-effort; a failure here is not fatal. */
    {
        struct { void *p; size_t n; const char *what; } locks[] = {
            { state.config_pass,      sizeof(state.config_pass),      "config_pass"      },
            { state.hub_ed25519_priv, sizeof(state.hub_ed25519_priv), "hub_ed25519_priv" },
            { state.hub_x25519_priv,  sizeof(state.hub_x25519_priv),  "hub_x25519_priv"  },
            { state.user_records,     sizeof(state.user_records),     "user_records"     },
        };
        for (size_t i = 0; i < sizeof(locks)/sizeof(locks[0]); i++)
            if (mlock(locks[i].p, locks[i].n) != 0)
                fprintf(stderr, "Warning: mlock(%s) failed - "
                                "secrets may reach swap.\n", locks[i].what);
    }
    /* The console log ring lives in its own mlock'd, MADV_DONTDUMP mapping
     * (hub_console_core.c); allocated before the first line is logged. */
    (void)hub_console_log_ring_init();
    state.running = true;
    g_state = &state;
    state.log_level = HUB_DEFAULT_LOG_LEVEL;
    state.console_log_level = HUB_DEFAULT_CONSOLE_LOG_LEVEL;
    state.log_max_size = HUB_LOG_FILE_SIZE;
    hub_conn_cfg_defaults(&state.conn_cfg);

    if (selftest_mode) {
        /* The swap happens in this directory: one another user owns is
         * refused at start (a group/other-writable one we own is tightened
         * there). */
        struct stat dst;
        if (stat(".", &dst) != 0 || dst.st_uid != geteuid()) {
            printf("selftest: FAIL this directory is not owned by this user\n");
            return 1;
        }
        if (access(HUB_CONFIG_FILE, R_OK) != 0) {
            printf("selftest: FAIL no readable %s\n", HUB_CONFIG_FILE);
            return 1;
        }
        char pw[MAX_PASS];
        memset(pw, 0, sizeof(pw));
        if (!passfile_load(HUB_PASS_FILE, pw, sizeof(pw)) || !pw[0]) {
            /* 2.5.1 reads only the 600k key; a pass file 2.5.0 never got to
             * rewrite is refused here so the upgrade reports it instead of
             * leaving a hub that cannot start. */
            secure_wipe(pw, sizeof(pw));
            printf("selftest: FAIL cannot read %s (written before 2.5.0? restart "
                   "once on 2.5.0, or rewrite it with -p)\n", HUB_PASS_FILE);
            return 1;
        }
        g_hub_config_readonly = true;
        hub_set_config_pass(&state, pw);
        bool ok = hub_config_load(&state, pw);
        secure_wipe(pw, sizeof(pw));
        OPENSSL_cleanse(state.config_pass, sizeof(state.config_pass));
        hub_config_key_forget(&state);
        OPENSSL_cleanse(state.hub_ed25519_priv, sizeof(state.hub_ed25519_priv));
        OPENSSL_cleanse(state.hub_x25519_priv, sizeof(state.hub_x25519_priv));
        if (!ok) {
            printf("selftest: FAIL cannot load %s\n", HUB_CONFIG_FILE);
            return 1;
        }
        printf("selftest: OK irchub %s %s\n", HUB_VERSION,
               hub_update_host_variant());
        return 0;
    }

    if (setup_mode) {
        int ch;

        printf("--- Setup ---\n");

        printf("Port: ");
        if (scanf("%d", &state.port) != 1) return 1;
        while ((ch = getchar()) != '\n' && ch != EOF);

        printf("Bind IP (default 0.0.0.0): ");
        fflush(stdout);
        {
            char bind_buf[65];
            memset(bind_buf, 0, sizeof(bind_buf));
            if (fgets(bind_buf, sizeof(bind_buf), stdin)) {
                bind_buf[strcspn(bind_buf, "\n")] = 0;
            }
            if (bind_buf[0] == 0) {
                snprintf(state.bind_ip, sizeof(state.bind_ip), "0.0.0.0");
            } else {
                snprintf(state.bind_ip, sizeof(state.bind_ip), "%.*s",
                         (int)(sizeof(state.bind_ip) - 1), bind_buf);
            }
        }

        for (;;) {
            char name_buf[128];
            printf("Friendly Name (A-Z a-z 0-9 . _ -, max 63): ");
            fflush(stdout);
            if (!fgets(name_buf, sizeof(name_buf), stdin)) {
                fprintf(stderr, "No hub name given.\n");
                return 1;
            }
            if (!strchr(name_buf, '\n') && strlen(name_buf) == sizeof(name_buf) - 1) {
                int drain;
                while ((drain = getchar()) != '\n' && drain != EOF) {}
                printf("Invalid name: longer than 63 characters.\n");
                continue;
            }
            name_buf[strcspn(name_buf, "\r\n")] = 0;
            if (hub_name_valid(name_buf)) {
                memcpy(state.hub_friendly_name, name_buf, strlen(name_buf) + 1);
                break;
            }
            printf("Invalid name: it is written into config lines and hub "
                   "handshakes, so 1-63 letters, digits, '.', '_' or '-'.\n");
        }

        generate_uuid_v4(state.hub_uuid, sizeof(state.hub_uuid));
        printf("Generated UUID: %s\n", state.hub_uuid);

        {
            char cfg_pass1[MAX_PASS], cfg_pass2[MAX_PASS];
            do {
                read_pass_hidden("Config Password: ", cfg_pass1, sizeof(cfg_pass1));
                if (!cfg_pass1[0]) {
                    printf("Password cannot be empty.\n");
                    continue;
                }
                read_pass_hidden("Confirm Config Password: ", cfg_pass2, sizeof(cfg_pass2));
                if (strcmp(cfg_pass1, cfg_pass2) != 0) {
                    printf("Passwords do not match. Try again.\n");
                }
            } while (!cfg_pass1[0] || strcmp(cfg_pass1, cfg_pass2) != 0);
            hub_set_config_pass(&state, cfg_pass1);
            secure_wipe(cfg_pass1, sizeof(cfg_pass1));
            secure_wipe(cfg_pass2, sizeof(cfg_pass2));
        }

        /* Per-hub independent keypair (no shared-keypair mesh).
         * Generate fresh; export only the public key.  The private key stays
         * inside the encrypted .irchub.cnf — no plaintext hub_private.b64
         * file is dumped any more. */
        {
            unsigned char priv64[64], pub64[64];
            printf("\n[*] Generating per-hub Curve25519 keypair (Ed25519 + X25519)...\n");
            if (!hub_crypto_generate_combined_keypair(priv64, pub64)) {
                printf("Key generation failed.\n");
                return 1;
            }
            hub_crypto_split_combined(priv64, state.hub_ed25519_priv, state.hub_x25519_priv);
            hub_crypto_split_combined(pub64,  state.hub_ed25519_pub,  state.hub_x25519_pub);
            state.hub_keys_loaded = true;

            char *pub_b64 = base64_encode(pub64, 64);
            secure_wipe(priv64, 64);
            if (pub_b64) {
                /* Dump the public key only.  The private key is persisted
                 * inside the AES-256-GCM encrypted .irchub.cnf. */
                int pfd = open("hub_public.b64",
                               O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (pfd >= 0) {
                    FILE *fpu = fdopen(pfd, "w");
                    if (fpu) { fprintf(fpu, "%s", pub_b64); fclose(fpu); }
                    else close(pfd);
                }
                printf("[+] Public key saved to: hub_public.b64\n");
                printf("[+] Public key: %s\n\n", pub_b64);
                printf("    ┌─────────────────────────────────────────────────┐\n");
                printf("    │ Save this public key + this hub's UUID.         │\n");
                printf("    │   - Bots adding this hub will need both         │\n");
                printf("    │     (ircbot -setup prompts for UUID + pubkey).  │\n");
                printf("    │   - Other hubs adding this hub will need the    │\n");
                printf("    │     UUID + ip:port + pubkey (console: hub add). │\n");
                printf("    │ The hub's PRIVATE key never leaves this machine │\n");
                printf("    │ (stored encrypted inside .irchub.cnf).          │\n");
                printf("    └─────────────────────────────────────────────────┘\n");
                free(pub_b64);
            }
            printf("[+] Curve25519 keypair generated.\n");
            {
                /* What ssh shows admins on their first login to the console. */
                char sshfp[80];
                console_ssh_fingerprint(state.hub_ed25519_pub, sshfp, sizeof(sshfp));
                printf("[+] SSH console host key: ssh-ed25519 %s\n", sshfp);
                printf("    Admins check it on first connect (keygen --ssh-fingerprint\n");
                printf("    hub_public.b64 prints the same line).\n");
                printf("[+] ./irchub -id prints this hub's uuid and keys again at any time.\n");
            }
        }
        (void)ch;

        /* Admin user setup — creates the first a| and m| records.  Admins
         * have no password: the operator generates the admin's keypair on the
         * admin's own machine (keygen <name>) and imports only the PUBLIC key
         * here.  The hub never sees or prints a user's private key. */
        printf("\n--- First Admin Setup ---\n");
        printf("This creates the first named admin, who can log into the hub's SSH\n");
        printf("console and command bots over IRC. Admins sign in with a Curve25519 key,\n");
        printf("not a password: on the admin's own machine run\n");
        printf("    ./keygen <name>      (irchub/bin/keygen or ircbot/utils/keygen)\n");
        printf("keep the <ts>_<name>.private.b64 there (chmod 600), and give this\n");
        printf("wizard the <ts>_<name>.public.b64.\n\n");
        {
            char bot_admin_name[64] = {0};

            /* Name */
            while (bot_admin_name[0] == '\0') {
                printf("Admin friendly name (no spaces, e.g. robert): ");
                fflush(stdout);
                if (!fgets(bot_admin_name, sizeof(bot_admin_name), stdin)) break;
                bot_admin_name[strcspn(bot_admin_name, "\n")] = '\0';
                if (strchr(bot_admin_name, ' ') || strchr(bot_admin_name, '|')) {
                    printf("Name cannot contain spaces or '|'. Try again.\n");
                    bot_admin_name[0] = '\0';
                }
            }
            if (!bot_admin_name[0]) {
                fprintf(stderr, "No admin name given; setup aborted.\n");
                return 1;
            }

            /* Public key: pasted, or a path to the .public.b64 */
            char admin_pub_b64[COMBINED_KEY_B64 + 1] = {0};
            if (!setup_read_pubkey(bot_admin_name, admin_pub_b64)) {
                fprintf(stderr, "No public key given; setup aborted.\n");
                return 1;
            }

            /* Generate UUID and create the user record */
            char new_uuid[37];
            generate_uuid_v4(new_uuid, sizeof(new_uuid));
            time_t now = time(NULL);

            if (state.user_record_count < MAX_HUB_USER_RECORDS) {
                hub_user_record_t *u = &state.user_records[state.user_record_count++];
                memset(u, 0, sizeof(*u));
                snprintf(u->uuid,       sizeof(u->uuid),       "%s", new_uuid);
                snprintf(u->name,       sizeof(u->name),       "%s", bot_admin_name);
                snprintf(u->pubkey_b64, sizeof(u->pubkey_b64), "%s", admin_pub_b64);
                u->has_pubkey = true;
                u->type = 'a'; u->is_active = true; u->timestamp = now;
            }

            /* Collect usermasks in a loop */
            int masks_added = 0;
            printf("\nEnter usermasks for this admin (e.g. nick!*@*.example.com).\n");
            printf("Press Enter with no mask when done (at least one required).\n\n");
            while (state.mask_record_count < MAX_HUB_USER_MASKS) {
                char mask_buf[MAX_MASK_LEN] = {0};
                printf("Usermask %d%s: ", masks_added + 1,
                       masks_added == 0 ? " (required)" : " (or Enter to finish)");
                fflush(stdout);
                if (!fgets(mask_buf, sizeof(mask_buf), stdin)) break;
                mask_buf[strcspn(mask_buf, "\n")] = '\0';
                if (mask_buf[0] == '\0') {
                    if (masks_added == 0) {
                        printf("At least one usermask is required.\n");
                        continue;
                    }
                    break;
                }
                if (!strchr(mask_buf, '!') || !strchr(mask_buf, '@')) {
                    printf("Invalid — mask must contain '!' and '@'. Try again.\n");
                    continue;
                }
                hub_mask_record_t *m = &state.mask_records[state.mask_record_count++];
                memset(m, 0, sizeof(*m));
                snprintf(m->uuid, sizeof(m->uuid), "%s", new_uuid);
                snprintf(m->mask, sizeof(m->mask), "%s", mask_buf);
                m->is_active = true; m->timestamp = now;
                masks_added++;
            }

            printf("[+] Admin '%s' created with %d usermask(s), UUID %s\n",
                   bot_admin_name, masks_added, new_uuid);
            printf("    Their SSH key:     <ts>_%s_ed25519 (keygen writes it with the IRC key)\n",
                   bot_admin_name);
            printf("    then log in with:  ssh -i <ts>_%s_ed25519 -p <hub port> %s@<hub>\n",
                   bot_admin_name, bot_admin_name);
        }

        hub_config_write(&state);
        secure_wipe(state.config_pass, sizeof(state.config_pass));
        hub_config_key_forget(&state);
        printf("Done.\n");

        secure_wipe(state.hub_ed25519_priv, 32);
        secure_wipe(state.hub_x25519_priv,  32);
        return 0;
    }

    /* -p: create/replace .irchub.pass from an interactive password prompt */
    if (passfile_mode) {
        char pass1[MAX_PASS], pass2[MAX_PASS];
        do {
            read_pass_hidden("Config Password: ",         pass1, sizeof(pass1));
            if (!pass1[0]) {
                fprintf(stderr, "Password cannot be empty.\n");
                return 1;
            }
            read_pass_hidden("Confirm Config Password: ", pass2, sizeof(pass2));
            if (strcmp(pass1, pass2) != 0)
                printf("Passwords do not match. Try again.\n");
        } while (strcmp(pass1, pass2) != 0);

        bool ok = passfile_create(HUB_PASS_FILE, pass1);
        secure_wipe(pass1, sizeof(pass1));
        secure_wipe(pass2, sizeof(pass2));
        if (ok) {
            printf("Saved: %s (0600, machine-bound)\n", HUB_PASS_FILE);
            return 0;
        }
        fprintf(stderr, "Failed to create %s.\n", HUB_PASS_FILE);
        return 1;
    }

    /* Refuse to proceed without a config — avoids prompting into a dead end */
    if (access(HUB_CONFIG_FILE, F_OK) != 0) {
        fprintf(stderr, "No config file found. First run: ./irchub -setup\n");
        return 1;
    }

    /* Password resolution: .irchub.pass → stdin prompt.
     * Load into a temporary buffer first; XOR-protect into state after load. */
    char _hub_plain_pass[MAX_PASS];
    memset(_hub_plain_pass, 0, sizeof(_hub_plain_pass));
    {
        /* 1. Machine-bound password file */
        if (!_hub_plain_pass[0])
            passfile_load(HUB_PASS_FILE, _hub_plain_pass, sizeof(_hub_plain_pass));

        /* 2. Interactive prompt — only reached if no passfile */
        if (!_hub_plain_pass[0]) {
            read_pass_hidden("Config Password: ", _hub_plain_pass, sizeof(_hub_plain_pass));
            if (!_hub_plain_pass[0]) {
                fprintf(stderr, "No password provided.\n");
                return 1;
            }
        }
    }

    if (identity_mode) return run_identity(&state, _hub_plain_pass);

    fflush(stdout); /* or the buffered lines are written again by the fork */
    daemonize();

    /* Seed rand() after the double-fork so each hub process gets a different
     * sequence — used to stagger anti-entropy timing across the mesh. */
    srand((unsigned int)(time(NULL) ^ getpid()));

    log_fp = hub_log_open(false);

    signal(SIGPIPE, SIG_IGN);
    {
        /* No SA_RESTART: a stop signal interrupts select() at once. */
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = handle_signal;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
    }

    /* The binary an upgrade replaces, and the one <exe>.prev sits beside
     * (resolved by instance_dir_enter() at startup). */
    snprintf(state.executable_path, sizeof(state.executable_path), "%s", self_exe);

    // Create PID file with exclusive lock
    int pid_fd = open(HUB_PID_FILE, O_CREAT | O_RDWR, 0600);
    if (pid_fd == -1) {
        hub_log_error("Cannot create PID file\n");
        return 1;
    }
    if (flock(pid_fd, LOCK_EX | LOCK_NB) == -1) {
        hub_log_error("Hub already running (PID file locked)\n");
        close(pid_fd);
        return 1;
    }
    char pid_str[16];
    snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
    if (write(pid_fd, pid_str, strlen(pid_str)) < 0) {
        hub_log_warning("Failed to write PID\n");
    }
    state.pid_fd = pid_fd;

    /* The config password must be in place BEFORE the load: hub_config_load()
     * rewrites the file itself when it dedups or migrates records (passwordless
     * migration drops every password on the first start), and that write reads
     * state.config_pass — unset, it would re-encrypt the config under an empty
     * password and lock the hub out on the next start. */
    hub_set_config_pass(&state, _hub_plain_pass);
    if (!hub_config_load(&state, _hub_plain_pass)) {
        secure_wipe(_hub_plain_pass, sizeof(_hub_plain_pass));
        OPENSSL_cleanse(state.config_pass, sizeof(state.config_pass));
        hub_config_key_forget(&state);
        printf("Config load failed. Run -setup.\n");
        if (log_fp) fprintf(log_fp, "Config load failed.\n");
        remove(HUB_PID_FILE);
        return 1;
    }
    secure_wipe(_hub_plain_pass, sizeof(_hub_plain_pass));

    /* Ensure next_lamport_seq is above the time-based floor even on first
     * boot (when no lamport_seq key exists in config).  The config loader
     * sets it if the key is present; this covers the first-boot case. */
    {
        uint64_t time_floor = ((uint64_t)time(NULL)) << 10;
        if (state.next_lamport_seq < time_floor)
            state.next_lamport_seq = time_floor;
    }

    // Set default bind_ip if not configured
    if (!state.bind_ip[0]) {
        snprintf(state.bind_ip, sizeof(state.bind_ip), "127.0.0.1");
    }

    if (!state.hub_keys_loaded) {
        hub_log_error("[HUB] No Curve25519 keypair in config. Re-run -setup.\n");
        return 1;
    }

    /* Per-hub independent keypairs (no shared-keypair mesh).
     * Peers without a registered pubkey are refused at handshake time —
     * the operator must add each peer with its own pubkey via the console. */
    {
        int peerless = 0;
        for (int i = 0; i < state.peer_count; i++)
            if (!state.peers[i].has_pubkey) peerless++;
        if (peerless > 0) {
            hub_log_warning("[HUB] %d linked hub(s) lack a Curve25519 pubkey and "
                    "will be refused on connect. Re-add them with the key ./irchub -id "
                    "prints on that hub (console: hub add / hub set <hub> key).\n",
                    peerless);
        }
    }

    hub_log_info("[HUB] Started on port %d (PID: %d)\n", state.port, getpid());

    state.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)state.port);

    // Use bind_ip if set, otherwise default to 0.0.0.0
    if (state.bind_ip[0] && strcmp(state.bind_ip, "0.0.0.0") != 0) {
        if (inet_pton(AF_INET, state.bind_ip, &addr.sin_addr) != 1) {
            hub_log_warning("[HUB] Invalid bind_ip: %s, using 0.0.0.0\n", state.bind_ip);
            addr.sin_addr.s_addr = INADDR_ANY;
        } else {
            hub_log_info("[HUB] Binding to %s:%d\n", state.bind_ip, state.port);
        }
    } else {
        addr.sin_addr.s_addr = INADDR_ANY;
        hub_log_info("[HUB] Binding to 0.0.0.0:%d (all interfaces)\n", state.port);
    }
    
    int opt = 1;
    setsockopt(state.listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    if (bind(state.listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        hub_log_error("[HUB] Bind failed\n");
        return 1;
    }
    
    listen(state.listen_fd, 10);
    inet_ntop(AF_INET, &addr.sin_addr, state.listen_ip, sizeof(state.listen_ip));
    state.listen_port = state.port;

    /* The SSH admin console (docs/console.md) shares this port: its thread
     * starts before the first accept.  A hub whose console cannot start
     * still serves its bots and peers, but no admin can reach it. */
    if (!hub_console_start(&state))
        hub_log_error("[CONSOLE] SSH console unavailable — no admin access to "
                      "this hub until it restarts\n");

    while (state.running && !g_hub_stop_signal) {
        hub_check_peers(&state);
        hub_maintenance(&state);

        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        FD_SET(state.listen_fd, &read_fds);
        int max_fd = state.listen_fd;
        if (state.console_ctl_fd >= 0) {
            FD_SET(state.console_ctl_fd, &read_fds);
            if (state.console_ctl_fd > max_fd) max_fd = state.console_ctl_fd;
        }
        bool sniffing = false;

        for (int i = 0; i < state.client_count; i++) {
            hub_client_t *c = state.clients[i];
            if (c->fd > 0) {
                /* A dial in flight: only its writability (hub_finish_dials). */
                if (c->dialing) {
                    FD_SET(c->fd, &write_fds);
                    if (c->fd > max_fd) max_fd = c->fd;
                    continue;
                }
                /* Not read until its first bytes are known (see below). */
                if (c->sniff_pending) {
                    sniffing = true;
                    if (c->fd > max_fd) max_fd = c->fd;
                    continue;
                }
                FD_SET(c->fd, &read_fds);
                /* Only watch writability if the per-peer queue or in-flight
                 * cipher buffer has bytes pending. Otherwise select() would
                 * spin returning writable for every idle socket and waste
                 * CPU — exactly the failure mode docs/cpu.md warned about. */
                if (peer_has_pending_writes(c)) {
                    FD_SET(c->fd, &write_fds);
                }
                if (c->fd > max_fd) {
                    max_fd = c->fd;
                }
            }
        }

        /* Short timeout (250 ms) so the drain loop and maintenance ticks
         * don't stall when nothing is happening. Existing 1-second timeout
         * was acceptable when there was no outbound queue to service; with
         * queues we want to revisit drain opportunities promptly without
         * busy-waiting. */
        struct timeval tv = {0, 250 * 1000};
        /* Frames already read but not yet handled (the pump's 8-per-call
         * cap): poll instead of sleeping, so they are handled this pass. */
        for (int i = 0; i < state.client_count; i++) {
            if (hub_client_has_buffered_frame(state.clients[i])) {
                tv.tv_usec = 0;
                break;
            }
        }
        if (sniffing && tv.tv_usec > 10 * 1000) tv.tv_usec = 10 * 1000;
        if (select(max_fd + 1, &read_fds, &write_fds, NULL, &tv) < 0) continue;

        /* Dials whose connect() finished (or timed out) first: a finished
         * one is a peer whose handshake goes out now. */
        hub_finish_dials(&state, &write_fds);

        /* ---- Drain writable peers FIRST.  This keeps URGENT op-flow
         * traffic prompt and prevents queues from accumulating across the
         * read pass (which can itself enqueue more outbound traffic). ---- */
        for (int i = 0; i < state.client_count; i++) {
            hub_client_t *c = state.clients[i];
            if (c->fd > 0 && fd_isset(c->fd, &write_fds)) {
                peer_drain_writable(&state, c);
            }
        }

        if (fd_isset(state.listen_fd, &read_fds)) {
            struct sockaddr_in ca;
            socklen_t len = sizeof(ca);
            int new_fd = accept(state.listen_fd, (struct sockaddr*)&ca, &len);

            if (new_fd >= 0) {
                char incoming_ip[64];
                snprintf(incoming_ip, sizeof(incoming_ip), "%s", inet_ntoa(ca.sin_addr));

                // Check access lists first
                if (!check_ip_access_lists(&state, incoming_ip)) {
                    hub_log_warning("[HUB] Connection from %s rejected (access control)\n", incoming_ip);
                    close(new_fd);
                } else if (!hub_startup_admit(&state, incoming_ip)) {
                    close(new_fd);   /* logged inside, at most once a minute */
                } else if (!is_ip_allowed(&state, incoming_ip)) {
                    hub_log_warning("[HUB] Connection from %s rejected (rate limit)\n", incoming_ip);
                    close(new_fd);
                } else if (state.client_count < MAX_CLIENTS) {
                    hub_client_t *c = calloc(1, sizeof(hub_client_t));
                    /* D2: unauthenticated clients get a small buffer; it is
                     * grown to MAX_BUFFER once the handshake completes. */
                    if (c && hub_client_alloc_buffers(c, PREAUTH_BUF_SIZE)) {
                        c->fd = new_fd;
                        c->conn_serial = hub_next_conn_serial();
                        snprintf(c->ip, sizeof(c->ip), "%s", incoming_ip);
                        c->last_seen = time(NULL);
                        c->connected_at = c->last_seen;  /* D4: pre-auth clock */
                        c->inbound = true;
                        c->last_pong_sent = 0;
                        /* First bytes decide: "SSH-" goes to the console. */
                        c->sniff_pending = true;
                        {
                            struct timeval snow;
                            gettimeofday(&snow, NULL);
                            c->sniff_deadline_ms = (long long)snow.tv_sec * 1000 +
                                                   snow.tv_usec / 1000 + CONSOLE_SNIFF_MS;
                        }
                        state.clients[state.client_count++] = c;

                        increment_active_connections(&state, c->ip);

                        hub_log_info("[HUB] Incoming connect: %s\n", c->ip);
                    } else {
                        free(c);
                        close(new_fd);
                    }
                } else {
                    close(new_fd);
                }
            }
        }

        if (state.console_ctl_fd >= 0 && fd_isset(state.console_ctl_fd, &read_fds))
            hub_console_ctl_read(&state);

        /* First-bytes sniff.  Bot and peer frames start with a 4-byte length;
         * "SSH-" read as one is ~1.4 GB, never valid, so the split is exact.
         * The bytes are only peeked: the console gets the stream untouched. */
        if (sniffing) {
            struct timeval snow;
            gettimeofday(&snow, NULL);
            long long now_ms = (long long)snow.tv_sec * 1000 + snow.tv_usec / 1000;
            for (int i = 0; i < state.client_count; i++) {
                hub_client_t *c = state.clients[i];
                if (!c->sniff_pending || c->fd <= 0) continue;
                unsigned char head[4];
                ssize_t n = recv(c->fd, head, sizeof(head), MSG_PEEK | MSG_DONTWAIT);
                if (n == 4) {
                    c->sniff_pending = false;
                    if (memcmp(head, "SSH-", 4) == 0) {
                        hub_console_handoff(&state, c);
                        i--;
                    }
                } else if (n == 0 ||
                           (n < 0 && !IO_WOULD_BLOCK(errno) && errno != EINTR)) {
                    hub_disconnect_client(&state, c);
                    i--;
                } else if (now_ms >= c->sniff_deadline_ms) {
                    c->sniff_pending = false;   /* bot/peer protocol from here */
                }
            }
        }

        for (int i = 0; i < state.client_count; i++) {
            hub_client_t *c = state.clients[i];
            
            if (c->fd <= 0 || c->sniff_pending) continue;

            if (fd_isset(c->fd, &read_fds)) {
                /* Frames are consumed by moving recv_off; the buffer is
                 * compacted only once it has no room left to read into. */
                if (c->recv_off > 0 && c->recv_len == c->recv_cap) {
                    memmove(c->recv_buf, c->recv_buf + c->recv_off,
                            (size_t)(c->recv_len - c->recv_off));
                    c->recv_len -= c->recv_off;
                    c->recv_off = 0;
                }
                int space = c->recv_cap - c->recv_len;  /* D2: per-client cap */

                if (space > 0) {
                    int n = (int)read(c->fd, c->recv_buf + c->recv_len, (size_t)space);

                    if (n <= 0) {
                        hub_disconnect_client(&state, c);
                        i--;
                        continue;
                    }
                    c->last_seen = time(NULL);
                    c->recv_len += n;
                } else if (!hub_client_has_buffered_frame(c)) {
                    /* Full buffer and no whole frame in it: cannot happen
                     * with a valid length prefix, so the stream is bad. */
                    hub_log_warning("[HUB] Buffer overflow %s\n", c->ip);
                    hub_disconnect_client(&state, c);
                    i--;
                    continue;
                }
                /* A full buffer that still holds whole frames is not an
                 * overflow: handle them and read the rest next pass. */
                if (!hub_handle_client_data(&state, c)) {
                    i--;
                }
            } else if (hub_client_has_buffered_frame(c)) {
                /* Nothing new on the socket, but frames left over from an
                 * earlier read: without this they wait for the sender's next
                 * packet (a burst of peer records took minutes). */
                if (!hub_handle_client_data(&state, c)) {
                    i--;
                }
            }
        }

        /* Events and log lines for the SSH consoles. */
        hub_console_tick(&state);
    }
    
    /* Shutdown.  The locked pid file is what says "this hub is running" (to
     * tooling, and to a second copy's single-instance check), so it goes
     * last: first the port and every link close and acknowledged changes
     * still inside the write debounce reach the config, then the file is
     * unlinked while still locked, then the lock is released.  Dropping it
     * first let an immediate restart find the port still bound. */
    hub_log_info("[HUB] Shutting down (signal %d).\n", (int)g_hub_stop_signal);
    if (state.listen_fd >= 0) {
        close(state.listen_fd);
        state.listen_fd = -1;
    }
    while (state.client_count > 0)
        hub_disconnect_client(&state, state.clients[state.client_count - 1]);
    hub_console_stop(&state);
    if (state.config_dirty) {
        hub_config_write(&state);
        state.config_dirty = false;
    }

    secure_wipe(state.hub_ed25519_priv, 32);
    secure_wipe(state.hub_x25519_priv,  32);
    OPENSSL_cleanse(state.config_pass,   sizeof(state.config_pass));
    hub_config_key_forget(&state);
    munlock(state.config_pass, sizeof(state.config_pass));

    unlink(HUB_PID_FILE);
    if (state.pid_fd >= 0) {
        close(state.pid_fd);
        state.pid_fd = -1;
    }
    if (log_fp) {
        fclose(log_fp);
        log_fp = NULL;
    }

    return 0;
}
