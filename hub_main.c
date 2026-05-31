#include "hub.h"
#include <malloc.h>
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
#include <sys/utsname.h>
#include <fcntl.h>
#include <termios.h>
#include <pwd.h>
#include <sys/mman.h>


FILE *log_fp = NULL;
hub_state_t *g_state = NULL;  // Global state pointer for use in hub_log() and other global functions

void hub_log(const char *format, ...) {
    va_list args;
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", t);

    // Check if logging disabled
    if (g_state && g_state->log_level == LOG_NONE) {
        return;
    }

    if (!log_fp) {
        // Try to open log file first
        int fd = open(HUB_LOG_FILE, O_CREAT | O_APPEND | O_WRONLY, 0600);
        if (fd >= 0) {
            log_fp = fdopen(fd, "a");
        } else {
            log_fp = NULL;
        }
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
        int fd = open(HUB_LOG_FILE, O_CREAT | O_APPEND | O_WRONLY, 0600);
        if (fd >= 0) {
            log_fp = fdopen(fd, "a");
        } else {
            log_fp = NULL;
        }
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
        int fd = open(HUB_LOG_FILE, O_CREAT | O_WRONLY | O_TRUNC, 0600);
        if (fd >= 0) {
            log_fp = fdopen(fd, "a");  // Use "a" mode for fdopen after truncate
        } else {
            log_fp = NULL;
        }
        if (!log_fp) {
            return;  // Silent fail if can't reopen
        }
        fprintf(log_fp, "[%s] Log file truncated (size limit reached)\n", time_buf);
        fflush(log_fp);
        return;
    }

    // Write log entry (log level filtering would be done by caller in Task 5)
    fprintf(log_fp, "[%s] ", time_buf);
    va_start(args, format);
    vfprintf(log_fp, format, args);
    va_end(args);
    fflush(log_fp);
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

void handle_signal(int sig) {
    (void)sig;
    if (log_fp) {
        if (!g_state || g_state->log_level != LOG_NONE)
            fprintf(log_fp, "[HUB] Shutting down signal received.\n");
        fclose(log_fp);
    }
    remove(HUB_PID_FILE);
    exit(0);
}

void hub_disconnect_client(hub_state_t *state, hub_client_t *c) {
    if (!c) return;

    hub_log("[HUB] Disconnecting client %s (FD: %d)\n", c->ip, c->fd);

    decrement_active_connections(state, c->ip);

    // 1. Update Peer Status FIRST
    for(int p = 0; p < state->peer_count; p++) {
        if (state->peers[p].fd == c->fd && c->fd != -1) {
            state->peers[p].connected = false;
            state->peers[p].fd = -1;
            state->mesh_state_dirty = true;
        }
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
    secure_wipe(c->session_key, sizeof(c->session_key));
    secure_wipe(c->bot_eph_x25519_priv, sizeof(c->bot_eph_x25519_priv));
    c->bot_eph_priv_set = false;
    if (c->recv_buf) secure_wipe(c->recv_buf, c->recv_len);
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

void hub_peer_handshake(hub_state_t *state, hub_client_t *c,
                         const hub_peer_config_t *peer) {
    if (!state->hub_keys_loaded) {
        hub_log("[PEER] No Curve25519 keys loaded; cannot handshake\n");
        hub_disconnect_client(state, c);
        return;
    }

    if (!peer || !peer->has_pubkey) {
        hub_log("[PEER] Peer has no registered pubkey — refusing to connect. "
                "Re-add this peer with its Curve25519 pubkey to enable v2 auth.\n");
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
                            "irchub-peer-auth-v2|%s|%s|%d|%s|%s",
                            state->hub_uuid, ts_str, state->port,
                            state->hub_friendly_name, state->bind_ip);
        if (tlen < 0 || tlen >= (int)sizeof(transcript)) {
            hub_log("[PEER] v2 transcript too long\n");
            hub_disconnect_client(state, c);
            return;
        }

        unsigned char sig[ED25519_SIG_LEN];
        if (!hub_crypto_ed25519_sign(state->hub_ed25519_priv,
                                     (unsigned char *)transcript, (size_t)tlen,
                                     sig)) {
            hub_log("[PEER] v2 Ed25519 sign failed\n");
            hub_disconnect_client(state, c);
            return;
        }

        char *sig_b64 = base64_encode(sig, ED25519_SIG_LEN);
        if (!sig_b64) {
            hub_log("[PEER] v2 signature base64 encode failed\n");
            hub_disconnect_client(state, c);
            return;
        }

        msg_len = snprintf((char *)pack, sizeof(pack),
                           "HUBv2|%s|%d|%s|%s|%s|%s",
                           state->hub_uuid, state->port,
                           state->hub_friendly_name, state->bind_ip,
                           ts_str, sig_b64);
        secure_wipe(sig_b64, strlen(sig_b64));
        free(sig_b64);

        if (msg_len < 0 || msg_len >= (int)sizeof(pack)) {
            hub_log("[PEER] v2 packet too long\n");
            hub_disconnect_client(state, c);
            return;
        }
    }

    unsigned char enc[MAX_BUFFER];
    static const unsigned char PEER_INFO[] = "irchub-peer-session-v1";
    const unsigned char *seal_target = peer->x25519_pub;
    int enc_len = hub_seal_send(seal_target,
                                pack, msg_len + 1,
                                PEER_INFO, sizeof(PEER_INFO) - 1,
                                enc, sizeof(enc), c->session_key);
    secure_wipe(pack, sizeof(pack));

    if (enc_len <= 0) {
        hub_log("[PEER] Sealed-box encryption failed\n");
        hub_disconnect_client(state, c);
        return;
    }

    uint32_t net_len = htonl(enc_len);
    if (write(c->fd, &net_len, 4) != (ssize_t)4 ||
        write(c->fd, enc, enc_len) != (ssize_t)enc_len) {
        hub_log("[PEER] Handshake write failed\n");
        hub_disconnect_client(state, c);
        return;
    }

    c->authenticated = true;
    /* D2: no-op for outbound peers (already full-size) but keeps every
     * auth-completion path uniform. */
    hub_client_promote_buffers(c);
    hub_log("[PEER] Handshake complete with %s\n", c->ip);
    /* Send a full config sync immediately via the BULK queue.  The queue
     * enforces a per-peer byte budget (BULK_SOFT_BUDGET_BPS = 32 KB/s) so
     * simultaneous startup of all 10 hubs no longer creates a cascade that
     * fills socket buffers.  Each hub's BULK drain is naturally staggered
     * by the select() cycle time.  This replaces the old approach of deferring
     * the first sync to anti-entropy (up to 90 s wait). */
    {
        char full_sync[MAX_BUFFER];
        hub_generate_sync_packet(state, full_sync, MAX_BUFFER - 100);
        int sync_len = strlen(full_sync);
        if (sync_len > 0) {
            queued_msg_t *sync_msg = queued_msg_new(CMD_PEER_SYNC, LANE_BULK,
                                                    (const unsigned char *)full_sync,
                                                    sync_len);
            if (sync_msg) {
                queued_msg_set_coalesce(sync_msg, state->hub_uuid,
                                        hub_next_lamport_seq(state),
                                        "handshake_sync");
                if (!peer_enqueue(c, sync_msg)) {
                    hub_log("[PEER] Could not queue initial sync to %s\n", c->ip);
                }
            }
        }
    }
}

bool send_ping(hub_client_t *c) {
    unsigned char buffer[MAX_BUFFER];
    unsigned char plain[16];
    unsigned char tag[GCM_TAG_LEN];
    
    plain[0] = CMD_PING;
    uint32_t zero = 0;
    memcpy(&plain[1], &zero, 4);
    
    int enc_len = aes_gcm_encrypt(plain, 5, c->session_key, buffer + 4, tag);
    if (enc_len > 0) {
        memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
        int packet_len = enc_len + GCM_TAG_LEN;
        uint32_t net_len = htonl(packet_len);
        memcpy(buffer, &net_len, 4);
        
        ssize_t sent = send(c->fd, buffer, 4 + packet_len, MSG_DONTWAIT | MSG_NOSIGNAL);
        if (sent != (ssize_t)(4 + packet_len)) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return true; // peer send buffer full but connection alive; skip ping
            }
            return false;
        }
    }
    return true;
}

void hub_maintenance(hub_state_t *state) {
    time_t now = time(NULL);
    static time_t last_anti_entropy = 0;
    static time_t last_mesh_gossip  = 0;
    static time_t last_client_scan  = 0;
    static time_t last_ip_cleanup   = 0;
    static time_t last_purge        = 0;
    static time_t last_status_dump  = 0;

    if (last_mesh_gossip == 0) last_mesh_gossip = now;
    if (last_client_scan == 0) last_client_scan = now;
    if (last_ip_cleanup  == 0) last_ip_cleanup  = now;
    if (last_status_dump == 0) last_status_dump = now;

    /* Mesh state gossip: every 5 min as heartbeat, or immediately when peer
     * topology changes (connect/disconnect sets mesh_state_dirty). */
    if (state->mesh_state_dirty || (now - last_mesh_gossip > 300)) {
        last_mesh_gossip = now;
        state->mesh_state_dirty = false;
        if (state->peer_count > 0)
            hub_broadcast_mesh_state(state);
    }

    /* Anti-entropy: stagger first fire 30–90 s, then every MESH_ANTI_ENTROPY_INTERVAL */
    if (last_anti_entropy == 0) {
        unsigned int jitter = 30 + (unsigned int)(rand() % 61);
        last_anti_entropy = now - (time_t)(MESH_ANTI_ENTROPY_INTERVAL - jitter);
    }
    bool forced_ae = state->anti_entropy_due;
    if (forced_ae || now - last_anti_entropy > MESH_ANTI_ENTROPY_INTERVAL) {
        last_anti_entropy = now;
        state->anti_entropy_due = false;
        if (state->peer_count > 0) {
            hub_log("[MESH] Running %santi-entropy sync...\n",
                    forced_ae ? "forced " : "periodic ");
            char full_sync[MAX_BUFFER];
            hub_generate_sync_packet(state, full_sync, MAX_BUFFER - 100);
            hub_broadcast_sync_to_peers(state, full_sync, -1);
        }
    }

    /* Config write debounce */
    if (state->config_dirty &&
        (now - state->last_config_write) >= CONFIG_WRITE_DEBOUNCE_S) {
        hub_config_write(state);
        state->config_dirty = false;
        state->last_config_write = now;
    }

    /* IP rate-limit cleanup: every 5 minutes */
    if (now - last_ip_cleanup > 300) {
        cleanup_old_ip_limits(state);
        last_ip_cleanup = now;
    }

    /* Scheduled tombstone purge: daily, leader only */
    if (state->purge_days_setting > 0) {
        if (last_purge == 0) last_purge = now;
        if (now - last_purge > 86400) {
            last_purge = now;
            if (hub_should_initiate_scheduled_purge(state)) {
                hub_log("[HUB] Running scheduled purge (older than %d days)\n",
                        state->purge_days_setting);
                char purge_log[MAX_BUFFER];
                time_t cutoff = now - ((time_t)state->purge_days_setting * 86400);
                int purged = hub_execute_purge(state, cutoff, purge_log, sizeof(purge_log));
                if (purged > 0)
                    hub_log("[HUB] Scheduled purge removed %d tombstones\n", purged);
                char sched_purge_msg[64];
                snprintf(sched_purge_msg, sizeof(sched_purge_msg), "PURGE|%ld\n", (long)cutoff);
                hub_broadcast_sync_to_peers(state, sched_purge_msg, -1);
            } else {
                hub_log("[HUB] Scheduled purge skipped (not elected leader in mesh)\n");
            }
        }
    }

    /* Client timeout/ping scan: every 5 s (was every 250 ms — no need to scan
     * 50+ clients 4x/sec when the ping window is 60 s and timeout is 180 s). */
    if (now - last_client_scan >= 5) {
        last_client_scan = now;
        for (int i = 0; i < state->client_count; i++) {
            hub_client_t *c = state->clients[i];
            if ((now - c->last_seen) > CLIENT_TIMEOUT) {
                hub_log("[HUB] Client %s timed out.\n", c->ip);
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
                hub_log("[HUB] Pre-auth timeout for %s (%lds, no handshake) — "
                        "dropping\n", c->ip, (long)(now - c->connected_at));
                hub_disconnect_client(state, c);
                i--;
                continue;
            }
            if (c->authenticated && (now - c->last_seen) > PING_INTERVAL) {
                if (!send_ping(c)) {
                    hub_log("[WARN] Ping failed to %s. Disconnecting.\n", c->ip);
                    hub_disconnect_client(state, c);
                    i--;
                    continue;
                }
            }
        }
    }

    /* Periodic status dump: every 60 s at INFO level.
     * One line showing all timer countdowns and current load so idle churn
     * is visible without having to stare at top/perf. */
    if (now - last_status_dump >= 60) {
        last_status_dump = now;

        int bot_count = 0, peer_count = 0, authing_count = 0;
        for (int i = 0; i < state->client_count; i++) {
            hub_client_t *c = state->clients[i];
            if (c->type == CLIENT_BOT && c->authenticated)       bot_count++;
            else if (c->type == CLIENT_HUB && c->authenticated)  peer_count++;
            else                                                  authing_count++;
        }

        time_t gossip_in    = 300 - (now - last_mesh_gossip);
        time_t entropy_in   = MESH_ANTI_ENTROPY_INTERVAL - (now - last_anti_entropy);
        time_t scan_in      = 5 - (now - last_client_scan);
        time_t ipcln_in     = 300 - (now - last_ip_cleanup);
        time_t purge_in     = (state->purge_days_setting > 0 && last_purge > 0)
                                ? (86400 - (now - last_purge)) : -1;
        time_t peer_chk_in  = PEER_RECONNECT_INTERVAL; /* approximate */

        if (gossip_in  < 0) gossip_in  = 0;
        if (entropy_in < 0) entropy_in = 0;
        if (scan_in    < 0) scan_in    = 0;
        if (ipcln_in   < 0) ipcln_in   = 0;

        if (purge_in >= 0) {
            hub_log("[STATUS] clients=%d(bots=%d peers=%d authing=%d) "
                    "dirty=%d "
                    "gossip_in=%lds entropy_in=%lds scan_in=%lds "
                    "ipcln_in=%lds peer_chk_in=%lds purge_in=%lds\n",
                    state->client_count, bot_count, peer_count, authing_count,
                    state->config_dirty,
                    (long)gossip_in, (long)entropy_in, (long)scan_in,
                    (long)ipcln_in, (long)peer_chk_in, (long)purge_in);
        } else {
            hub_log("[STATUS] clients=%d(bots=%d peers=%d authing=%d) "
                    "dirty=%d "
                    "gossip_in=%lds entropy_in=%lds scan_in=%lds "
                    "ipcln_in=%lds peer_chk_in=%lds purge=off\n",
                    state->client_count, bot_count, peer_count, authing_count,
                    state->config_dirty,
                    (long)gossip_in, (long)entropy_in, (long)scan_in,
                    (long)ipcln_in, (long)peer_chk_in);
        }
    }
}

void hub_check_peers(hub_state_t *state) {
    static time_t last_check = 0;
    time_t now = time(NULL);
    
    if (now - last_check < PEER_RECONNECT_INTERVAL) return;
    last_check = now;

    for (int i = 0; i < state->peer_count; i++) {
        if (!state->peers[i].connected) {
            hub_log("[PEER] Attempting to connect to %s:%d...\n", 
                   state->peers[i].ip, state->peers[i].port);
            
            int sockfd = socket(AF_INET, SOCK_STREAM, 0);
            if (sockfd < 0) continue;

            struct timeval timeout;
            timeout.tv_sec = CONNECT_TIMEOUT;
            timeout.tv_usec = 0;
            
            if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                          sizeof(timeout)) < 0) {
                hub_log("setsockopt failed\n");
            }

            struct sockaddr_in peer_addr;
            peer_addr.sin_family = AF_INET;
            peer_addr.sin_port = htons(state->peers[i].port);
            inet_pton(AF_INET, state->peers[i].ip, &peer_addr.sin_addr);

            if (connect(sockfd, (struct sockaddr*)&peer_addr, sizeof(peer_addr)) == 0) {
                if (state->client_count < MAX_CLIENTS) {
                    hub_client_t *c = calloc(1, sizeof(hub_client_t));
                    /* D2: outbound peers immediately exchange bulk anti-entropy
                     * sync, so allocate full-size buffers up front. */
                    if (!c || !hub_client_alloc_buffers(c, MAX_BUFFER)) {
                        free(c);
                        close(sockfd);
                        continue;
                    }

                    c->fd = sockfd;
                    snprintf(c->ip, sizeof(c->ip), "%s", state->peers[i].ip);
                    c->type = CLIENT_HUB;
                    c->last_seen = time(NULL);
                    c->connected_at = c->last_seen;  /* D4 (exempt: CLIENT_HUB) */
                    c->last_pong_sent = 0;
                    state->clients[state->client_count++] = c;
                    
                    state->peers[i].connected = true;
                    state->peers[i].fd = sockfd;
                    state->mesh_state_dirty = true;
                    hub_peer_handshake(state, c, &state->peers[i]);
                } else {
                    close(sockfd);
                    hub_log("[PEER] Client limit reached.\n");
                }
            } else {
                hub_log("[PEER] Failed to connect to %s:%d\n", 
                       state->peers[i].ip, state->peers[i].port);
                close(sockfd);
            }
        }
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
    snprintf(buf, len, "%lu:%lu:%u:%u:%s",
             (unsigned long)home_st.st_ino, (unsigned long)home_st.st_dev,
             (unsigned int)getuid(), (unsigned int)getgid(), uts.machine);
}

static bool passfile_derive_key(const char *ctx, const unsigned char *salt,
                                unsigned char *key) {
    return PKCS5_PBKDF2_HMAC(ctx, (int)strlen(ctx), salt, SALT_SIZE,
                             PBKDF2_ITERATIONS, EVP_sha256(), 32, key) == 1;
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
    if (!passfile_derive_key(ctx, salt, key)) goto done;
    mlock(out_pass, out_len);
    unsigned char *plain = malloc((size_t)enc_len);
    if (!plain) goto done;
    mlock(plain, (size_t)enc_len);
    int dec_len = aes_gcm_decrypt(enc_blk, enc_len, key, plain, tag);
    if (dec_len > 0 && (size_t)dec_len < out_len) {
        plain[dec_len] = 0;
        memcpy(out_pass, plain, (size_t)dec_len + 1);
        ok = true;
    } else {
        fprintf(stderr, "[WARN] .irchub.pass: decryption failed "
                        "(wrong machine or tampered file), falling through.\n");
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
    if (!passfile_derive_key(ctx, salt, key)) {
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

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { perror("open"); free(enc_buf); goto done; }

    if (fchmod(fd, 0600) != 0) {
        perror("fchmod"); close(fd); free(enc_buf); goto done;
    }

    ok = (write(fd, salt,    SALT_SIZE)   == SALT_SIZE &&
          write(fd, enc_buf, enc_len)     == enc_len   &&
          write(fd, tag,     GCM_TAG_LEN) == GCM_TAG_LEN);

    if (!ok) perror("write .irchub.pass");
    close(fd);
    free(enc_buf);

done:
    secure_wipe(key, sizeof(key));
    secure_wipe(ctx, sizeof(ctx));
    return ok;
}

int main(int argc, char *argv[]) {
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
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-setup") == 0) setup_mode = true;
        if (strcmp(argv[i], "-p")     == 0) passfile_mode = true;
    }

    static hub_state_t state;
    memset(&state, 0, sizeof(state));
    state.running = true;
    g_state = &state;
    state.log_level = HUB_DEFAULT_LOG_LEVEL;
    state.log_max_size = HUB_LOG_FILE_SIZE;

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

        printf("Friendly Name: ");
        fflush(stdout);
        if (fgets(state.hub_friendly_name, sizeof(state.hub_friendly_name), stdin)) {
            state.hub_friendly_name[strcspn(state.hub_friendly_name, "\n")] = 0;
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
                printf("    │   - Peer hubs adding this hub will need the     │\n");
                printf("    │     UUID + ip:port + pubkey via hub_admin.      │\n");
                printf("    │ The hub's PRIVATE key never leaves this machine │\n");
                printf("    │ (stored encrypted inside .irchub.cnf).          │\n");
                printf("    └─────────────────────────────────────────────────┘\n");
                free(pub_b64);
            }
            printf("[+] Curve25519 keypair generated.\n");
        }
        (void)ch;

        /* The legacy single 'Hub Admin Password' is gone — auth is per-admin
         * via the a| user records. state->admin_password remains in the struct
         * but is not used or persisted by the v3 admin auth path. */
        state.admin_password[0] = '\0';

        /* Admin user setup — creates first a| and m| records.
         * Each admin gets a Curve25519 keypair: pubkey lives in the a| record
         * (replicated through the mesh); the matching priv is dumped to a file
         * the operator must carry to the machine that runs hub_admin. */
        printf("\n--- First Admin Setup ---\n");
        printf("This creates the first named admin for IRC bot command\n");
        printf("authentication AND hub_admin login (per-admin password).\n\n");
        {
            char bot_admin_name[64] = {0};
            char bot_admin_pass1[MAX_PASS] = {0}, bot_admin_pass2[MAX_PASS] = {0};

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

            /* Password */
            do {
                read_pass_hidden("Admin Password: ", bot_admin_pass1, sizeof(bot_admin_pass1));
                read_pass_hidden("Confirm Admin Password: ", bot_admin_pass2, sizeof(bot_admin_pass2));
                if (strcmp(bot_admin_pass1, bot_admin_pass2) != 0)
                    printf("Passwords do not match. Try again.\n");
            } while (strcmp(bot_admin_pass1, bot_admin_pass2) != 0);

            /* Generate per-admin Curve25519 keypair.  The PRIVATE key is
             * displayed exactly once — never written to disk by this wizard.
             * The operator must copy it (out of band) to a file on the host
             * that will run hub_admin (e.g. ~/admin_<name>.b64, 0600).
             * The PUBLIC key is stored in the a| record and replicates
             * through the mesh. */
            char admin_pub_b64[COMBINED_KEY_B64 + 1] = {0};
            {
                unsigned char ad_priv[COMBINED_KEY_LEN], ad_pub[COMBINED_KEY_LEN];
                if (!hub_crypto_generate_combined_keypair(ad_priv, ad_pub)) {
                    fprintf(stderr, "Admin keypair generation failed.\n");
                    return 1;
                }
                char *priv_b64 = base64_encode(ad_priv, COMBINED_KEY_LEN);
                char *pub_b64  = base64_encode(ad_pub,  COMBINED_KEY_LEN);
                secure_wipe(ad_priv, COMBINED_KEY_LEN);
                if (priv_b64 && pub_b64) {
                    snprintf(admin_pub_b64, sizeof(admin_pub_b64), "%s", pub_b64);
                    printf("\n");
                    printf("    ┌──────────────────────────────────────────────────────────┐\n");
                    printf("    │  ⚠ Admin '%s' PRIVATE key (save this NOW; not stored):  \n",
                           bot_admin_name);
                    printf("    │                                                          \n");
                    printf("    │  %s  \n", priv_b64);
                    printf("    │                                                          \n");
                    printf("    │  Save to (e.g.) admin_%s.b64 with mode 0600 on the      \n",
                           bot_admin_name);
                    printf("    │  host that will run hub_admin, then:                     \n");
                    printf("    │    ./hub_admin <ip> <port> admin_%s.b64                  \n",
                           bot_admin_name);
                    printf("    │                                                          \n");
                    printf("    │  This key is NOT recoverable from .irchub.cnf if lost.   \n");
                    printf("    └──────────────────────────────────────────────────────────┘\n");
                    printf("\n    Admin public key (replicated through mesh in a| record):\n");
                    printf("      %s\n\n", pub_b64);
                    printf("    Press Enter when you have copied the private key...");
                    fflush(stdout);
                    { int c; while ((c = getchar()) != '\n' && c != EOF); }
                }
                if (priv_b64) { secure_wipe(priv_b64, strlen(priv_b64)); free(priv_b64); }
                if (pub_b64)  free(pub_b64);
            }

            /* Generate UUID and create the user record */
            char new_uuid[37];
            generate_uuid_v4(new_uuid, sizeof(new_uuid));
            time_t now = time(NULL);

            if (state.user_record_count < MAX_HUB_USER_RECORDS) {
                hub_user_record_t *u = &state.user_records[state.user_record_count++];
                memset(u, 0, sizeof(*u));
                snprintf(u->uuid,     sizeof(u->uuid),     "%s", new_uuid);
                snprintf(u->name,     sizeof(u->name),     "%s", bot_admin_name);
                snprintf(u->password, sizeof(u->password), "%s", bot_admin_pass1);
                u->type = 'a'; u->is_active = true; u->timestamp = now;
                if (admin_pub_b64[0]) {
                    snprintf(u->pubkey_b64, sizeof(u->pubkey_b64), "%s", admin_pub_b64);
                    u->has_pubkey = true;
                }
            }
            secure_wipe(bot_admin_pass1, sizeof(bot_admin_pass1));
            secure_wipe(bot_admin_pass2, sizeof(bot_admin_pass2));

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

            printf("[+] Bot admin '%s' created with %d usermask(s), UUID %s\n",
                   bot_admin_name, masks_added, new_uuid);
        }

        hub_config_write(&state);
        secure_wipe(state.config_pass, sizeof(state.config_pass));
        secure_wipe(state.admin_password, sizeof(state.admin_password));
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

    daemonize();

    /* Seed rand() after the double-fork so each hub process gets a different
     * sequence — used to stagger anti-entropy timing across the mesh. */
    srand((unsigned int)(time(NULL) ^ getpid()));

    log_fp = fopen(HUB_LOG_FILE, "a");

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Create PID file with exclusive lock
    int pid_fd = open(HUB_PID_FILE, O_CREAT | O_RDWR, 0600);
    if (pid_fd == -1) {
        hub_log("[ERROR] Cannot create PID file\n");
        return 1;
    }
    if (flock(pid_fd, LOCK_EX | LOCK_NB) == -1) {
        hub_log("[ERROR] Hub already running (PID file locked)\n");
        close(pid_fd);
        return 1;
    }
    char pid_str[16];
    snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
    if (write(pid_fd, pid_str, strlen(pid_str)) < 0) {
        hub_log("[WARN] Failed to write PID\n");
    }
    state.pid_fd = pid_fd;

    if (!hub_config_load(&state, _hub_plain_pass)) {
        secure_wipe(_hub_plain_pass, sizeof(_hub_plain_pass));
        printf("Config load failed. Run -setup.\n");
        if (log_fp) fprintf(log_fp, "Config load failed.\n");
        remove(HUB_PID_FILE);
        return 1;
    }
    /* XOR-protect config_pass; hub_config_write() decodes it on every save. */
    hub_set_config_pass(&state, _hub_plain_pass);
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
        hub_log("[ERROR] No Curve25519 keypair in config. Re-run -setup.\n");
        return 1;
    }

    /* Per-hub independent keypairs (no shared-keypair mesh).
     * Peers without a registered pubkey are refused at handshake time —
     * the operator must add each peer with its own pubkey via hub_admin. */
    {
        int peerless = 0;
        for (int i = 0; i < state.peer_count; i++)
            if (!state.peers[i].has_pubkey) peerless++;
        if (peerless > 0) {
            hub_log("[HUB] WARNING: %d peer(s) lack a Curve25519 pubkey and "
                    "will be refused on connect. Re-add them with their "
                    "hub_public.b64 via hub_admin (Add Peer / Set Peer Pubkey).\n",
                    peerless);
        }
    }

    hub_log("[HUB] Started on port %d (PID: %d)\n", state.port, getpid());

    state.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(state.port);

    // Use bind_ip if set, otherwise default to 0.0.0.0
    if (state.bind_ip[0] && strcmp(state.bind_ip, "0.0.0.0") != 0) {
        if (inet_pton(AF_INET, state.bind_ip, &addr.sin_addr) != 1) {
            hub_log("[ERROR] Invalid bind_ip: %s, using 0.0.0.0\n", state.bind_ip);
            addr.sin_addr.s_addr = INADDR_ANY;
        } else {
            hub_log("[HUB] Binding to %s:%d\n", state.bind_ip, state.port);
        }
    } else {
        addr.sin_addr.s_addr = INADDR_ANY;
        hub_log("[HUB] Binding to 0.0.0.0:%d (all interfaces)\n", state.port);
    }
    
    int opt = 1;
    setsockopt(state.listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    if (bind(state.listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        hub_log("[ERROR] Bind failed\n");
        return 1;
    }
    
    listen(state.listen_fd, 10);

    while (state.running) {
        hub_check_peers(&state);
        hub_maintenance(&state);

        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        FD_SET(state.listen_fd, &read_fds);
        int max_fd = state.listen_fd;

        for (int i = 0; i < state.client_count; i++) {
            hub_client_t *c = state.clients[i];
            if (c->fd > 0) {
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
        if (select(max_fd + 1, &read_fds, &write_fds, NULL, &tv) < 0) continue;

        /* ---- Drain writable peers FIRST.  This keeps URGENT op-flow
         * traffic prompt and prevents queues from accumulating across the
         * read pass (which can itself enqueue more outbound traffic). ---- */
        for (int i = 0; i < state.client_count; i++) {
            hub_client_t *c = state.clients[i];
            if (c->fd > 0 && FD_ISSET(c->fd, &write_fds)) {
                peer_drain_writable(&state, c);
            }
        }

        if (FD_ISSET(state.listen_fd, &read_fds)) {
            struct sockaddr_in ca;
            socklen_t len = sizeof(ca);
            int new_fd = accept(state.listen_fd, (struct sockaddr*)&ca, &len);

            if (new_fd >= 0) {
                char incoming_ip[64];
                snprintf(incoming_ip, sizeof(incoming_ip), "%s", inet_ntoa(ca.sin_addr));

                // Check access lists first
                if (!check_ip_access_lists(&state, incoming_ip)) {
                    hub_log("[HUB] Connection from %s rejected (access control)\n", incoming_ip);
                    close(new_fd);
                } else if (!is_ip_allowed(&state, incoming_ip)) {
                    hub_log("[HUB] Connection from %s rejected (rate limit)\n", incoming_ip);
                    close(new_fd);
                } else if (state.client_count < MAX_CLIENTS) {
                    hub_client_t *c = calloc(1, sizeof(hub_client_t));
                    /* D2: unauthenticated clients get a small buffer; it is
                     * grown to MAX_BUFFER once the handshake completes. */
                    if (c && hub_client_alloc_buffers(c, PREAUTH_BUF_SIZE)) {
                        c->fd = new_fd;
                        snprintf(c->ip, sizeof(c->ip), "%s", incoming_ip);
                        c->last_seen = time(NULL);
                        c->connected_at = c->last_seen;  /* D4: pre-auth clock */
                        c->last_pong_sent = 0;
                        state.clients[state.client_count++] = c;

                        increment_active_connections(&state, c->ip);

                        hub_log("[HUB] Incoming connect: %s\n", c->ip);
                    } else {
                        free(c);
                        close(new_fd);
                    }
                } else {
                    close(new_fd);
                }
            }
        }

        for (int i = 0; i < state.client_count; i++) {
            hub_client_t *c = state.clients[i];
            
            if (c->fd > 0 && FD_ISSET(c->fd, &read_fds)) {
                int space = c->recv_cap - c->recv_len;  /* D2: per-client cap */
                
                if (space > 0) {
                    int n = read(c->fd, c->recv_buf + c->recv_len, space);
                    
                    if (n <= 0) {
                        hub_disconnect_client(&state, c);
                        i--;
                    } else {
                        c->last_seen = time(NULL);
                        c->recv_len += n;
                        
                        if (!hub_handle_client_data(&state, c)) {
                            i--;
                        }
                    }
                } else {
                    hub_log("[HUB] Buffer overflow %s\n", c->ip);
                    hub_disconnect_client(&state, c);
                    i--;
                }
            }
        }
    }
    
    // Cleanup
    if (state.pid_fd >= 0) {
        close(state.pid_fd);
    }
    remove(HUB_PID_FILE);

    secure_wipe(state.hub_ed25519_priv, 32);
    secure_wipe(state.hub_x25519_priv,  32);
    OPENSSL_cleanse(state.config_pass,   sizeof(state.config_pass));
    munlock(state.config_pass, sizeof(state.config_pass));

    return 0;
}
