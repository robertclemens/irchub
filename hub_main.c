#include "hub.h"
#include <stdarg.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <termios.h>

FILE *log_fp = NULL;
hub_state_t *g_state = NULL;  // Global state pointer for use in hub_log() and other global functions

void hub_log(const char *format, ...) {
    va_list args;
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", t);

    // Check if logging disabled
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

    // Check if g_state exists and log level is NONE
    if (g_state && g_state->log_level == LOG_NONE) {
        return;
    }

    // Check if log file exists; if deleted, reopen it
    struct stat st;
    if (stat(HUB_LOG_FILE, &st) != 0) {
        // File doesn't exist, close and reopen
        if (log_fp) {
            fclose(log_fp);
            log_fp = NULL;
        }
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

void handle_signal(int sig) {
    (void)sig;
    if (log_fp) {
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
    secure_wipe(c->recv_buf, c->recv_len);
    free(c);
}

// FIXED: Updated to use EVP API
void hub_peer_handshake(hub_state_t *state, hub_client_t *c) {
    RAND_bytes(c->session_key, 32);
    
    unsigned char pack[256];
    memcpy(pack, c->session_key, 32);
    
    int msg_len = snprintf((char*)pack + 32, 220, "HUB %s %d %s %s %s",
                          state->admin_password, state->port,
                          state->hub_uuid, state->hub_friendly_name, state->bind_ip);
    if (msg_len < 0 || msg_len >= 220) {
        hub_log("[PEER] Handshake message too long\n");
        hub_disconnect_client(state, c);
        return;
    }
    
    unsigned char enc[512];
    
    // FIXED: Use EVP API instead of deprecated RSA functions
    int enc_len = evp_public_encrypt(state->priv_key, pack, 
                                     32 + msg_len + 1, enc);

    if (enc_len <= 0) {
        hub_log("[PEER] Encryption failed\n");
        secure_wipe(pack, sizeof(pack));
        hub_disconnect_client(state, c);
        return;
    }

    uint32_t net_len = htonl(enc_len);
    if (write(c->fd, &net_len, 4) != (ssize_t)4) {
        hub_log("[PEER] Handshake header write failed\n");
        secure_wipe(pack, sizeof(pack));
        hub_disconnect_client(state, c);
        return;
    }

    if (write(c->fd, enc, enc_len) != (ssize_t)enc_len) {
        hub_log("[PEER] Handshake body write failed\n");
        secure_wipe(pack, sizeof(pack));
        hub_disconnect_client(state, c);
        return;
    }
    
    // Wipe sensitive handshake data
    secure_wipe(pack, sizeof(pack));
    
    c->authenticated = true;
    
    // Send initial sync
    unsigned char plain[MAX_BUFFER];
    plain[0] = CMD_PEER_SYNC;
    
    hub_generate_sync_packet(state, (char*)plain + 5, MAX_BUFFER - 100);
    
    int payload_len = strlen((char*)plain + 5);
    int total_plain = 1 + 4 + payload_len;
    memcpy(&plain[1], &payload_len, 4);
    
    unsigned char buffer[MAX_BUFFER];
    unsigned char tag[GCM_TAG_LEN];
    
    int cipher_len = aes_gcm_encrypt(plain, total_plain, c->session_key, 
                                    buffer + 4, tag);
    
    if (cipher_len <= 0) {
        hub_log("[PEER] Sync encryption failed\n");
        hub_disconnect_client(state, c);
        return;
    }
    
    memcpy(buffer + 4 + cipher_len, tag, GCM_TAG_LEN);
    int packet_len = cipher_len + GCM_TAG_LEN;
    uint32_t nl = htonl(packet_len);
    memcpy(buffer, &nl, 4);
    
    if (write(c->fd, buffer, 4 + packet_len) != (ssize_t)(4 + packet_len)) {
        hub_log("[PEER] Sync write failed\n");
        hub_disconnect_client(state, c);
    } else {
        hub_log("[PEER] Sent handshake & sync to %s\n", c->ip);
        hub_broadcast_mesh_state(state);
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
        
        if (write(c->fd, buffer, 4 + packet_len) != (ssize_t)(4 + packet_len)) {
            return false;
        }
    }
    return true;
}

void hub_maintenance(hub_state_t *state) {
    time_t now = time(NULL);
    static time_t last_anti_entropy = 0;
    static time_t last_mesh_gossip = 0;
    static time_t last_config_sync = 0;  // NEW

    if (last_mesh_gossip == 0) last_mesh_gossip = now;

    // Existing mesh gossip...
    if (now - last_mesh_gossip > 10) {
        last_mesh_gossip = now;
        if (state->peer_count > 0) {
            hub_broadcast_mesh_state(state);
        }
    }

    if (last_anti_entropy == 0) last_anti_entropy = now;
    
    // Existing anti-entropy...
    if ((now - last_anti_entropy) > MESH_ANTI_ENTROPY_INTERVAL) {
        last_anti_entropy = now;
        if (state->peer_count > 0) {
            hub_log("[MESH] Running periodic anti-entropy sync...\n");
            char full_sync[MAX_BUFFER];
            hub_generate_sync_packet(state, full_sync, MAX_BUFFER - 100);
            hub_broadcast_sync_to_peers(state, full_sync, -1);
        }
    }
    
    // NEW: Bidirectional config sync every 5 minutes
    if (last_config_sync == 0) last_config_sync = now;
    
    if ((now - last_config_sync) > CONFIG_SYNC_INTERVAL) {
        last_config_sync = now;
        
        int sync_count = 0;
        for (int i = 0; i < state->client_count; i++) {
            hub_client_t *c = state->clients[i];
            if (c->type == CLIENT_BOT && c->authenticated) {
                // Send CONFIG_PULL to request fresh config
                unsigned char buffer[MAX_BUFFER];
                unsigned char plain[16];
                unsigned char tag[GCM_TAG_LEN];
                
                plain[0] = CMD_CONFIG_PULL;
                uint32_t zero = 0;
                memcpy(&plain[1], &zero, 4);
                
                int enc_len = aes_gcm_encrypt(plain, 5, c->session_key, 
                                             buffer + 4, tag);
                if (enc_len > 0) {
                    memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
                    uint32_t net_len = htonl(enc_len + GCM_TAG_LEN);
                    memcpy(buffer, &net_len, 4);
                    
                    if (write(c->fd, buffer, 4 + enc_len + GCM_TAG_LEN) == (ssize_t)(4 + enc_len + GCM_TAG_LEN)) {
                        sync_count++;
                    }
                }
            }
        }
        
        if (sync_count > 0) {
            hub_log("[HUB] Requested config sync from %d bots\n", sync_count);
        }
    }

    // IP limit cleanup every 5 minutes
    static time_t last_ip_cleanup = 0;
    if (last_ip_cleanup == 0) last_ip_cleanup = now;
    if (now - last_ip_cleanup > 300) {  // Every 5 minutes
        cleanup_old_ip_limits(state);
        last_ip_cleanup = now;
    }

    // Scheduled tombstone purge (if configured)
    // Only the elected leader hub initiates to prevent duplicate purges across mesh
    static time_t last_purge = 0;
    if (state->purge_days_setting > 0) {
        if (last_purge == 0) last_purge = now;

        // Run daily (86400 seconds)
        if (now - last_purge > 86400) {
            last_purge = now;

            // Leader election: only hub with smallest UUID in mesh initiates
            if (hub_should_initiate_scheduled_purge(state)) {
                hub_log("[HUB] Running scheduled purge (older than %d days)\n",
                        state->purge_days_setting);

                char purge_log[MAX_BUFFER];
                time_t cutoff = now - ((time_t)state->purge_days_setting * 86400);

                int purged = hub_execute_purge(state, cutoff,
                                                purge_log, sizeof(purge_log));

                if (purged > 0) {
                    hub_log("[HUB] Scheduled purge removed %d tombstones\n", purged);
                }

                // Broadcast PURGE|<cutoff> to peer hubs.
                char sched_purge_msg[64];
                snprintf(sched_purge_msg, sizeof(sched_purge_msg),
                         "PURGE|%ld\n", (long)cutoff);
                hub_broadcast_sync_to_peers(state, sched_purge_msg, -1);
            } else {
                hub_log("[HUB] Scheduled purge skipped (not elected leader in mesh)\n");
            }
        }
    }

    // Existing timeout/ping code...
    for (int i = 0; i < state->client_count; i++) {
        hub_client_t *c = state->clients[i];
        
        if ((now - c->last_seen) > CLIENT_TIMEOUT) {
            hub_log("[HUB] Client %s timed out.\n", c->ip);
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
                    if (!c) {
                        close(sockfd);
                        continue;
                    }
                    
                    c->fd = sockfd;
                    snprintf(c->ip, sizeof(c->ip), "%s", state->peers[i].ip);
                    c->type = CLIENT_HUB;
                    c->last_seen = time(NULL);
c->last_pong_sent = 0;
                    state->clients[state->client_count++] = c;
                    
                    state->peers[i].connected = true;
                    state->peers[i].fd = sockfd;
                    
                    hub_peer_handshake(state, c);
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
    printf("%s", prompt);
    fflush(stdout);
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    if (!fgets(buf, (int)len, stdin)) buf[0] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
    buf[strcspn(buf, "\n")] = 0;
}

int main(int argc, char *argv[]) {
    bool setup_mode = false;
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-setup") == 0) setup_mode = true;
    }

    hub_state_t state;
    memset(&state, 0, sizeof(state));
    state.running = true;
    g_state = &state;
    state.log_level = LOG_INFO;
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
                snprintf(state.bind_ip, sizeof(state.bind_ip), "%s", bind_buf);
            }
        }

        printf("Friendly Name: ");
        if (scanf("%63s", state.hub_friendly_name) != 1) return 1;
        state.hub_friendly_name[sizeof(state.hub_friendly_name) - 1] = 0;
        while ((ch = getchar()) != '\n' && ch != EOF);

        generate_uuid_v4(state.hub_uuid, sizeof(state.hub_uuid));
        printf("Generated UUID: %s\n", state.hub_uuid);

        read_pass_hidden("Config Password: ", state.config_pass, sizeof(state.config_pass));

        printf("\nHub Keypair:\n");
        printf("  1. Generate new keypair\n");
        printf("  2. Use existing key file\n");
        printf("Choice: ");
        fflush(stdout);
        {
            int kp_choice = 0;
            if (scanf("%d", &kp_choice) != 1) kp_choice = 2;
            while ((ch = getchar()) != '\n' && ch != EOF);

            if (kp_choice == 1) {
                char *priv_pem = NULL, *pub_pem = NULL;
                printf("[*] Generating RSA-2048 keypair...\n");
                if (!hub_crypto_generate_keypair(&priv_pem, &pub_pem)) {
                    printf("Key generation failed.\n");
                    return 1;
                }
                state.private_key_pem = priv_pem;
                state.priv_key = load_private_key_from_memory(priv_pem);
                free(pub_pem);
                if (!state.priv_key) {
                    printf("Failed to load generated key.\n");
                    secure_wipe(priv_pem, strlen(priv_pem));
                    free(priv_pem);
                    return 1;
                }
                printf("[+] Keypair generated.\n");
            } else {
                char kp_path[256];
                memset(kp_path, 0, sizeof(kp_path));
                printf("Private Key File Path: ");
                fflush(stdout);
                if (!fgets(kp_path, sizeof(kp_path), stdin)) {
                    printf("Read error.\n");
                    return 1;
                }
                kp_path[strcspn(kp_path, "\n")] = 0;

                {
                    FILE *f = fopen(kp_path, "rb");
                    if (!f) {
                        printf("Key file not found.\n");
                        return 1;
                    }
                    fseek(f, 0, SEEK_END);
                    {
                        long s = ftell(f);
                        fseek(f, 0, SEEK_SET);
                        state.private_key_pem = malloc(s + 1);
                        if (!state.private_key_pem ||
                            fread(state.private_key_pem, 1, s, f) != (size_t)s) {
                            printf("Error reading key file.\n");
                            if (state.private_key_pem) free(state.private_key_pem);
                            fclose(f);
                            return 1;
                        }
                        state.private_key_pem[s] = 0;
                    }
                    fclose(f);
                }
                state.priv_key = load_private_key_from_memory(state.private_key_pem);
                if (!state.priv_key) {
                    printf("Failed to load private key.\n");
                    secure_wipe(state.private_key_pem, strlen(state.private_key_pem));
                    free(state.private_key_pem);
                    return 1;
                }
            }
        }

        {
            char admin_pass1[MAX_PASS], admin_pass2[MAX_PASS];
            do {
                read_pass_hidden("Admin Password: ", admin_pass1, sizeof(admin_pass1));
                read_pass_hidden("Confirm Admin Password: ", admin_pass2, sizeof(admin_pass2));
                if (strcmp(admin_pass1, admin_pass2) != 0) {
                    printf("Passwords do not match. Try again.\n");
                }
            } while (strcmp(admin_pass1, admin_pass2) != 0);
            snprintf(state.admin_password, sizeof(state.admin_password), "%s", admin_pass1);
            secure_wipe(admin_pass1, sizeof(admin_pass1));
            secure_wipe(admin_pass2, sizeof(admin_pass2));
        }

        hub_config_write(&state);
        printf("Done.\n");

        if (state.priv_key) EVP_PKEY_free(state.priv_key);
        if (state.private_key_pem) {
            secure_wipe(state.private_key_pem, strlen(state.private_key_pem));
            free(state.private_key_pem);
        }
        return 0;
    }

    /* Normal mode: read password from environment */
    {
        const char *env_pass = getenv(CONFIG_PASS_ENV_VAR);
        if (!env_pass || !env_pass[0]) {
            fprintf(stderr, "Error: %s environment variable is not set.\n",
                    CONFIG_PASS_ENV_VAR);
            fprintf(stderr, "Set it before starting: export %s=<password>\n",
                    CONFIG_PASS_ENV_VAR);
            return 1;
        }
        snprintf(state.config_pass, sizeof(state.config_pass), "%s", env_pass);
    }

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

    if (!hub_config_load(&state, state.config_pass)) {
        printf("Config load failed. Run -setup.\n");
        if (log_fp) fprintf(log_fp, "Config load failed.\n");
        remove(HUB_PID_FILE);
        return 1;
    }

    // Set default bind_ip if not configured
    if (!state.bind_ip[0]) {
        snprintf(state.bind_ip, sizeof(state.bind_ip), "127.0.0.1");
    }

    if (!state.private_key_pem) {
        hub_log("[ERROR] No private key in config\n");
        return 1;
    }
    
    // FIXED: Load key using EVP API
    state.priv_key = load_private_key_from_memory(state.private_key_pem);
    if (!state.priv_key) {
        hub_log("[ERROR] Failed to load private key\n");
        secure_wipe(state.private_key_pem, strlen(state.private_key_pem));
        free(state.private_key_pem);
        return 1;
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

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(state.listen_fd, &read_fds);
        int max_fd = state.listen_fd;

        for (int i = 0; i < state.client_count; i++) {
            if (state.clients[i]->fd > 0) {
                FD_SET(state.clients[i]->fd, &read_fds);
                if (state.clients[i]->fd > max_fd) {
                    max_fd = state.clients[i]->fd;
                }
            }
        }

        struct timeval tv = {1, 0};
        if (select(max_fd + 1, &read_fds, NULL, NULL, &tv) < 0) continue;

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
                    if (c) {
                        c->fd = new_fd;
                        snprintf(c->ip, sizeof(c->ip), "%s", incoming_ip);
                        c->last_seen = time(NULL);
                        c->last_pong_sent = 0;
                        state.clients[state.client_count++] = c;

                        increment_active_connections(&state, c->ip);

                        hub_log("[HUB] Incoming connect: %s\n", c->ip);
                    } else {
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
                int space = MAX_BUFFER - c->recv_len;
                
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

    if (state.priv_key) EVP_PKEY_free(state.priv_key);
    if (state.private_key_pem) {
        secure_wipe(state.private_key_pem, strlen(state.private_key_pem));
        free(state.private_key_pem);
    }
    if (state.public_key_pem) free(state.public_key_pem);

    return 0;
}
