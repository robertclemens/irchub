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

FILE *log_fp = NULL;

void hub_log(const char *format, ...) {
    va_list args;
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", t);
    
    if (log_fp) {
        fprintf(log_fp, "[%s] ", time_buf);
        va_start(args, format);
        vfprintf(log_fp, format, args);
        va_end(args);
        fflush(log_fp);
    }
    
    printf("[%s] ", time_buf);
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
}

void handle_signal(int sig) {
    (void)sig;
    if (log_fp) {
        fprintf(log_fp, "[HUB] Shutting down signal received.\n");
        fclose(log_fp);
    }
    exit(0);
}

void hub_disconnect_client(hub_state_t *state, hub_client_t *c) {
    if (!c) return;
    
    hub_log("[HUB] Disconnecting client %s (FD: %d)\n", c->ip, c->fd);

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
    
    int msg_len = snprintf((char*)pack + 32, 220, "HUB %s %d", 
                          state->admin_password, state->port);
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
    if (write(c->fd, &net_len, 4) != 4) {
        hub_log("[PEER] Handshake header write failed\n");
        secure_wipe(pack, sizeof(pack));
        hub_disconnect_client(state, c);
        return;
    }
    
    if (write(c->fd, enc, enc_len) != enc_len) {
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
    
    if (write(c->fd, buffer, 4 + packet_len) != (4 + packet_len)) {
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
        
        if (write(c->fd, buffer, 4 + packet_len) != (4 + packet_len)) {
            return false;
        }
    }
    return true;
}

void hub_maintenance(hub_state_t *state) {
    time_t now = time(NULL);
    static time_t last_anti_entropy = 0;
    static time_t last_mesh_gossip = 0;

    if (now - last_mesh_gossip > 10) {
        last_mesh_gossip = now;
        if (state->peer_count > 0) {
            hub_broadcast_mesh_state(state);
        }
    }

    if (last_anti_entropy == 0) last_anti_entropy = now;
    
    if ((now - last_anti_entropy) > MESH_ANTI_ENTROPY_INTERVAL) {
        last_anti_entropy = now;
        if (state->peer_count > 0) {
            hub_log("[MESH] Running periodic anti-entropy sync...\n");
            char full_sync[MAX_BUFFER];
            hub_generate_sync_packet(state, full_sync, MAX_BUFFER - 100);
            hub_broadcast_sync_to_peers(state, full_sync, -1);
        }
    }
    
    // Check clients for timeouts and send pings
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
                perror("setsockopt failed");
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
                    strncpy(c->ip, state->peers[i].ip, sizeof(c->ip) - 1);
                    c->ip[sizeof(c->ip) - 1] = 0;
                    c->type = CLIENT_HUB;
                    c->last_seen = time(NULL);
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

void daemonize() {
    pid_t pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);
    
    if (setsid() < 0) exit(1);
    
    pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);
    
    umask(0);
    if (chdir("/") < 0) exit(1);
    
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    int x = open("/dev/null", O_RDWR);
    if (x != -1) {
        dup2(x, STDIN_FILENO);
        dup2(x, STDOUT_FILENO);
        dup2(x, STDERR_FILENO);
        if (x > 2) close(x);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: ./irchub <pass> [-setup] [-d]\n");
        return 1;
    }

    bool daemon_mode = false;
    for(int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0) daemon_mode = true;
    }

    hub_state_t state;
    memset(&state, 0, sizeof(state));
    strncpy(state.config_pass, argv[1], sizeof(state.config_pass) - 1);
    state.config_pass[sizeof(state.config_pass) - 1] = 0;
    state.running = true;

    if (argc >= 3 && strcmp(argv[2], "-setup") == 0) {
        char kp[256];
        printf("--- Setup ---\nPort: ");
        if (scanf("%d", &state.port) != 1) return 1;
        
        printf("PrivKey Path: ");
        if (scanf("%255s", kp) != 1) return 1;
        
        printf("Admin Pass: ");
        if (scanf("%127s", state.admin_password) != 1) return 1;
        
        FILE *f = fopen(kp, "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            long s = ftell(f);
            fseek(f, 0, SEEK_SET);
            
            state.private_key_pem = malloc(s + 1);
            if (!state.private_key_pem || fread(state.private_key_pem, 1, s, f) != (size_t)s) {
                printf("Error reading key file.\n");
                if(state.private_key_pem) free(state.private_key_pem);
                fclose(f);
                return 1;
            }
            state.private_key_pem[s] = 0;
            fclose(f);
        } else {
            printf("Key file not found.\n");
            return 1;
        }
        
        hub_config_write(&state);
        printf("Done.\n");
        return 0;
    }

    log_fp = fopen("irchub.log", "a");
    if (daemon_mode) {
        printf("Starting in daemon mode...\n");
        daemonize();
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    if (!hub_config_load(&state, state.config_pass)) {
        if (!daemon_mode) printf("Config load failed. Run -setup.\n");
        if (log_fp) fprintf(log_fp, "Config load failed.\n");
        return 1;
    }

    if (!state.private_key_pem) {
        hub_log("[ERROR] No private key in config\n");
        return 1;
    }
    
    // FIXED: Load key using EVP API
    state.priv_key = load_private_key_from_memory(state.private_key_pem);
    if (!state.priv_key) {
        hub_log("[ERROR] Failed to load private key\n");
        return 1;
    }
    
    hub_log("[HUB] Started on port %d (PID: %d)\n", state.port, getpid());

    state.listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(state.port)
    };
    
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
                if (state.client_count < MAX_CLIENTS) {
                    hub_client_t *c = calloc(1, sizeof(hub_client_t));
                    if (c) {
                        c->fd = new_fd;
                        strncpy(c->ip, inet_ntoa(ca.sin_addr), sizeof(c->ip) - 1);
                        c->ip[sizeof(c->ip) - 1] = 0;
                        c->last_seen = time(NULL);
                        state.clients[state.client_count++] = c;
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
    if (state.priv_key) EVP_PKEY_free(state.priv_key);
    if (state.private_key_pem) {
        secure_wipe(state.private_key_pem, strlen(state.private_key_pem));
        free(state.private_key_pem);
    }
    if (state.public_key_pem) free(state.public_key_pem);
    
    return 0;
}
