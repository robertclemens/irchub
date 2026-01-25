#include "hub.h"
#include <termios.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int g_fd = -1;
unsigned char g_key[32];

// ============================================================================
// NETWORK & CRYPTO HELPERS
// ============================================================================

int recv_all(int socket, void *buffer, size_t length) {
    size_t bytes_read = 0;
    char *ptr = (char *)buffer;
    while (bytes_read < length) {
        ssize_t n = read(socket, ptr + bytes_read, length - bytes_read);
        if (n <= 0) return n;
        bytes_read += n;
    }
    return bytes_read;
}

void send_packet(int fd, int cmd_id, const char *payload, unsigned char *key) {
    unsigned char buffer[MAX_BUFFER];
    unsigned char tag[GCM_TAG_LEN];
    unsigned char plain[MAX_BUFFER];

    plain[0] = cmd_id;
    int payload_len = payload ? strlen(payload) : 0;
    memcpy(&plain[1], &payload_len, 4);
    if (payload) memcpy(&plain[5], payload, payload_len);

    int total_plain = 1 + 4 + payload_len;
    
    int enc_len = aes_gcm_encrypt(plain, total_plain, key, buffer + 4, tag);

    memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
    int packet_len = enc_len + GCM_TAG_LEN;
    uint32_t net_len = htonl(packet_len);
    memcpy(buffer, &net_len, 4);

    int total = 4 + packet_len;
    if (write(fd, buffer, total) != total) {
        // Write failed
    }
}

bool process_incoming_packet() {
    uint32_t net_len;
    if (recv(g_fd, &net_len, 4, MSG_PEEK | MSG_DONTWAIT) != 4) return false;

    recv_all(g_fd, &net_len, 4);
    int len = ntohl(net_len);
    
    if (len > MAX_BUFFER || len < GCM_TAG_LEN + 5) return false;

    unsigned char enc_buf[MAX_BUFFER];
    if (recv_all(g_fd, enc_buf, len) != len) return false;

    unsigned char tag[GCM_TAG_LEN];
    memcpy(tag, enc_buf + len - GCM_TAG_LEN, GCM_TAG_LEN);

    unsigned char plain[MAX_BUFFER];
    
    int plain_len = aes_gcm_decrypt(enc_buf, len - GCM_TAG_LEN, g_key, 
                                   plain, tag);

    if (plain_len > 0) {
        if (plain[0] == CMD_PING) {
            send_packet(g_fd, CMD_PING, NULL, g_key);
        }
        return true;
    }
    return false;
}

// ============================================================================
// INPUT HELPERS
// ============================================================================

bool wait_for_input_or_socket(char *buf, size_t len) {
    fd_set fds;
    buf[0] = 0;
    
    while (1) {
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        FD_SET(g_fd, &fds);
        int max_fd = (g_fd > STDIN_FILENO) ? g_fd : STDIN_FILENO;

        if (select(max_fd + 1, &fds, NULL, NULL, NULL) < 0) return false;

        if (FD_ISSET(g_fd, &fds)) {
            if (!process_incoming_packet()) {
                printf("\n[!] Connection lost.\n");
                return false;
            }
            continue;
        }

        if (FD_ISSET(STDIN_FILENO, &fds)) {
            if (!fgets(buf, len, stdin)) return false;
            buf[strcspn(buf, "\n")] = 0;
            return true;
        }
    }
}

void get_password_secure(const char *prompt, char *buf, size_t len) {
    struct termios oldt, newt;
    printf("%s", prompt);
    fflush(stdout);
    
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    
    if (!fgets(buf, len, stdin)) buf[0] = 0;
    
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
    buf[strcspn(buf, "\n")] = 0;
}

void get_input(const char *prompt, char *buf, size_t len) {
    printf("%s", prompt);
    fflush(stdout);
    if (!wait_for_input_or_socket(buf, len)) {
        printf("Connection died during input.\n");
        exit(1);
    }
}

bool get_confirmation(const char *msg) {
    char buf[10];
    printf("%s (y/n): ", msg);
    fflush(stdout);
    if (!wait_for_input_or_socket(buf, sizeof(buf))) exit(1);
    return (buf[0] == 'y' || buf[0] == 'Y');
}

void read_response(int fd, unsigned char *key, char *out_buf, int max_len) {
    while (1) {
        uint32_t net_len;
        if (recv_all(fd, &net_len, 4) != 4) {
            strcpy(out_buf, "Error: Connection lost");
            return;
        }
        
        int len = ntohl(net_len);
        if (len > MAX_BUFFER || len < GCM_TAG_LEN + 5) {
            strcpy(out_buf, "Error: Invalid packet");
            return;
        }

        unsigned char enc_buf[MAX_BUFFER];
        if (recv_all(fd, enc_buf, len) != len) {
            strcpy(out_buf, "Error: Connection lost");
            return;
        }

        unsigned char tag[GCM_TAG_LEN];
        memcpy(tag, enc_buf + len - GCM_TAG_LEN, GCM_TAG_LEN);

        unsigned char plain[MAX_BUFFER];
        
        int plain_len = aes_gcm_decrypt(enc_buf, len - GCM_TAG_LEN, key, 
                                       plain, tag);

        if (plain_len > 0) {
            if (plain[0] == CMD_PING) {
                send_packet(fd, CMD_PING, NULL, key);
                continue;
            }
            plain[plain_len] = 0;
            strncpy(out_buf, (char*)plain, max_len - 1);
            out_buf[max_len - 1] = 0;
            return;
        } else {
            strcpy(out_buf, "Error: Decryption failed");
            return;
        }
    }
}

// ============================================================================
// BOT MANAGEMENT FUNCTIONS
// ============================================================================

void bot_list() {
    char response[MAX_BUFFER];
    send_packet(g_fd, CMD_ADMIN_LIST_FULL, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("\n%s\n", response);
    
    printf("\nPress Enter to continue...");
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void bot_add() {
    char nick[64];
    char response[8192];
    
    printf("\n═══════════════════════════════════════════════════\n");
    printf("           ADD BOT - REMOTE PROVISIONING\n");
    printf("═══════════════════════════════════════════════════\n\n");
    
    get_input("Enter Bot Nickname: ", nick, sizeof(nick));
    
    printf("[*] Requesting hub to generate credentials...\n");
    send_packet(g_fd, CMD_ADMIN_CREATE_BOT, nick, g_key);

    read_response(g_fd, g_key, response, sizeof(response));
    
    if (strncmp(response, "SUCCESS|", 8) == 0) {
        char *uuid_start = response + 8;
        char *priv_key = strchr(uuid_start, '|');
        
        if (priv_key) {
            *priv_key = 0;
            priv_key++;  // Now points to BASE64(full PEM)
            
            char uuid[64];
            strncpy(uuid, uuid_start, sizeof(uuid) - 1);
            uuid[sizeof(uuid) - 1] = '\0';
            
            printf("\n╔══════════════════════════════════════════════════╗\n");
            printf("║             BOT CREATED SUCCESSFULLY             ║\n");
            printf("╚══════════════════════════════════════════════════╝\n\n");
            
            printf("Bot Name: %s\n", nick);
            printf("UUID:     %s\n\n", uuid);
            
            size_t key_len = strlen(priv_key);
            int total_parts = (key_len + 249) / 250;
            
            printf("Private key: %zu chars → %d parts\n\n", key_len, total_parts);
            printf("COPY AND PASTE THESE COMMANDS:\n");
            printf("═══════════════════════════════════════════════════\n\n");
            
            for (int i = 0; i < total_parts; i++) {
                size_t start = i * 250;
                size_t len = (start + 250 > key_len) ? (key_len - start) : 250;
                
                char chunk[260];
                memset(chunk, 0, sizeof(chunk));
                strncpy(chunk, priv_key + start, len);
                
                printf("/msg %s <hash> sethubkey %d/%d:%s\n",
                       nick, i+1, total_parts, chunk);
            }
            
            printf("\n/msg %s <hash> setuuid %s\n", nick, uuid);
            printf("/msg %s <hash> +hub <hub_ip>:<hub_port>\n\n", nick);
            
            printf("═══════════════════════════════════════════════════\n");
            printf("After all parts: Bot will auto-reconnect to hub.\n\n");
            
            // FIXED: Save backup as base64 encoded (matches IRC output)
            char fname[128];
            snprintf(fname, sizeof(fname), "bot_%s_priv_key.b64", nick);
            FILE *f = fopen(fname, "w");
            if (f) {
                fprintf(f, "%s\n", priv_key);
                fclose(f);
                printf("[Backup saved: %s (BASE64 encoded)]\n\n", fname);
            }
            
            secure_wipe(response, sizeof(response));
        } else {
            printf("ERROR: Malformed response from hub.\n");
        }
    } else {
        printf("Hub Response: %s\n", response);
    }
    
    printf("\nPress Enter to continue...");
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void bot_remove() {
    char response[MAX_BUFFER];
    
    send_packet(g_fd, CMD_ADMIN_LIST_SUMMARY, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("\n%s\n", response);
    
    char uuid[64];
    get_input("UUID to REMOVE (or blank to cancel): ", uuid, sizeof(uuid));
    
    if (strlen(uuid) > 0 && get_confirmation("Are you sure? Bot will be disconnected")) {
        send_packet(g_fd, CMD_ADMIN_DEL, uuid, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("Hub: %s\n", response);
    }
    
    printf("\nPress Enter to continue...");
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void bot_rekey() {
    char response[MAX_BUFFER];
    
    send_packet(g_fd, CMD_ADMIN_LIST_SUMMARY, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("\n%s\n", response);
    
    char uuid[64];
    get_input("UUID to REKEY: ", uuid, sizeof(uuid));
    
    if (strlen(uuid) == 0) {
        printf("Cancelled.\n");
        return;
    }
    
    if (!get_confirmation("Generate new keypair? Bot will be disconnected")) {
        return;
    }
    
    printf("\n[*] Requesting hub to rekey bot...\n");
    send_packet(g_fd, CMD_ADMIN_REKEY_BOT, uuid, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    
    if (strncmp(response, "SUCCESS|", 8) == 0) {
        char *nick_start = response + 8;
        char *priv_key = strchr(nick_start, '|');
        
        if (priv_key) {
            *priv_key = 0;
            priv_key++;
            
            char nick[64];
            strncpy(nick, nick_start, sizeof(nick) - 1);
            nick[sizeof(nick) - 1] = '\0';
            
            printf("\n╔══════════════════════════════════════════════════╗\n");
            printf("║              BOT REKEYED SUCCESSFULLY            ║\n");
            printf("╚══════════════════════════════════════════════════╝\n\n");
            
            printf("UUID: %s\n", uuid);
            printf("Nick: %s\n\n", nick);
            
            size_t key_len = strlen(priv_key);
            int total_parts = (key_len + 249) / 250;
            
            printf("New private key: %zu chars → %d parts\n\n", key_len, total_parts);
            printf("COPY AND PASTE THESE COMMANDS:\n");
            printf("═══════════════════════════════════════════════════\n\n");
            
            for (int i = 0; i < total_parts; i++) {
                size_t start = i * 250;
                size_t len = (start + 250 > key_len) ? (key_len - start) : 250;
                
                char chunk[260];
                memset(chunk, 0, sizeof(chunk));
                strncpy(chunk, priv_key + start, len);
                
                printf("/msg %s <hash> sethubkey %d/%d:%s\n",
                       nick, i+1, total_parts, chunk);
            }
            
            printf("\n/msg %s <hash> +hub <hub_ip>:<hub_port>\n\n", nick);
            
            printf("═══════════════════════════════════════════════════\n\n");
            
            // Save new key backup
            char fname[128];
            snprintf(fname, sizeof(fname), "bot_%s_priv_key_REKEY.b64", nick);
            FILE *f = fopen(fname, "w");
            if (f) {
                fprintf(f, "%s\n", priv_key);
                fclose(f);
                printf("[New key backup: %s]\n\n", fname);
            }
            
            secure_wipe(response, sizeof(response));
        }
    } else {
        printf("Hub Response: %s\n", response);
    }
    
    printf("\nPress Enter to continue...");
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

// ============================================================================
// PEER (HUB) MANAGEMENT FUNCTIONS
// ============================================================================

void peer_list() {
    char response[MAX_BUFFER];
    
    printf("\n");
    send_packet(g_fd, CMD_ADMIN_LIST_PEERS, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("%s\n", response);
    
    printf("\nPress Enter to continue...");
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void peer_add() {
    char response[MAX_BUFFER];
    char ip[64], port[10];
    
    printf("\n═══════════════════════════════════════════════════\n");
    printf("                   ADD PEER HUB\n");
    printf("═══════════════════════════════════════════════════\n\n");
    
    get_input("Peer IP: ", ip, sizeof(ip));
    get_input("Peer Port: ", port, sizeof(port));
    
    char payload[128];
    snprintf(payload, sizeof(payload), "%s:%s", ip, port);
    
    send_packet(g_fd, CMD_ADMIN_ADD_PEER, payload, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("\nHub: %s\n", response);
    
    printf("\nPress Enter to continue...");
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void peer_remove() {
    char response[MAX_BUFFER];
    
    send_packet(g_fd, CMD_ADMIN_LIST_PEERS, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("\n%s\n", response);
    
    char idx[10];
    get_input("Enter Index to Remove (or blank to cancel): ", idx, sizeof(idx));
    
    if (strlen(idx) > 0 && atoi(idx) > 0) {
        if (get_confirmation("Remove this peer?")) {
            send_packet(g_fd, CMD_ADMIN_DEL_PEER, idx, g_key);
            read_response(g_fd, g_key, response, sizeof(response));
            printf("Hub: %s\n", response);
        }
    }
    
    printf("\nPress Enter to continue...");
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void peer_force_sync() {
    char response[1024];
    
    printf("\n[*] Forcing mesh synchronization...\n");
    send_packet(g_fd, CMD_ADMIN_SYNC_MESH, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("Hub: %s\n", response);
    
    printf("\nPress Enter to continue...");
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void peer_rekey_hubs() {
    char response[MAX_BUFFER];
    
    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║               ⚠️  DANGER ZONE ⚠️                  ║\n");
    printf("║          REKEY ALL HUB COMMUNICATION             ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");
    
    printf("This will:\n");
    printf("  1. Generate new RSA keypair for hub-to-hub auth\n");
    printf("  2. Distribute new private key to all peers\n");
    printf("  3. Wait for confirmation from all peers\n");
    printf("  4. Reconnect all peers with new keys\n");
    printf("  5. Export new public key for hub_admin\n\n");
    
    if (!get_confirmation("Proceed with hub rekey?")) {
        printf("Cancelled.\n");
        return;
    }
    
    printf("\n[*] Requesting hub to generate new keypair...\n");
    send_packet(g_fd, CMD_ADMIN_REGEN_KEYS, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    
    if (strlen(response) > 20 && strstr(response, "BEGIN PUBLIC KEY")) {
        printf("\n╔══════════════════════════════════════════════════╗\n");
        printf("║           HUB KEYS REGENERATED SUCCESS           ║\n");
        printf("╚══════════════════════════════════════════════════╝\n\n");
        
        // Save new public key
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        char fname[64];
        strftime(fname, sizeof(fname), "hub_public_%Y%m%d_%H%M%S.pem", t);
        
        FILE *f = fopen(fname, "w");
        if (f) {
            fputs(response, f);
            fclose(f);
            printf("[NEW PUBLIC KEY SAVED: %s]\n\n", fname);
        }
        
        printf("NEW PUBLIC KEY:\n");
        printf("═══════════════════════════════════════════════════\n");
        printf("%s\n", response);
        printf("═══════════════════════════════════════════════════\n\n");
        
        printf("ACTION REQUIRED:\n");
        printf("1. Update hub_admin on all admin machines:\n");
        printf("   ./hub_admin <ip> <port> %s\n\n", fname);
        printf("2. All peer hubs have been updated automatically\n");
        printf("3. All peer hubs will reconnect with new keys\n\n");
        
    } else {
        printf("Hub Response: %s\n", response);
    }
    
    printf("\nPress Enter to continue...");
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

// ============================================================================
// ADMIN COMMANDS FUNCTIONS
// ============================================================================

void admin_op_user() {
    char response[MAX_BUFFER];
    char nick[64], channel[64];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("                     OP USER\n");
    printf("═══════════════════════════════════════════════════\n\n");

    get_input("Nick to OP: ", nick, sizeof(nick));
    get_input("Channel: ", channel, sizeof(channel));

    if (strlen(nick) > 0 && strlen(channel) > 0) {
        char payload[256];
        snprintf(payload, sizeof(payload), "%s|%s", nick, channel);

        printf("[*] Sending op request to hub...\n");
        send_packet(g_fd, CMD_ADMIN_OP_USER, payload, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("\nHub: %s\n", response);
    }

    printf("\nPress Enter to continue...");
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_list_masks() {
    char response[MAX_BUFFER];

    printf("\n");
    send_packet(g_fd, CMD_ADMIN_LIST_MASKS, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("%s\n", response);

    printf("\nPress Enter to continue...");
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_add_mask() {
    char response[MAX_BUFFER];
    char mask[256];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("                  ADD ADMIN MASK\n");
    printf("═══════════════════════════════════════════════════\n\n");
    printf("Format examples:\n");
    printf("  *!*@*.example.com\n");
    printf("  nick!*@*\n");
    printf("  *!user@host.com\n\n");

    get_input("Admin Mask: ", mask, sizeof(mask));

    if (strlen(mask) > 0) {
        send_packet(g_fd, CMD_ADMIN_ADD_MASK, mask, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("\nHub: %s\n", response);
    }

    printf("\nPress Enter to continue...");
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_del_mask() {
    char response[MAX_BUFFER];

    send_packet(g_fd, CMD_ADMIN_LIST_MASKS, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("\n%s\n", response);

    char mask[256];
    get_input("Mask to REMOVE (or blank to cancel): ", mask, sizeof(mask));

    if (strlen(mask) > 0 && get_confirmation("Remove this admin mask?")) {
        send_packet(g_fd, CMD_ADMIN_DEL_MASK, mask, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("Hub: %s\n", response);
    }

    printf("\nPress Enter to continue...");
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_list_opers() {
    char response[MAX_BUFFER];

    printf("\n");
    send_packet(g_fd, CMD_ADMIN_LIST_OPERS, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("%s\n", response);

    printf("\nPress Enter to continue...");
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_add_oper() {
    char response[MAX_BUFFER];
    char mask[256], pass[128];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("                  ADD OPER MASK\n");
    printf("═══════════════════════════════════════════════════\n\n");

    get_input("Oper Mask: ", mask, sizeof(mask));
    get_password_secure("Oper Password: ", pass, sizeof(pass));

    if (strlen(mask) > 0 && strlen(pass) > 0) {
        char payload[512];
        snprintf(payload, sizeof(payload), "%s|%s", mask, pass);

        send_packet(g_fd, CMD_ADMIN_ADD_OPER, payload, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("\nHub: %s\n", response);

        secure_wipe(pass, sizeof(pass));
        secure_wipe(payload, sizeof(payload));
    }

    printf("\nPress Enter to continue...");
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_del_oper() {
    char response[MAX_BUFFER];

    send_packet(g_fd, CMD_ADMIN_LIST_OPERS, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("\n%s\n", response);

    char mask[256];
    get_input("Oper Mask to REMOVE (or blank to cancel): ", mask, sizeof(mask));

    if (strlen(mask) > 0 && get_confirmation("Remove this oper mask?")) {
        send_packet(g_fd, CMD_ADMIN_DEL_OPER, mask, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("Hub: %s\n", response);
    }

    printf("\nPress Enter to continue...");
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_list_channels() {
    char response[MAX_BUFFER];

    printf("\n");
    send_packet(g_fd, CMD_ADMIN_LIST_CHANNELS, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("%s\n", response);

    printf("\nPress Enter to continue...");
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_add_channel() {
    char response[MAX_BUFFER];
    char chan[64], key[64];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("                   ADD CHANNEL\n");
    printf("═══════════════════════════════════════════════════\n\n");

    get_input("Channel Name: ", chan, sizeof(chan));
    get_input("Channel Key (or blank): ", key, sizeof(key));

    if (strlen(chan) > 0) {
        char payload[256];
        if (strlen(key) > 0) {
            snprintf(payload, sizeof(payload), "%s|%s", chan, key);
        } else {
            snprintf(payload, sizeof(payload), "%s|", chan);
        }

        send_packet(g_fd, CMD_ADMIN_ADD_CHANNEL, payload, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("\nHub: %s\n", response);
    }

    printf("\nPress Enter to continue...");
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_del_channel() {
    char response[MAX_BUFFER];

    send_packet(g_fd, CMD_ADMIN_LIST_CHANNELS, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("\n%s\n", response);

    char chan[64];
    get_input("Channel to REMOVE (or blank to cancel): ", chan, sizeof(chan));

    if (strlen(chan) > 0 && get_confirmation("Remove this channel from all bots?")) {
        send_packet(g_fd, CMD_ADMIN_DEL_CHANNEL, chan, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("Hub: %s\n", response);
    }

    printf("\nPress Enter to continue...");
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_change_admin_password() {
    char response[MAX_BUFFER];
    char pass[128];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("             CHANGE ADMIN PASSWORD\n");
    printf("═══════════════════════════════════════════════════\n\n");

    get_password_secure("New Admin Password: ", pass, sizeof(pass));

    if (strlen(pass) > 0 && get_confirmation("Update admin password?")) {
        send_packet(g_fd, CMD_ADMIN_SET_ADMIN_PASS, pass, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("\nHub: %s\n", response);
    }

    secure_wipe(pass, sizeof(pass));

    printf("\nPress Enter to continue...");
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_change_bot_password() {
    char response[MAX_BUFFER];
    char pass[128];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("              CHANGE BOT PASSWORD\n");
    printf("═══════════════════════════════════════════════════\n\n");
    printf("This will update the bot communication password\n");
    printf("synced to all bots.\n\n");

    get_password_secure("New Bot Password: ", pass, sizeof(pass));

    if (strlen(pass) > 0 && get_confirmation("Update bot password on all bots?")) {
        send_packet(g_fd, CMD_ADMIN_SET_BOT_PASS, pass, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("\nHub: %s\n", response);
    }

    secure_wipe(pass, sizeof(pass));

    printf("\nPress Enter to continue...");
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void menu_manage_admin_masks() {
    while (1) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║              MANAGE ADMIN MASKS                  ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("  1. List Admin Masks\n");
        printf("  2. Add Admin Mask\n");
        printf("  3. Del Admin Mask\n");
        printf("  4. Back to Admin Commands\n");
        printf("\n");
        printf("Select: ");
        fflush(stdout);

        char buf[10];
        if (!wait_for_input_or_socket(buf, sizeof(buf))) {
            printf("\n[!] Connection lost.\n");
            exit(1);
        }

        int choice = atoi(buf);

        switch(choice) {
            case 1:
                admin_list_masks();
                break;
            case 2:
                admin_add_mask();
                break;
            case 3:
                admin_del_mask();
                break;
            case 4:
                return;
            default:
                printf("Invalid choice.\n");
                break;
        }
    }
}

void menu_manage_oper_masks() {
    while (1) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║              MANAGE OPER MASKS                   ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("  1. List Oper Masks\n");
        printf("  2. Add Oper Mask\n");
        printf("  3. Del Oper Mask\n");
        printf("  4. Back to Admin Commands\n");
        printf("\n");
        printf("Select: ");
        fflush(stdout);

        char buf[10];
        if (!wait_for_input_or_socket(buf, sizeof(buf))) {
            printf("\n[!] Connection lost.\n");
            exit(1);
        }

        int choice = atoi(buf);

        switch(choice) {
            case 1:
                admin_list_opers();
                break;
            case 2:
                admin_add_oper();
                break;
            case 3:
                admin_del_oper();
                break;
            case 4:
                return;
            default:
                printf("Invalid choice.\n");
                break;
        }
    }
}

void menu_manage_channels() {
    while (1) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║               MANAGE CHANNELS                    ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("  1. List Channels\n");
        printf("  2. Add Channel\n");
        printf("  3. Del Channel\n");
        printf("  4. Back to Admin Commands\n");
        printf("\n");
        printf("Select: ");
        fflush(stdout);

        char buf[10];
        if (!wait_for_input_or_socket(buf, sizeof(buf))) {
            printf("\n[!] Connection lost.\n");
            exit(1);
        }

        int choice = atoi(buf);

        switch(choice) {
            case 1:
                admin_list_channels();
                break;
            case 2:
                admin_add_channel();
                break;
            case 3:
                admin_del_channel();
                break;
            case 4:
                return;
            default:
                printf("Invalid choice.\n");
                break;
        }
    }
}

void menu_admin_commands() {
    while (1) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║               ADMIN COMMANDS                     ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("  1. Op User\n");
        printf("  2. Manage Admin Masks\n");
        printf("  3. Manage Oper Masks\n");
        printf("  4. Manage Channels\n");
        printf("  5. Change Admin Password\n");
        printf("  6. Change Bot Password\n");
        printf("  7. Back to Main Menu\n");
        printf("\n");
        printf("Select: ");
        fflush(stdout);

        char buf[10];
        if (!wait_for_input_or_socket(buf, sizeof(buf))) {
            printf("\n[!] Connection lost.\n");
            exit(1);
        }

        int choice = atoi(buf);

        switch(choice) {
            case 1:
                admin_op_user();
                break;
            case 2:
                menu_manage_admin_masks();
                break;
            case 3:
                menu_manage_oper_masks();
                break;
            case 4:
                menu_manage_channels();
                break;
            case 5:
                admin_change_admin_password();
                break;
            case 6:
                admin_change_bot_password();
                break;
            case 7:
                return;
            default:
                printf("Invalid choice.\n");
                break;
        }
    }
}

// ============================================================================
// MENU FUNCTIONS
// ============================================================================

void menu_manage_bots() {
    while (1) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║                 MANAGE BOTS                      ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("  1. List Bots\n");
        printf("  2. Add Bot\n");
        printf("  3. Remove Bot\n");
        printf("  4. Rekey Bot\n");
        printf("  5. Back to Main Menu\n");
        printf("\n");
        printf("Select: ");
        fflush(stdout);
        
        char buf[10];
        if (!wait_for_input_or_socket(buf, sizeof(buf))) {
            printf("\n[!] Connection lost.\n");
            exit(1);
        }
        
        int choice = atoi(buf);
        
        switch(choice) {
            case 1:
                bot_list();
                break;
            case 2:
                bot_add();
                break;
            case 3:
                bot_remove();
                break;
            case 4:
                bot_rekey();
                break;
            case 5:
                return;  // Back to main menu
            default:
                printf("Invalid choice.\n");
                break;
        }
    }
}

void menu_manage_peers() {
    while (1) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║             MANAGE PEERS (HUBS)                  ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("  1. List Peers (Mesh Matrix)\n");
        printf("  2. Add Peer\n");
        printf("  3. Remove Peer\n");
        printf("  4. Force Mesh Sync\n");
        printf("  5. Rekey Hubs (DANGER)\n");
        printf("  6. Back to Main Menu\n");
        printf("\n");
        printf("Select: ");
        fflush(stdout);
        
        char buf[10];
        if (!wait_for_input_or_socket(buf, sizeof(buf))) {
            printf("\n[!] Connection lost.\n");
            exit(1);
        }
        
        int choice = atoi(buf);
        
        switch(choice) {
            case 1:
                peer_list();
                break;
            case 2:
                peer_add();
                break;
            case 3:
                peer_remove();
                break;
            case 4:
                peer_force_sync();
                break;
            case 5:
                peer_rekey_hubs();
                break;
            case 6:
                return;  // Back to main menu
            default:
                printf("Invalid choice.\n");
                break;
        }
    }
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: ./hub_admin <ip> <port> <pub.pem>\n");
        return 1;
    }

    FILE *f = fopen(argv[3], "rb");
    if (!f) {
        perror("Failed to open key file");
        return 1;
    }
    
    EVP_PKEY *pub_key = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    
    if (!pub_key) {
        fprintf(stderr, "Failed to load public key\n");
        return 1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(atoi(argv[2]))
    };
    inet_pton(AF_INET, argv[1], &addr.sin_addr);
    
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("Connect failed");
        EVP_PKEY_free(pub_key);
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    g_fd = fd;
    RAND_bytes(g_key, 32);

    char auth_pass[128];
    get_password_secure("Admin Password: ", auth_pass, sizeof(auth_pass));

    unsigned char pack[256];
    memcpy(pack, g_key, 32);
    int msg_len = snprintf((char*)pack + 32, 220, "ADMIN %s", auth_pass);
    
    secure_wipe(auth_pass, sizeof(auth_pass));

    unsigned char enc[512];
    int enc_len = evp_public_encrypt(pub_key, pack, 32 + msg_len + 1, enc);
    
    EVP_PKEY_free(pub_key);
    secure_wipe(pack, sizeof(pack));

    if (enc_len <= 0) {
        fprintf(stderr, "Encryption failed\n");
        close(fd);
        return 1;
    }

    uint32_t net_len = htonl(enc_len);
    if (write(fd, &net_len, 4) != 4 || write(fd, enc, enc_len) != enc_len) {
        perror("Send failed");
        close(fd);
        return 1;
    }

    printf("[+] Authenticated to hub.\n");

    // MAIN MENU LOOP
    while (1) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║              IRC HUB ADMIN CONSOLE               ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("  1. Manage Bots\n");
        printf("  2. Manage Peers (Hubs)\n");
        printf("  3. Admin Commands\n");
        printf("  4. Exit\n");
        printf("\n");
        printf("Select: ");
        fflush(stdout);

        char buf[10];
        if (!wait_for_input_or_socket(buf, sizeof(buf))) {
            printf("\n[!] Disconnected.\n");
            break;
        }

        int choice = atoi(buf);

        switch(choice) {
            case 1:
                menu_manage_bots();
                break;

            case 2:
                menu_manage_peers();
                break;

            case 3:
                menu_admin_commands();
                break;

            case 4:
                printf("\nExiting...\n");
                secure_wipe(g_key, sizeof(g_key));
                close(fd);
                return 0;

            default:
                printf("Invalid choice.\n");
                break;
        }
    }
    
    secure_wipe(g_key, sizeof(g_key));
    close(fd);
    return 0;
}
