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

// FIXED: Larger buffer + automatic file save for private key
void menu_add_managed_bot() {
 char nick[64];
    char response[8192];
    
    printf("\n--- Create New Bot (Remote Provisioning) ---\n");
    get_input("Enter Bot Nickname: ", nick, sizeof(nick));
    
    printf("[*] Requesting Hub to generate credentials...\n");
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
            printf("║       BOT CREATED - REMOTE PROVISIONING          ║\n");
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
            
            // Save backup - decode to get actual PEM
            char fname[128];
            snprintf(fname, sizeof(fname), "bot_%s_priv.pem", nick);
            FILE *f = fopen(fname, "w");
            if (f) {
                int pem_len;
                unsigned char *pem_data = base64_decode(priv_key, &pem_len);
                if (pem_data) {
                    fwrite(pem_data, 1, pem_len, f);
                    free(pem_data);
                }
                fclose(f);
                printf("[Backup saved: %s]\n\n", fname);
            }
            
            secure_wipe(response, sizeof(response));
        }
    }
}



void menu_manage_peers(int fd, unsigned char *key) {
    char response[MAX_BUFFER];
    send_packet(fd, CMD_ADMIN_LIST_PEERS, NULL, key);
    read_response(fd, key, response, sizeof(response));
    printf("\n%s\n", response);

    printf("1. Add Peer\n2. Remove Peer\n3. Back\nSelect: ");
    char b[10];
    get_input("", b, 10);
    int c = atoi(b);

    if (c == 1) {
        char ip[64], port[10];
        get_input("Peer IP: ", ip, sizeof(ip));
        get_input("Peer Port: ", port, sizeof(port));
        
        char payload[128];
        snprintf(payload, sizeof(payload), "%s:%s", ip, port);
        send_packet(fd, CMD_ADMIN_ADD_PEER, payload, key);
        read_response(fd, key, response, sizeof(response));
        printf("Hub: %s\n", response);
    }
    else if (c == 2) {
        char idx[10];
        get_input("Enter Index to Remove: ", idx, sizeof(idx));
        if (atoi(idx) > 0) {
            send_packet(fd, CMD_ADMIN_DEL_PEER, idx, key);
            read_response(fd, key, response, sizeof(response));
            printf("Hub: %s\n", response);
        }
    }
}

void menu_list_bots(int fd, unsigned char *key) {
    char response[MAX_BUFFER];
    send_packet(fd, CMD_ADMIN_LIST_FULL, NULL, key);
    read_response(fd, key, response, sizeof(response));
    printf("\n%s\n", response);
}

void menu_pending_bots(int fd, unsigned char *key) {
    char response[MAX_BUFFER];
    send_packet(fd, CMD_ADMIN_GET_PENDING, NULL, key);
    read_response(fd, key, response, sizeof(response));
    printf("\n%s\n", response);
    
    if (strstr(response, "No pending")) return;
    
    char choice[10];
    get_input("Approve Index: ", choice, sizeof(choice));
    if (atoi(choice) > 0) {
        send_packet(fd, CMD_ADMIN_APPROVE, choice, key);
        read_response(fd, key, response, sizeof(response));
        printf("Hub: %s\n", response);
    }
}

void menu_del_bot(int fd, unsigned char *key) {
    char response[MAX_BUFFER];
    send_packet(fd, CMD_ADMIN_LIST_SUMMARY, NULL, key);
    read_response(fd, key, response, sizeof(response));
    printf("\n%s\n", response);
    
    char uuid[64];
    get_input("UUID to DELETE: ", uuid, sizeof(uuid));
    
    if (strlen(uuid) > 0 && get_confirmation("Are you sure?")) {
        send_packet(fd, CMD_ADMIN_DEL, uuid, key);
        read_response(fd, key, response, sizeof(response));
        printf("Hub: %s\n", response);
    }
}

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

    printf("[+] Authentication sent.\n");

    while (1) {
        printf("\n");
        printf("1. List Bots\n");
        printf("2. Pending Bots\n");
        printf("3. Manual Auth UUID\n");
        printf("4. Manage Peers\n");
        printf("5. Remove Bot\n");
        printf("6. Force Mesh Sync\n");
        printf("7. Add Managed Bot (New)\n");
        printf("8. Exit\n");
        printf("Select: ");
        fflush(stdout);

        char b[10];
        if (!wait_for_input_or_socket(b, 10)) {
            printf("\n[!] Disconnected.\n");
            break;
        }

        int c = atoi(b);
        
        switch(c) {
            case 1:
                menu_list_bots(fd, g_key);
                break;
                
            case 2:
                menu_pending_bots(fd, g_key);
                break;
                
            case 4:
                menu_manage_peers(fd, g_key);
                break;
                
            case 5:
                menu_del_bot(fd, g_key);
                break;
                
            case 6:
                {
                    send_packet(fd, CMD_ADMIN_SYNC_MESH, NULL, g_key);
                    char r[1024];
                    read_response(fd, g_key, r, 1024);
                    printf("Hub: %s\n", r);
                }
                break;
                
            case 7:
                menu_add_managed_bot();
                break;
                
            case 8:
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
