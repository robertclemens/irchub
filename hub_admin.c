#include "hub.h"
#include <termios.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int g_fd = -1;
unsigned char g_key[32];

void pause_and_continue(void);

// Stub hub_log for hub_crypto.c (hub_admin doesn't use file logging)
void hub_log(const char *format, ...) {
    (void)format;
    // No-op: hub_admin doesn't log to file
}

// ============================================================================
// NETWORK & CRYPTO HELPERS
// ============================================================================

int recv_all(int socket, void *buffer, size_t length) {
    size_t bytes_read = 0;
    char *ptr = (char *)buffer;
    while (bytes_read < length) {
        ssize_t n = read(socket, ptr + bytes_read, length - bytes_read);
        if (n <= 0) return (int)n;
        bytes_read += n;
    }
    return (int)bytes_read;
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
    if (enc_len <= 0) return;

    memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
    int packet_len = enc_len + GCM_TAG_LEN;
    uint32_t net_len = htonl(packet_len);
    memcpy(buffer, &net_len, 4);

    int total = 4 + packet_len;
    if (write(fd, buffer, total) != (ssize_t)total) {
        // Write failed
    }
}

void send_packet_binary(int fd, int cmd_id, const unsigned char *payload, int payload_len, unsigned char *key) {
    unsigned char buffer[MAX_BUFFER];
    unsigned char tag[GCM_TAG_LEN];
    unsigned char plain[MAX_BUFFER];

    plain[0] = cmd_id;
    memcpy(&plain[1], &payload_len, 4);
    if (payload && payload_len > 0) memcpy(&plain[5], payload, payload_len);

    int total_plain = 1 + 4 + payload_len;

    int enc_len = aes_gcm_encrypt(plain, total_plain, key, buffer + 4, tag);
    if (enc_len <= 0) return;

    memcpy(buffer + 4 + enc_len, tag, GCM_TAG_LEN);
    int packet_len = enc_len + GCM_TAG_LEN;
    uint32_t net_len = htonl(packet_len);
    memcpy(buffer, &net_len, 4);

    int total = 4 + packet_len;
    if (write(fd, buffer, total) != (ssize_t)total) {
        // Write failed
    }
}

/* Upper bound for any valid hub packet: 65536-byte plaintext + IV + tag */
#define MAX_HUB_PACKET (65536 + GCM_IV_LEN + GCM_TAG_LEN + 64)

bool process_incoming_packet(void) {
    uint32_t net_len;
    if (recv(g_fd, &net_len, 4, MSG_PEEK | MSG_DONTWAIT) != 4) return false;

    recv_all(g_fd, &net_len, 4);
    int len = ntohl(net_len);

    if (len < GCM_TAG_LEN + 5 || len > MAX_HUB_PACKET) return false;

    unsigned char *enc_buf = malloc((size_t)len);
    if (!enc_buf) return false;
    if (recv_all(g_fd, enc_buf, len) != len) { free(enc_buf); return false; }

    unsigned char tag[GCM_TAG_LEN];
    memcpy(tag, enc_buf + len - GCM_TAG_LEN, GCM_TAG_LEN);

    unsigned char *plain = malloc((size_t)(len + 1));
    if (!plain) { free(enc_buf); return false; }

    int plain_len = aes_gcm_decrypt(enc_buf, len - GCM_TAG_LEN, g_key, plain, tag);
    free(enc_buf);

    bool result = false;
    if (plain_len > 0) {
        if (plain[0] == CMD_PING)
            send_packet(g_fd, CMD_PING, NULL, g_key);
        result = true;
    }
    secure_wipe(plain, (size_t)(len + 1));
    free(plain);
    return result;
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
            snprintf(out_buf, max_len, "Error: Connection lost");
            return;
        }

        int len = ntohl(net_len);
        if (len < GCM_TAG_LEN + 5 || len > MAX_HUB_PACKET) {
            snprintf(out_buf, max_len, "Error: Invalid packet (len=%d)", len);
            return;
        }

        unsigned char *enc_buf = malloc((size_t)len);
        if (!enc_buf) {
            snprintf(out_buf, max_len, "Error: Out of memory");
            return;
        }
        if (recv_all(fd, enc_buf, len) != len) {
            free(enc_buf);
            snprintf(out_buf, max_len, "Error: Connection lost");
            return;
        }

        unsigned char tag[GCM_TAG_LEN];
        memcpy(tag, enc_buf + len - GCM_TAG_LEN, GCM_TAG_LEN);

        /* +1 for the NUL we write at plain[plain_len] */
        unsigned char *plain = malloc((size_t)(len + 1));
        if (!plain) {
            free(enc_buf);
            snprintf(out_buf, max_len, "Error: Out of memory");
            return;
        }

        int plain_len = aes_gcm_decrypt(enc_buf, len - GCM_TAG_LEN, key, plain, tag);
        free(enc_buf);

        if (plain_len > 0) {
            if (plain[0] == CMD_PING) {
                secure_wipe(plain, (size_t)(len + 1));
                free(plain);
                send_packet(fd, CMD_PING, NULL, key);
                continue;
            }
            plain[plain_len] = 0;
            snprintf(out_buf, max_len, "%s", (char *)plain);
            secure_wipe(plain, (size_t)(len + 1));
            free(plain);
            return;
        }
        secure_wipe(plain, (size_t)(len + 1));
        free(plain);
        snprintf(out_buf, max_len, "Error: Decryption failed");
        return;
    }
}

// ============================================================================
// BOT MANAGEMENT FUNCTIONS
// ============================================================================

void bot_list(void) {
    char response[MAX_BUFFER];
    send_packet(g_fd, CMD_ADMIN_LIST_FULL, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("\n%s\n", response);
    
    printf("\nPress Enter to continue...");
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void bot_add(void) {
    char nick[64];
    char uuid[64];
    char pubkey[256];
    char response[8192];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("           ADD BOT (bot-provided identity)\n");
    printf("═══════════════════════════════════════════════════\n");
    printf("The bot has generated its own UUID and Curve25519\n");
    printf("keypair during 'ircbot -setup'.  Paste the UUID and\n");
    printf("the 88-char base64 public key it printed.\n\n");

    get_input("Bot Nickname: ", nick, sizeof(nick));
    get_input("Bot UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx): ",
              uuid, sizeof(uuid));
    /* Validate UUID */
    if (strlen(uuid) != 36 || uuid[8] != '-' || uuid[13] != '-' ||
        uuid[18] != '-' || uuid[23] != '-') {
        printf("Error: UUID format invalid.\n");
        pause_and_continue();
        return;
    }
    get_input("Bot public key (88 chars base64): ", pubkey, sizeof(pubkey));
    size_t pl = strlen(pubkey);
    while (pl > 0 && (pubkey[pl-1]==' '||pubkey[pl-1]=='\r'||
                      pubkey[pl-1]=='\n'||pubkey[pl-1]=='\t'))
        pubkey[--pl] = '\0';
    if (pl != 88) {
        printf("Error: public key must be exactly 88 chars (got %zu).\n", pl);
        pause_and_continue();
        return;
    }

    /* Payload: NICK|UUID|PUBKEY_B64 */
    char payload[512];
    snprintf(payload, sizeof(payload), "%s|%s|%s", nick, uuid, pubkey);
    send_packet(g_fd, CMD_ADMIN_CREATE_BOT, payload, g_key);
    read_response(g_fd, g_key, response, sizeof(response));

    if (strncmp(response, "SUCCESS", 7) == 0) {
        printf("\n[+] Bot '%s' (UUID %s) registered.\n", nick, uuid);
        printf("    Hub UUID + pubkey were printed during 'irchub -setup'\n");
        printf("    (see hub_public.b64). Use those when configuring the\n");
        printf("    bot's hub connection from 'ircbot -setup'.\n");
    } else {
        printf("\nHub Response: %s\n", response);
    }

    pause_and_continue();
}

void bot_remove(void) {
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
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void bot_rekey(void) {
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
    
    /* Rekey is bot-local: only the bot can rotate its own keypair, because it
     * owns its private key (v3 trust model — the hub never holds bot privkeys).
     * This menu just relays the request; the hub replies with instructions to
     * run the bot's own 'rekey' admin command, which regenerates the keypair
     * locally, pushes the new pubkey to the hub, and reconnects. */
    if (!get_confirmation("Ask the bot to rekey itself (it will reconnect)?")) {
        return;
    }

    printf("\n[*] Requesting rekey instructions from hub...\n");
    send_packet(g_fd, CMD_ADMIN_REKEY_BOT, uuid, g_key);
    read_response(g_fd, g_key, response, sizeof(response));

    /* Hub replies INSTRUCT|<uuid>|<human-readable instructions> on success,
     * or ERROR|<reason>. Show the instructions (stripped of the prefix). */
    if (strncmp(response, "INSTRUCT|", 9) == 0) {
        char *p = strchr(response + 9, '|');
        const char *text = p ? p + 1 : response;
        printf("\n╔══════════════════════════════════════════════════╗\n");
        printf("║                  REKEY: NEXT STEP                ║\n");
        printf("╚══════════════════════════════════════════════════╝\n\n");
        printf("UUID: %s\n\n%s\n", uuid, text);
    } else {
        printf("Hub Response: %s\n", response);
    }
    secure_wipe(response, sizeof(response));

    printf("\nPress Enter to continue...");
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

// ============================================================================
// PEER (HUB) MANAGEMENT FUNCTIONS
// ============================================================================

void peer_list(void) {
    char *response = malloc(MAX_HUB_PACKET);
    if (!response) { printf("Error: Out of memory\n"); return; }

    printf("\n");
    send_packet(g_fd, CMD_ADMIN_LIST_PEERS, NULL, g_key);
    read_response(g_fd, g_key, response, MAX_HUB_PACKET);
    printf("%s\n", response);
    free(response);

    printf("\nPress Enter to continue...");
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void peer_add(void) {
    char response[MAX_BUFFER];
    char ip[64], port[10], uuid[64], name[64], pubkey[128];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("                   ADD PEER HUB\n");
    printf("═══════════════════════════════════════════════════\n");
    printf("Paste the peer's 88-char Curve25519 pubkey (contents of\n");
    printf("its hub_public.b64). The pubkey is required — connections\n");
    printf("from peers without a registered pubkey are refused.\n\n");

    get_input("Peer IP: ", ip, sizeof(ip));
    get_input("Peer Port: ", port, sizeof(port));
    get_input("Peer UUID: ", uuid, sizeof(uuid));
    get_input("Friendly Name (optional, auto-syncs): ", name, sizeof(name));
    get_input("Peer pubkey (88 char base64, required): ", pubkey, sizeof(pubkey));

    /* Strip trailing whitespace some terminals slip in. */
    size_t pl = strlen(pubkey);
    while (pl > 0 && (pubkey[pl-1] == ' ' || pubkey[pl-1] == '\r' ||
                      pubkey[pl-1] == '\n' || pubkey[pl-1] == '\t')) {
        pubkey[--pl] = '\0';
    }

    if (!pubkey[0]) {
        printf("\nError: pubkey is required. Re-add the peer after obtaining "
               "its hub_public.b64.\n");
        printf("\nPress Enter to continue...");
        fflush(stdout);
        char dummy[10];
        wait_for_input_or_socket(dummy, sizeof(dummy));
        return;
    }
    if (pl != 88) {
        printf("\nWarning: pubkey is %zu chars, expected 88. Submitting anyway; "
               "hub will reject if invalid.\n", pl);
    }
    char payload[512];
    snprintf(payload, sizeof(payload), "%s:%s:%s:%s:%s",
             ip, port, uuid, name, pubkey);

    send_packet(g_fd, CMD_ADMIN_ADD_PEER, payload, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("\nHub: %s\n", response);

    printf("\nPress Enter to continue...");
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void peer_remove(void) {
    char *response = malloc(MAX_HUB_PACKET);
    if (!response) { printf("Error: Out of memory\n"); return; }

    send_packet(g_fd, CMD_ADMIN_LIST_PEERS, NULL, g_key);
    read_response(g_fd, g_key, response, MAX_HUB_PACKET);
    printf("\n%s\n", response);

    char idx[10];
    get_input("Enter Index to Remove (or blank to cancel): ", idx, sizeof(idx));

    if (strlen(idx) > 0 && atoi(idx) > 0) {
        if (get_confirmation("Remove this peer?")) {
            send_packet(g_fd, CMD_ADMIN_DEL_PEER, idx, g_key);
            read_response(g_fd, g_key, response, MAX_HUB_PACKET);
            printf("Hub: %s\n", response);
        }
    }

    free(response);
    printf("\nPress Enter to continue...");
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void peer_set_pubkey(void) {
    char response[MAX_BUFFER];
    char uuid[64], pubkey[128];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("              SET PEER PUBKEY (v2 upgrade)\n");
    printf("═══════════════════════════════════════════════════\n");
    printf("Registers the peer's 88-char Curve25519 pubkey on an\n");
    printf("existing peer entry. The next connection from that peer\n");
    printf("will use Ed25519-signature auth (no admin_password).\n\n");
    printf("Get the pubkey from the peer's hub_public.b64 file.\n\n");

    get_input("Peer UUID: ", uuid, sizeof(uuid));
    get_input("Peer pubkey (88 char base64): ", pubkey, sizeof(pubkey));

    size_t pl = strlen(pubkey);
    while (pl > 0 && (pubkey[pl-1] == ' ' || pubkey[pl-1] == '\r' ||
                      pubkey[pl-1] == '\n' || pubkey[pl-1] == '\t'))
        pubkey[--pl] = '\0';

    if (!uuid[0] || !pubkey[0]) {
        printf("Cancelled.\n");
        return;
    }
    if (pl != 88)
        printf("\nWarning: pubkey is %zu chars, expected 88.\n", pl);

    char payload[256];
    snprintf(payload, sizeof(payload), "%s:%s", uuid, pubkey);
    send_packet(g_fd, CMD_ADMIN_SET_PEER_PUBKEY, payload, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("\nHub: %s\n", response);

    printf("\nPress Enter to continue...");
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void peer_force_sync(void) {
    char response[1024];
    
    printf("\n[*] Forcing mesh synchronization...\n");
    send_packet(g_fd, CMD_ADMIN_SYNC_MESH, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("Hub: %s\n", response);
    
    printf("\nPress Enter to continue...");
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void peer_rekey_hubs(void) {
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
        strftime(fname, sizeof(fname), "hub_public_%Y%m%d_%H%M%S.b64", t);
        
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
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

// ============================================================================
// ADMIN COMMANDS FUNCTIONS
// ============================================================================

void admin_op_user(void) {
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
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void pause_and_continue(void) {
    printf("\nPress Enter to continue...");
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

/* ---- Admin management (v2: named records) ---- */

void admin_list_admins(void) {
    char response[MAX_BUFFER];
    printf("\n");
    send_packet(g_fd, CMD_ADMIN_LIST_ADMINS, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("%s\n", response);
    pause_and_continue();
}

void admin_add_admin_record(void) {
    char response[MAX_BUFFER];
    char name[64], pass[MAX_PASS], mask[256];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("                   ADD ADMIN\n");
    printf("═══════════════════════════════════════════════════\n\n");
    printf("Friendly name (no spaces, e.g. robert): ");
    get_input("Name: ", name, sizeof(name));
    get_password_secure("Admin Password: ", pass, sizeof(pass));
    printf("First usermask (e.g. nick!*@*.example.com): ");
    get_input("Mask: ", mask, sizeof(mask));

    if (strlen(name) > 0 && strlen(pass) > 0 && strlen(mask) > 0) {
        char payload[MAX_BUFFER];
        snprintf(payload, sizeof(payload), "%s|%s|%s", name, pass, mask);
        send_packet(g_fd, CMD_ADMIN_ADD_ADMIN, payload, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        secure_wipe(pass, sizeof(pass));
        secure_wipe(payload, sizeof(payload));
        /* Response format: SUCCESS|<a|o>|<name>|<mask>|<priv_b64>|<pub_b64>
         * Pull out the priv_b64 and offer to save it. */
        if (strncmp(response, "SUCCESS|", 8) == 0) {
            char *toks[6] = {0}; int n = 0;
            char *save_ptr2 = NULL;
            char *t = strtok_r(response, "|", &save_ptr2);
            while (t && n < 6) { toks[n++] = t; t = strtok_r(NULL, "|", &save_ptr2); }
            const char *priv_b64 = (n > 4) ? toks[4] : "";
            const char *pub_b64  = (n > 5) ? toks[5] : "";
            printf("\n[+] Admin '%s' created.\n", name);
            if (priv_b64 && priv_b64[0]) {
                printf("\n    ┌──────────────────────────────────────────────────────────┐\n");
                printf("    │ ⚠ Admin '%s' PRIVATE key (save NOW; NOT stored on hub):\n",
                       name);
                printf("    │                                                          \n");
                printf("    │  %s\n", priv_b64);
                printf("    │                                                          \n");
                printf("    │ Save to admin_%s.b64 (mode 0600) on the host that will  \n",
                       name);
                printf("    │ run hub_admin under this name.  Then:                    \n");
                printf("    │   ./hub_admin <ip> <port> admin_%s.b64                   \n",
                       name);
                printf("    │                                                          \n");
                printf("    │ Not recoverable if lost — admin must be re-created.      \n");
                printf("    └──────────────────────────────────────────────────────────┘\n");
                if (pub_b64 && pub_b64[0])
                    printf("\n    Public key (mesh-replicated): %s\n", pub_b64);
            }
        } else {
            printf("\nHub: %s\n", response);
        }
    }
    pause_and_continue();
}

void admin_del_admin_record(void) {
    char response[MAX_BUFFER];
    send_packet(g_fd, CMD_ADMIN_LIST_ADMINS, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("\n%s\n", response);

    char name[64];
    get_input("Admin name to REMOVE (or blank to cancel): ", name, sizeof(name));
    if (strlen(name) > 0 && get_confirmation("Remove this admin and all their masks?")) {
        send_packet(g_fd, CMD_ADMIN_DEL_ADMIN, name, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("Hub: %s\n", response);
    }
    pause_and_continue();
}

/* ---- Oper management (v2: named records) ---- */

void admin_list_opers(void) {
    char response[MAX_BUFFER];
    printf("\n");
    send_packet(g_fd, CMD_ADMIN_LIST_OPERS_V2, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("%s\n", response);
    pause_and_continue();
}

void admin_add_oper_record(void) {
    char response[MAX_BUFFER];
    char name[64], pass[MAX_PASS], mask[256];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("                    ADD OPER\n");
    printf("═══════════════════════════════════════════════════\n\n");
    get_input("Name: ", name, sizeof(name));
    get_password_secure("Oper Password: ", pass, sizeof(pass));
    get_input("First usermask (e.g. nick!*@hostname.com): ", mask, sizeof(mask));

    if (strlen(name) > 0 && strlen(pass) > 0 && strlen(mask) > 0) {
        char payload[MAX_BUFFER];
        snprintf(payload, sizeof(payload), "%s|%s|%s", name, pass, mask);
        send_packet(g_fd, CMD_ADMIN_ADD_OPER_RECORD, payload, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        secure_wipe(pass, sizeof(pass));
        secure_wipe(payload, sizeof(payload));
        if (strncmp(response, "SUCCESS|", 8) == 0) {
            char *toks[6] = {0}; int n = 0;
            char *save_ptr2 = NULL;
            char *t = strtok_r(response, "|", &save_ptr2);
            while (t && n < 6) { toks[n++] = t; t = strtok_r(NULL, "|", &save_ptr2); }
            const char *priv_b64 = (n > 4) ? toks[4] : "";
            const char *pub_b64  = (n > 5) ? toks[5] : "";
            printf("\n[+] Oper '%s' created.\n", name);
            if (priv_b64 && priv_b64[0]) {
                printf("\n    ┌──────────────────────────────────────────────────────────┐\n");
                printf("    │ ⚠ Oper '%s' PRIVATE key (save NOW; NOT stored on hub): \n",
                       name);
                printf("    │                                                          \n");
                printf("    │  %s\n", priv_b64);
                printf("    │                                                          \n");
                printf("    │ Opers currently do not need this key for hub_admin login \n");
                printf("    │ (only admins do), but save it for future use.            \n");
                printf("    └──────────────────────────────────────────────────────────┘\n");
                if (pub_b64 && pub_b64[0])
                    printf("\n    Public key (mesh-replicated): %s\n", pub_b64);
            }
        } else {
            printf("\nHub: %s\n", response);
        }
    }
    pause_and_continue();
}

void admin_del_oper_record(void) {
    char response[MAX_BUFFER];
    send_packet(g_fd, CMD_ADMIN_LIST_OPERS_V2, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("\n%s\n", response);

    char name[64];
    get_input("Oper name to REMOVE (or blank to cancel): ", name, sizeof(name));
    if (strlen(name) > 0 && get_confirmation("Remove this oper and all their masks?")) {
        send_packet(g_fd, CMD_ADMIN_DEL_OPER_RECORD, name, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("Hub: %s\n", response);
    }
    pause_and_continue();
}

/* ---- Shared usermask management ---- */

void admin_add_usermask(void) {
    char response[MAX_BUFFER];
    char name[64], mask[256];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("               ADD USERMASK TO USER\n");
    printf("═══════════════════════════════════════════════════\n\n");
    get_input("User name (admin or oper): ", name, sizeof(name));
    get_input("New usermask (e.g. nick!*@*.example.com): ", mask, sizeof(mask));

    if (strlen(name) > 0 && strlen(mask) > 0) {
        char payload[512];
        snprintf(payload, sizeof(payload), "%s|%s", name, mask);
        send_packet(g_fd, CMD_ADMIN_ADD_USERMASK, payload, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("\nHub: %s\n", response);
    }
    pause_and_continue();
}

void admin_del_usermask(void) {
    char response[MAX_BUFFER];
    char name[64], mask[256];

    get_input("User name: ", name, sizeof(name));
    if (strlen(name) > 0) {
        char match_payload[64];
        snprintf(match_payload, sizeof(match_payload), "%s", name);
        send_packet(g_fd, CMD_ADMIN_MATCH, match_payload, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("\n%s\n", response);
    }
    get_input("Mask to REMOVE (or blank to cancel): ", mask, sizeof(mask));
    if (strlen(name) > 0 && strlen(mask) > 0 && get_confirmation("Remove this mask?")) {
        char payload[512];
        snprintf(payload, sizeof(payload), "%s|%s", name, mask);
        send_packet(g_fd, CMD_ADMIN_DEL_USERMASK, payload, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("Hub: %s\n", response);
    }
    pause_and_continue();
}

void admin_match_user(void) {
    char response[MAX_BUFFER];
    char name[64];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("                    MATCH USER\n");
    printf("═══════════════════════════════════════════════════\n\n");
    printf("Enter a name to show that user's records, or * for all users.\n");
    printf("WARNING: * may produce many lines of output.\n\n");
    get_input("Name or *: ", name, sizeof(name));

    if (strlen(name) > 0) {
        send_packet(g_fd, CMD_ADMIN_MATCH, name, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("\n%s\n", response);
    }
    pause_and_continue();
}

void admin_change_userpass(void) {
    char response[MAX_BUFFER];
    char name[64], pass[MAX_PASS];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("               CHANGE USER PASSWORD\n");
    printf("═══════════════════════════════════════════════════\n\n");
    get_input("User name: ", name, sizeof(name));
    get_password_secure("New Password: ", pass, sizeof(pass));

    if (strlen(name) > 0 && strlen(pass) > 0) {
        char payload[MAX_PASS + 70];
        snprintf(payload, sizeof(payload), "%s|%s", name, pass);
        send_packet(g_fd, CMD_ADMIN_SET_USERPASS, payload, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("\nHub: %s\n", response);
        secure_wipe(pass, sizeof(pass));
        secure_wipe(payload, sizeof(payload));
    }
    pause_and_continue();
}

void admin_list_channels(void) {
    char response[MAX_BUFFER];

    printf("\n");
    send_packet(g_fd, CMD_ADMIN_LIST_CHANNELS, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("%s\n", response);

    printf("\nPress Enter to continue...");
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_add_channel(void) {
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
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_del_channel(void) {
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
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_change_admin_password(void) {
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
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_change_bot_password(void) {
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
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_purge_tombstones(void) {
    char response[MAX_BUFFER];
    char choice[10];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("             PURGE TOMBSTONED ENTRIES\n");
    printf("═══════════════════════════════════════════════════\n\n");
    printf("This will permanently remove deleted (tombstoned)\n");
    printf("channels, admin masks, and oper masks.\n\n");
    printf("  1. Immediate purge (all tombstones)\n");
    printf("  2. Time-based purge (default: 30 days)\n");
    printf("  3. Custom time-based purge\n");
    printf("  4. Cancel\n\n");

    get_input("Select option: ", choice, sizeof(choice));
    int opt = atoi(choice);

    char payload[64] = "";
    bool proceed = false;

    switch(opt) {
        case 1:
            snprintf(payload, sizeof(payload), "immediate");
            proceed = get_confirmation("Purge ALL tombstoned entries immediately?");
            break;
        case 2:
            snprintf(payload, sizeof(payload), "30");
            proceed = get_confirmation("Purge tombstones older than 30 days?");
            break;
        case 3: {
            char days[10];
            get_input("Enter number of days: ", days, sizeof(days));
            int d = atoi(days);
            if (d > 0) {
                snprintf(payload, sizeof(payload), "%d", d);
                char confirm_msg[128];
                snprintf(confirm_msg, sizeof(confirm_msg),
                         "Purge tombstones older than %d days?", d);
                proceed = get_confirmation(confirm_msg);
            } else {
                printf("Invalid number of days.\n");
            }
            break;
        }
        case 4:
            printf("Cancelled.\n");
            break;
        default:
            printf("Invalid option.\n");
            break;
    }

    if (proceed) {
        printf("\n[*] Sending purge request to hub...\n");
        send_packet(g_fd, CMD_ADMIN_PURGE_TOMBSTONES, payload, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("\nHub Response:\n%s\n", response);
    }

    printf("\nPress Enter to continue...");
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_configure_auto_purge(void) {
    char response[MAX_BUFFER];
    char days_input[10];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("         CONFIGURE AUTOMATIC PURGE\n");
    printf("═══════════════════════════════════════════════════\n\n");
    printf("Configure automatic daily purging of old tombstones.\n");
    printf("Tombstones are deleted channels, masks, and opers.\n\n");
    printf("Enter number of days (tombstones older than this\n");
    printf("will be purged daily), or 0 to disable:\n\n");

    get_input("Days (0 to disable): ", days_input, sizeof(days_input));
    int days = atoi(days_input);

    if (days < 0) {
        printf("Invalid input. Must be 0 or positive number.\n");
        printf("\nPress Enter to continue...");
        fflush(stdout);
        char dummy[10];
        wait_for_input_or_socket(dummy, sizeof(dummy));
        return;
    }

    char payload[16];
    snprintf(payload, sizeof(payload), "%d", days);

    printf("\n[*] Sending configuration to hub...\n");
    send_packet(g_fd, CMD_ADMIN_SET_PURGE_DAYS, payload, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("\nHub Response:\n%s\n", response);

    printf("\nPress Enter to continue...");
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_list_allowlist(void) {
    char response[MAX_BUFFER];

    printf("\n");
    send_packet(g_fd, CMD_ADMIN_LIST_ALLOWLIST, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("%s\n", response);

    printf("\nPress Enter to continue...");
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_add_allowlist(void) {
    char response[MAX_BUFFER];
    char ip_pattern[256];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("              ADD IP TO ALLOWLIST\n");
    printf("═══════════════════════════════════════════════════\n\n");
    printf("Format examples:\n");
    printf("  192.168.1.5       - Single IP\n");
    printf("  192.168.1.0/24    - Subnet (CIDR notation)\n");
    printf("  10.0.0.0/8        - Large network\n\n");

    get_input("IP or CIDR pattern: ", ip_pattern, sizeof(ip_pattern));

    if (strlen(ip_pattern) > 0) {
        send_packet(g_fd, CMD_ADMIN_ADD_ALLOWLIST, ip_pattern, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("\nHub: %s\n", response);
    }

    printf("\nPress Enter to continue...");
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_del_allowlist(void) {
    char response[MAX_BUFFER];

    send_packet(g_fd, CMD_ADMIN_LIST_ALLOWLIST, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("\n%s\n", response);

    char ip_pattern[256];
    get_input("IP/CIDR to REMOVE (or blank to cancel): ", ip_pattern, sizeof(ip_pattern));

    if (strlen(ip_pattern) > 0 && get_confirmation("Remove this allowlist entry?")) {
        send_packet(g_fd, CMD_ADMIN_DEL_ALLOWLIST, ip_pattern, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("Hub: %s\n", response);
    }

    printf("\nPress Enter to continue...");
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_list_denylist(void) {
    char response[MAX_BUFFER];

    printf("\n");
    send_packet(g_fd, CMD_ADMIN_LIST_DENYLIST, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("%s\n", response);

    printf("\nPress Enter to continue...");
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_add_denylist(void) {
    char response[MAX_BUFFER];
    char ip_pattern[256];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("              ADD IP TO DENYLIST\n");
    printf("═══════════════════════════════════════════════════\n\n");
    printf("Format examples:\n");
    printf("  192.168.1.5       - Single IP\n");
    printf("  192.168.1.0/24    - Subnet (CIDR notation)\n");
    printf("  10.0.0.0/8        - Large network\n\n");

    get_input("IP or CIDR pattern: ", ip_pattern, sizeof(ip_pattern));

    if (strlen(ip_pattern) > 0) {
        send_packet(g_fd, CMD_ADMIN_ADD_DENYLIST, ip_pattern, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("\nHub: %s\n", response);
    }

    printf("\nPress Enter to continue...");
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_del_denylist(void) {
    char response[MAX_BUFFER];

    send_packet(g_fd, CMD_ADMIN_LIST_DENYLIST, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("\n%s\n", response);

    char ip_pattern[256];
    get_input("IP/CIDR to REMOVE (or blank to cancel): ", ip_pattern, sizeof(ip_pattern));

    if (strlen(ip_pattern) > 0 && get_confirmation("Remove this denylist entry?")) {
        send_packet(g_fd, CMD_ADMIN_DEL_DENYLIST, ip_pattern, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("Hub: %s\n", response);
    }

    printf("\nPress Enter to continue...");
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void menu_manage_allowlist(void) {
    while (1) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║            MANAGE IP ALLOWLIST                   ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("  1. List Allowlist\n");
        printf("  2. Add IP to Allowlist\n");
        printf("  3. Remove IP from Allowlist\n");
        printf("  4. Back to Manage Peer Config\n");
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
            case 1: admin_list_allowlist(); break;
            case 2: admin_add_allowlist(); break;
            case 3: admin_del_allowlist(); break;
            case 4: return;
            default: printf("Invalid choice.\n"); break;
        }
    }
}

void menu_manage_denylist(void) {
    while (1) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║            MANAGE IP DENYLIST                    ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("  1. List Denylist\n");
        printf("  2. Add IP to Denylist\n");
        printf("  3. Remove IP from Denylist\n");
        printf("  4. Back\n");
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
            case 1: admin_list_denylist(); break;
            case 2: admin_add_denylist(); break;
            case 3: admin_del_denylist(); break;
            case 4: return;
            default: printf("Invalid choice.\n"); break;
        }
    }
}

void admin_set_bind_ip(void) {
    char response[MAX_BUFFER];
    char ip[64];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("                SET BIND IP ADDRESS\n");
    printf("═══════════════════════════════════════════════════\n\n");
    printf("Set the IP address this hub binds to:\n");
    printf("  0.0.0.0      - Bind to all interfaces (default)\n");
    printf("  127.0.0.1    - Localhost only\n");
    printf("  192.168.x.x  - Specific interface\n\n");
    printf("NOTE: Hub restart required for changes to take effect.\n\n");

    get_input("Bind IP: ", ip, sizeof(ip));

    if (strlen(ip) > 0) {
        send_packet(g_fd, CMD_ADMIN_SET_BIND_IP, ip, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("\nHub: %s\n", response);
    }

    printf("\nPress Enter to continue...");
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_set_hub_name(void) {
    char response[MAX_BUFFER];
    char name[64];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("                   SET HUB NAME\n");
    printf("═══════════════════════════════════════════════════\n\n");
    printf("Set a friendly name for this hub.\n");
    printf("This name will be synced across the mesh network.\n\n");

    get_input("Hub Name: ", name, sizeof(name));

    if (strlen(name) > 0) {
        send_packet(g_fd, CMD_ADMIN_SET_HUB_NAME, name, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("\nHub: %s\n", response);
    }

    printf("\nPress Enter to continue...");
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_set_bind_port(void) {
    char response[MAX_BUFFER];
    char port[10];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("                 SET BIND PORT\n");
    printf("═══════════════════════════════════════════════════\n\n");
    printf("Set the port this hub listens on (1-65535).\n");
    printf("NOTE: Hub restart required for changes to take effect.\n\n");

    get_input("Bind Port: ", port, sizeof(port));

    if (strlen(port) > 0) {
        send_packet(g_fd, CMD_ADMIN_SET_BIND_PORT, port, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("\nHub: %s\n", response);
    }

    printf("\nPress Enter to continue...");
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_export_private_key(void) {
    char response[MAX_BUFFER];

    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║           *** SECURITY WARNING ***               ║\n");
    printf("║              EXPORT PRIVATE KEY                  ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");
    printf("This is the hub's private key used for hub-to-hub\n");
    printf("and hub_admin authentication. Anyone with this key\n");
    printf("can authenticate to this hub.\n\n");
    printf("  - Store it in a password manager or encrypted vault\n");
    printf("  - Never share it over unencrypted channels\n");
    printf("  - Keep a secure backup — losing it means re-keying\n");
    printf("    all peer hubs and hub_admin installations\n\n");

    if (!get_confirmation("I understand the risks. Export private key?")) {
        printf("Cancelled.\n");
        printf("\nPress Enter to continue...");
        fflush(stdout);
        char dummy[10];
        wait_for_input_or_socket(dummy, sizeof(dummy));
        return;
    }

    send_packet(g_fd, CMD_ADMIN_GET_PRIVKEY, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));

    if (strncmp(response, "ERROR", 5) == 0) {
        printf("\n%s\n", response);
    } else {
        printf("\n  1. Save to file\n");
        printf("  2. Print to terminal only (do not write to disk)\n\n");
        char choice[4];
        get_input("Choice: ", choice, sizeof(choice));

        if (atoi(choice) == 2) {
            printf("\n══════════════════════ PRIVATE KEY ══════════════════════\n");
            printf("%s\n", response);
            printf("═════════════════════════════════════════════════════════\n");
            printf("Copy and store this key securely before closing.\n");
        } else {
            time_t now = time(NULL);
            struct tm *t = localtime(&now);
            char fname[64];
            strftime(fname, sizeof(fname), "hub_private_%Y%m%d_%H%M%S.b64", t);
            /* Create the private-key file with mode 0600 atomically.  fopen("w")
             * honors the umask first and would leave the key world-readable in
             * the window before chmod — a local-disclosure race for key
             * material.  open(O_CREAT,0600)+fchmod closes that window. */
            int kfd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            FILE *f = (kfd >= 0) ? fdopen(kfd, "w") : NULL;
            if (f) {
                (void)fchmod(fileno(f), 0600);
                fputs(response, f);
                fclose(f);
                printf("\n[PRIVATE KEY SAVED: %s] (permissions: 0600)\n", fname);
                printf("Move this file to secure storage and delete it from here.\n");
            } else {
                if (kfd >= 0) close(kfd);
                printf("\nFailed to save private key to file.\n");
            }
        }
        secure_wipe(response, strlen(response));
    }

    printf("\nPress Enter to continue...");
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_export_public_key(void) {
    char response[MAX_BUFFER];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("               EXPORT PUBLIC KEY\n");
    printf("═══════════════════════════════════════════════════\n\n");
    printf("The public key is required by hub_admin to connect.\n");
    printf("Share it with anyone who needs hub_admin access.\n\n");
    printf("  1. Save to file\n");
    printf("  2. Print to terminal only\n\n");

    send_packet(g_fd, CMD_ADMIN_GET_PUBKEY, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));

    if (strncmp(response, "ERROR", 5) == 0) {
        printf("\n%s\n", response);
    } else {
        char choice[4];
        get_input("Choice: ", choice, sizeof(choice));

        if (atoi(choice) == 2) {
            printf("\n══════════════════════ PUBLIC KEY ═══════════════════════\n");
            printf("%s\n", response);
            printf("═════════════════════════════════════════════════════════\n");
            printf("Usage: ./hub_admin <ip> <port> <key_file>\n");
            printf("Save this string to a .b64 file and pass it as the third argument.\n");
        } else {
            time_t now = time(NULL);
            struct tm *t = localtime(&now);
            char fname[64];
            strftime(fname, sizeof(fname), "hub_public_%Y%m%d_%H%M%S.b64", t);
            FILE *f = fopen(fname, "w");
            if (f) {
                fputs(response, f);
                fclose(f);
                printf("\n[PUBLIC KEY SAVED: %s]\n\n", fname);
                printf("Use with hub_admin:\n");
                printf("  ./hub_admin <ip> <port> %s\n", fname);
            } else {
                printf("\nFailed to save public key to file.\n");
            }
        }
    }

    printf("\nPress Enter to continue...");
    fflush(stdout);
    char dummy[10];
    wait_for_input_or_socket(dummy, sizeof(dummy));
}

void admin_set_log_level(void) {
    printf("\n");
    printf("Log Levels:\n");
    printf("  0: NONE (no logging)\n");
    printf("  1: ERROR (only errors)\n");
    printf("  2: WARNING (errors + warnings)\n");
    printf("  3: INFO (errors + warnings + info) [default]\n");
    printf("  4: DEBUG (everything)\n");
    printf("\n");

    char buf[10];
    printf("Select level (0-4): ");
    fflush(stdout);
    if (!wait_for_input_or_socket(buf, sizeof(buf))) {
        printf("\n[!] Connection lost.\n");
        exit(1);
    }

    int level = atoi(buf);
    if (level < 0 || level > 4) {
        printf("Invalid level.\n");
        return;
    }

    // Send command to hub using encrypted packet
    unsigned char payload[1];
    payload[0] = (unsigned char)level;
    send_packet_binary(g_fd, CMD_ADMIN_SET_LOG_LEVEL, payload, 1, g_key);

    char response[1024];
    read_response(g_fd, g_key, response, sizeof(response));
    printf("[+] %s\n", response);
}

void admin_set_log_size_limit(void) {
    printf("\nCurrent default: 10 MB\n");
    printf("Enter log size limit in MB (1-1024): ");
    fflush(stdout);

    char buf[10];
    if (!wait_for_input_or_socket(buf, sizeof(buf))) {
        printf("\n[!] Connection lost.\n");
        exit(1);
    }

    int mb = atoi(buf);
    if (mb < 1 || mb > 1024) {
        printf("Invalid size (must be 1-1024 MB).\n");
        return;
    }

    uint32_t bytes = (uint32_t)mb * 1024 * 1024;
    uint32_t network_bytes = htonl(bytes);

    // Send command to hub using encrypted packet
    unsigned char payload[4];
    memcpy(payload, &network_bytes, 4);
    send_packet_binary(g_fd, CMD_ADMIN_SET_LOG_SIZE, payload, 4, g_key);

    char response[1024];
    read_response(g_fd, g_key, response, sizeof(response));
    printf("[+] %s\n", response);
}

void menu_manage_admins(void) {
    while (1) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║               MANAGE ADMINS                      ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("  1. List Admins\n");
        printf("  2. Add Admin\n");
        printf("  3. Remove Admin\n");
        printf("  4. Add Usermask to Admin/Oper\n");
        printf("  5. Remove Usermask from Admin/Oper\n");
        printf("  6. Change User Password\n");
        printf("  7. Match User (show all records)\n");
        printf("  8. Back\n");
        printf("\n");
        printf("Select: ");
        fflush(stdout);

        char buf[10];
        if (!wait_for_input_or_socket(buf, sizeof(buf))) {
            printf("\n[!] Connection lost.\n");
            exit(1);
        }

        switch(atoi(buf)) {
            case 1: admin_list_admins();       break;
            case 2: admin_add_admin_record();  break;
            case 3: admin_del_admin_record();  break;
            case 4: admin_add_usermask();      break;
            case 5: admin_del_usermask();      break;
            case 6: admin_change_userpass();   break;
            case 7: admin_match_user();        break;
            case 8: return;
            default: printf("Invalid choice.\n"); break;
        }
    }
}

void menu_manage_opers(void) {
    while (1) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║               MANAGE OPERS                       ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("  1. List Opers\n");
        printf("  2. Add Oper\n");
        printf("  3. Remove Oper\n");
        printf("  4. Add Usermask to Oper\n");
        printf("  5. Remove Usermask from Oper\n");
        printf("  6. Change Oper Password\n");
        printf("  7. Match User (show all records)\n");
        printf("  8. Back\n");
        printf("\n");
        printf("Select: ");
        fflush(stdout);

        char buf[10];
        if (!wait_for_input_or_socket(buf, sizeof(buf))) {
            printf("\n[!] Connection lost.\n");
            exit(1);
        }

        switch(atoi(buf)) {
            case 1: admin_list_opers();         break;
            case 2: admin_add_oper_record();    break;
            case 3: admin_del_oper_record();    break;
            case 4: admin_add_usermask();       break;
            case 5: admin_del_usermask();       break;
            case 6: admin_change_userpass();    break;
            case 7: admin_match_user();         break;
            case 8: return;
            default: printf("Invalid choice.\n"); break;
        }
    }
}

void menu_manage_channels(void) {
    while (1) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║               MANAGE CHANNELS                    ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("  1. List Channels\n");
        printf("  2. Add Channel\n");
        printf("  3. Del Channel\n");
        printf("  4. Back\n");
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

static void admin_show_opt_flags(void) {
    char response[256];
    send_packet(g_fd, CMD_ADMIN_GET_OPT_FLAGS, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("\nCurrent network opt flags:\n  %s\n", response);
    pause_and_continue();
}

static void admin_set_opt_flags_cli(void) {
    char response[256];
    char flags[64];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("              SET NETWORK OPT FLAGS\n");
    printf("═══════════════════════════════════════════════════\n");
    printf("Each character is a single option letter [a-zA-Z0-9].\n");
    printf("Known options:\n");
    printf("  h  hub-only mutations (bots refuse local +admin/-admin,\n");
    printf("     +oper/-oper, +usermask/-usermask, +bot/-bot, join/part,\n");
    printf("     botpass, chpass, +hub/-hub)\n\n");
    printf("Enter the full flag string (empty to clear): ");
    fflush(stdout);
    if (!wait_for_input_or_socket(flags, sizeof(flags))) return;

    send_packet(g_fd, CMD_ADMIN_SET_OPT_FLAGS, flags, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("\nHub: %s\n", response);
    pause_and_continue();
}

void menu_manage_global_peer_config(void) {
    while (1) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║         MANAGE GLOBAL PEER CONFIG                ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("  1. Show Opt Flags\n");
        printf("  2. Set Opt Flags\n");
        printf("  3. Back to Main Menu\n");
        printf("\n");
        printf("Select: ");
        fflush(stdout);

        char buf[10];
        if (!wait_for_input_or_socket(buf, sizeof(buf))) {
            printf("\n[!] Connection lost.\n");
            exit(1);
        }

        switch(atoi(buf)) {
            case 1: admin_show_opt_flags();    break;
            case 2: admin_set_opt_flags_cli(); break;
            case 3: return;
            default: printf("Invalid choice.\n"); break;
        }
    }
}

void menu_admin_commands(void) {
    while (1) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║             IRC ADMIN COMMANDS                   ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("  1. Op User\n");
        printf("  2. Manage Admins\n");
        printf("  3. Manage Opers\n");
        printf("  4. Manage Channels\n");
        printf("  5. Change Bot Password\n");
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
                admin_op_user();
                break;
            case 2:
                menu_manage_admins();
                break;
            case 3:
                menu_manage_opers();
                break;
            case 4:
                menu_manage_channels();
                break;
            case 5:
                admin_change_bot_password();
                break;
            case 6:
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

void menu_manage_bots(void) {
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

void menu_manage_peer_connections(void) {
    while (1) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║          MANAGE PEER CONNECTIONS                 ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("  1. List Peers (Mesh Matrix)\n");
        printf("  2. Add Peer\n");
        printf("  3. Remove Peer\n");
        printf("  4. Set Peer Pubkey (upgrade to v2 auth)\n");
        printf("  5. Force Mesh Sync\n");
        printf("  6. Rekey Hubs (DANGER)\n");
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
                peer_list();
                break;
            case 2:
                peer_add();
                break;
            case 3:
                peer_remove();
                break;
            case 4:
                peer_set_pubkey();
                break;
            case 5:
                peer_force_sync();
                break;
            case 6:
                peer_rekey_hubs();
                break;
            case 7:
                return;  // Back to main menu
            default:
                printf("Invalid choice.\n");
                break;
        }
    }
}

void menu_manage_peer_config(void) {
    while (1) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║         MANAGE LOCAL PEER CONFIG                 ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("  1. Set Hub Name\n");
        printf("  2. Set Bind IP\n");
        printf("  3. Set Bind Port\n");
        printf("  4. Manage IP Allowlist\n");
        printf("  5. Manage IP Denylist\n");
        printf("  6. Purge Tombstones\n");
        printf("  7. Configure Automatic Purge\n");
        printf("  8. Export Private Key\n");
        printf("  9. Export Public Key\n");
        printf(" 10. Set Log Level\n");
        printf(" 11. Set Log Size Limit\n");
        printf(" 12. Change Hub Admin Password\n");
        printf(" 13. Back to Main Menu\n");
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
                admin_set_hub_name();
                break;
            case 2:
                admin_set_bind_ip();
                break;
            case 3:
                admin_set_bind_port();
                break;
            case 4:
                menu_manage_allowlist();
                break;
            case 5:
                menu_manage_denylist();
                break;
            case 6:
                admin_purge_tombstones();
                break;
            case 7:
                admin_configure_auto_purge();
                break;
            case 8:
                admin_export_private_key();
                break;
            case 9:
                admin_export_public_key();
                break;
            case 10:
                admin_set_log_level();
                break;
            case 11:
                admin_set_log_size_limit();
                break;
            case 12:
                admin_change_admin_password();
                break;
            case 13:
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
        printf("Usage: ./hub_admin <ip> <port> <admin_<name>_priv.b64>\n");
        printf("\n");
        printf("The admin's Curve25519 private key file (88-char base64 of\n");
        printf("the 64-byte combined Ed25519+X25519 key) is the only credential\n");
        printf("required.  The hub's public key is fetched at connect time over\n");
        printf("the same TCP connection (no hub_public.b64 file needed).\n");
        return 1;
    }

    /* Load admin's combined Curve25519 PRIVATE key (88 chars base64). */
    FILE *f = fopen(argv[3], "r");
    if (!f) {
        perror("Failed to open admin priv key file");
        return 1;
    }
    char ab64[128] = {0};
    if (!fgets(ab64, sizeof(ab64), f)) {
        fprintf(stderr, "Failed to read admin priv key file\n");
        fclose(f);
        return 1;
    }
    fclose(f);
    ab64[strcspn(ab64, "\r\n")] = 0;

    int adec_len = 0;
    unsigned char *admin_priv_combined = base64_decode(ab64, &adec_len);
    secure_wipe(ab64, sizeof(ab64));
    if (!admin_priv_combined || adec_len != 64) {
        fprintf(stderr, "Invalid admin priv key file: expected 64-byte "
                        "Curve25519 combined key (88 chars base64).\n");
        if (admin_priv_combined) free(admin_priv_combined);
        return 1;
    }
    /* Layout: ed_priv(32) || x_priv(32).  We only use x_priv for the
     * ECDH that derives the session key.  Could later sign a challenge
     * with ed_priv for stronger anti-replay (not yet implemented). */
    unsigned char admin_x_priv[32], admin_ed_priv[32];
    memcpy(admin_ed_priv, admin_priv_combined,      32);
    memcpy(admin_x_priv,  admin_priv_combined + 32, 32);
    secure_wipe(admin_priv_combined, 64);
    free(admin_priv_combined);
    (void)admin_ed_priv; /* reserved for future signed handshake */

    /* Derive admin X25519 public key from the loaded priv. */
    unsigned char admin_x_pub[32];
    {
        EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                    admin_x_priv, 32);
        size_t l = 32;
        bool ok = pk && EVP_PKEY_get_raw_public_key(pk, admin_x_pub, &l) == 1 && l == 32;
        if (pk) EVP_PKEY_free(pk);
        if (!ok) {
            fprintf(stderr, "Failed to derive admin pubkey from priv key.\n");
            secure_wipe(admin_x_priv, 32);
            return 1;
        }
    }
    (void)admin_x_pub;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(atoi(argv[2]))
    };
    inet_pton(AF_INET, argv[1], &addr.sin_addr);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("Connect failed");
        secure_wipe(admin_x_priv, 32);
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    g_fd = fd;

    /* Step 1: ADMIN-HELLO probe.  Hub responds with its X25519 pubkey + UUID
     * over the same TCP socket — no hub_public.b64 file needed. */
    {
        const char *hello = "ADMIN-HELLO";
        uint32_t nl = htonl(11);
        if (write(fd, &nl, 4) != 4 || write(fd, hello, 11) != 11) {
            perror("HELLO write failed");
            secure_wipe(admin_x_priv, 32);
            close(fd);
            return 1;
        }
    }

    unsigned char hub_x25519_pub[32] = {0};
    {
        uint32_t rnl;
        if (recv_all(fd, &rnl, 4) != 4) {
            fprintf(stderr, "No HELLO reply from hub.\n");
            secure_wipe(admin_x_priv, 32);
            close(fd);
            return 1;
        }
        int rl = (int)ntohl(rnl);
        if (rl < 14 || rl > 200) {
            fprintf(stderr, "HELLO reply length out of range: %d\n", rl);
            secure_wipe(admin_x_priv, 32);
            close(fd);
            return 1;
        }
        char reply[256] = {0};
        if (recv_all(fd, reply, rl) != rl) {
            fprintf(stderr, "Short HELLO reply.\n");
            secure_wipe(admin_x_priv, 32);
            close(fd);
            return 1;
        }
        reply[rl] = 0;
        if (strncmp(reply, "HUB-PUBKEY|", 11) != 0) {
            fprintf(stderr, "Unexpected HELLO reply: %s\n", reply);
            secure_wipe(admin_x_priv, 32);
            close(fd);
            return 1;
        }
        char *pub_b64 = reply + 11;
        char *bar = strchr(pub_b64, '|');
        if (bar) *bar = 0;
        int xpd = 0;
        unsigned char *xpd_buf = base64_decode(pub_b64, &xpd);
        if (!xpd_buf || xpd != 32) {
            fprintf(stderr, "HELLO reply pubkey not 32 bytes.\n");
            if (xpd_buf) free(xpd_buf);
            secure_wipe(admin_x_priv, 32);
            close(fd);
            return 1;
        }
        memcpy(hub_x25519_pub, xpd_buf, 32);
        free(xpd_buf);
        printf("[*] Discovered hub X25519 pubkey via HELLO.\n");
    }

    /* Step 2: prompt for admin name + password, then sealed-box AUTH using
     * the admin's STATIC X25519 priv (instead of an ephemeral) so the hub
     * can identify the admin by the pubkey on the wire. */
    char auth_name[64];
    char auth_pass[128];
    printf("Admin name: ");
    fflush(stdout);
    if (!fgets(auth_name, sizeof(auth_name), stdin)) {
        fprintf(stderr, "No name provided.\n");
        secure_wipe(admin_x_priv, 32);
        close(fd);
        return 1;
    }
    auth_name[strcspn(auth_name, "\r\n")] = '\0';
    if (!auth_name[0]) {
        fprintf(stderr, "Empty admin name.\n");
        secure_wipe(admin_x_priv, 32);
        close(fd);
        return 1;
    }
    get_password_secure("Admin Password: ", auth_pass, sizeof(auth_pass));

    unsigned char plain[256];
    int msg_len = snprintf((char*)plain, sizeof(plain), "ADMIN|%s|%s|%s:%s",
                           auth_name, auth_pass, argv[1], argv[2]);
    secure_wipe(auth_pass, sizeof(auth_pass));
    secure_wipe(auth_name, sizeof(auth_name));

    /* Derive session key from STATIC admin X25519 priv + hub X25519 pub.
     * This binds the wire to possession of the admin priv key — only the
     * admin (and the hub) can reconstruct the same key. */
    unsigned char shared[32], session_key[32];
    if (!hub_crypto_x25519_derive(admin_x_priv, hub_x25519_pub, shared)) {
        fprintf(stderr, "X25519 derive failed\n");
        secure_wipe(admin_x_priv, 32);
        close(fd);
        return 1;
    }
    secure_wipe(admin_x_priv, 32);

    static const unsigned char ADMIN_INFO[] = "irchub-admin-session-v1";
    if (!hub_crypto_hkdf_sha256(shared, 32, admin_x_pub, 32,
                                ADMIN_INFO, sizeof(ADMIN_INFO) - 1,
                                session_key, 32)) {
        fprintf(stderr, "HKDF failed\n");
        secure_wipe(shared, 32);
        close(fd);
        return 1;
    }
    secure_wipe(shared, 32);
    memcpy(g_key, session_key, 32);
    secure_wipe(session_key, 32);

    /* Wire layout for hub_handle_client_data's sealed-box decode is:
     *   eph_pub(32) || iv(GCM_IV_LEN) || ct || tag
     * where the hub uses its own X25519 priv with eph_pub to recover the
     * shared secret.  We slot the admin's STATIC X25519 pub into that
     * field — semantics on the hub side are identical (X25519(hub_priv,
     * admin_pub) == X25519(admin_priv, hub_pub)). */
    unsigned char enc[512];
    unsigned char tag[GCM_TAG_LEN];
    memcpy(enc, admin_x_pub, 32);
    int ct_len = aes_gcm_encrypt(plain, msg_len + 1, g_key, enc + 32, tag);
    secure_wipe(plain, sizeof(plain));
    if (ct_len <= 0) {
        fprintf(stderr, "AES-GCM encryption failed\n");
        close(fd);
        return 1;
    }
    memcpy(enc + 32 + ct_len, tag, GCM_TAG_LEN);
    int enc_len = 32 + ct_len + GCM_TAG_LEN;

    uint32_t net_len = htonl(enc_len);
    if (write(fd, &net_len, 4) != (ssize_t)4 || write(fd, enc, enc_len) != (ssize_t)enc_len) {
        perror("Send failed");
        close(fd);
        return 1;
    }

    printf("[+] Authenticated to hub (per-admin Curve25519).\n");

    // MAIN MENU LOOP
    while (1) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║              IRC HUB ADMIN CONSOLE               ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("  1. Manage Bots\n");
        printf("  2. Manage Peer Connections\n");
        printf("  3. Manage Local Peer Config\n");
        printf("  4. Manage Global Peer Config\n");
        printf("  5. IRC Admin Commands\n");
        printf("  6. Exit\n");
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
                menu_manage_peer_connections();
                break;

            case 3:
                menu_manage_peer_config();
                break;

            case 4:
                menu_manage_global_peer_config();
                break;

            case 5:
                menu_admin_commands();
                break;

            case 6:
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
