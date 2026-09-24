#include "hub.h"
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
    printf("                 SET PEER PUBKEY\n");
    printf("═══════════════════════════════════════════════════\n");
    printf("Registers the peer's 88-char Curve25519 pubkey on an\n");
    printf("existing peer entry. The next connection from that peer\n");
    printf("authenticates with it (HUBv3 Ed25519 signature).\n\n");
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

/* Prompt for a user's public key: the pasted 88-char key, or a path to
 * their .public.b64.  Shows the fingerprint and asks to confirm.  Returns
 * false if the operator gives up (empty input). */
static bool prompt_user_pubkey(const char *who, char out[COMBINED_KEY_B64 + 1]) {
    for (;;) {
        char in[1024];
        unsigned char raw[COMBINED_KEY_LEN];
        out[0] = '\0';
        get_input("Public key (paste the 88 chars, or a path to the .public.b64; "
                  "blank to cancel): ", in, sizeof(in));
        if (!in[0]) return false;
        /* A private and a public key file have the same shape (88-char
         * base64 of 64 bytes), so the content cannot tell them apart; refuse
         * a keygen private file by name before it gets published. */
        if (strstr(in, ".private.")) {
            printf("  That is a PRIVATE key file — never hand it out. Use the "
                   "matching .public.b64.\n");
            continue;
        }
        if (hub_crypto_pubkey_b64_decode(in, raw)) {
            memcpy(out, in, COMBINED_KEY_B64);          /* validated: 88 chars */
        } else {
            FILE *f = fopen(in, "r");
            char line[256] = {0};
            if (f) {
                if (!fgets(line, sizeof(line), f)) line[0] = '\0';
                fclose(f);
                line[strcspn(line, " \t\r\n")] = '\0';
            }
            if (!line[0] || !hub_crypto_pubkey_b64_decode(line, raw)) {
                printf("  Not an 88-char public key%s. Use the .public.b64 — "
                       "never the .private.b64.\n", f ? " in that file" : "");
                continue;
            }
            memcpy(out, line, COMBINED_KEY_B64);
        }
        out[COMBINED_KEY_B64] = '\0';
        char fp[KEY_FP_LEN + 1];
        hub_crypto_key_fingerprint(raw, fp);
        printf("  Key fingerprint for %s: %s  (keygen printed it with the "
               "PUBLIC key)\n", who, fp);
        if (get_confirmation("  Use this key?")) return true;
    }
}

static void keygen_hint(void) {
    printf("The user makes their own keypair on their own machine:\n");
    printf("    ./keygen <name>     (irchub/bin/keygen or ircbot/utils/keygen)\n");
    printf("They keep <ts>_<name>.private.b64 (chmod 600) and give you only\n");
    printf("<ts>_<name>.public.b64. The hub never sees a private key.\n\n");
}

static void admin_add_user_record(bool admin) {
    char response[MAX_BUFFER];
    char name[64], pub[COMBINED_KEY_B64 + 1], mask[256];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("                   ADD %s\n", admin ? "ADMIN" : "OPER");
    printf("═══════════════════════════════════════════════════\n\n");
    keygen_hint();
    get_input("Name (no spaces, e.g. robert): ", name, sizeof(name));
    if (!name[0] || strchr(name, ' ') || strchr(name, '|')) {
        printf("Invalid name.\n");
        pause_and_continue();
        return;
    }
    if (!prompt_user_pubkey(name, pub)) {
        printf("Cancelled.\n");
        pause_and_continue();
        return;
    }
    get_input("First usermask (e.g. nick!*@*.example.com): ", mask, sizeof(mask));
    if (!strchr(mask, '!') || !strchr(mask, '@')) {
        printf("Mask must contain '!' and '@'.\n");
        pause_and_continue();
        return;
    }

    char payload[512];
    snprintf(payload, sizeof(payload), "%s|%s|%s", name, pub, mask);
    send_packet(g_fd, admin ? CMD_ADMIN_ADD_ADMIN : CMD_ADMIN_ADD_OPER_RECORD,
                payload, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    /* Response: SUCCESS|<a|o>|<name>|<mask>|<key fingerprint> */
    if (strncmp(response, "SUCCESS|", 8) == 0) {
        char *toks[5] = {0}; int n = 0;
        char *sp = NULL;
        char *t = strtok_r(response, "|", &sp);
        while (t && n < 5) { toks[n++] = t; t = strtok_r(NULL, "|", &sp); }
        printf("\n[+] %s '%s' created with mask %s (key %s).\n",
               admin ? "Admin" : "Oper", name, n > 3 ? toks[3] : mask,
               n > 4 ? toks[4] : "?");
        if (admin)
            printf("    They log in with: ./hub_admin <ip> <port> <their .private.b64>\n");
        printf("    IRC: their client script (ircbot/utils) uses the same "
               ".private.b64.\n");
    } else {
        printf("\nHub: %s\n", response);
    }
    pause_and_continue();
}

void admin_add_admin_record(void) { admin_add_user_record(true); }

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

void admin_add_oper_record(void) { admin_add_user_record(false); }

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

void admin_change_userkey(void) {
    char response[MAX_BUFFER];
    char name[64], pub[COMBINED_KEY_B64 + 1];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("              CHANGE USER PUBLIC KEY\n");
    printf("═══════════════════════════════════════════════════\n\n");
    printf("Replaces the key of an admin or oper (rotation, a lost key, or a\n");
    printf("legacy user with no key). UUID and usermasks are kept; the old key\n");
    printf("stops working on the hub and on every bot as soon as it syncs.\n\n");
    keygen_hint();
    get_input("User name: ", name, sizeof(name));
    if (name[0] && prompt_user_pubkey(name, pub)) {
        char payload[256];
        snprintf(payload, sizeof(payload), "%s|%s", name, pub);
        send_packet(g_fd, CMD_ADMIN_SET_USERKEY, payload, g_key);
        read_response(g_fd, g_key, response, sizeof(response));
        printf("\nHub: %s\n", response);
    } else {
        printf("Cancelled.\n");
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
    printf("Format examples (IPv4):\n");
    printf("  192.168.1.5       - Single IP\n");
    printf("  192.168.1.0/24    - Subnet (CIDR notation)\n");
    printf("  10.0.0.0/8        - Large network\n\n");
    printf("The first entry turns the allowlist on: only listed addresses\n");
    printf("(bots, peer hubs, hub_admin) can connect after that.\n\n");

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
    printf("Format examples (IPv4):\n");
    printf("  192.168.1.5       - Single IP\n");
    printf("  192.168.1.0/24    - Subnet (CIDR notation)\n");
    printf("  10.0.0.0/8        - Large network\n\n");
    printf("A denied address is refused even if the allowlist has it.\n\n");

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
        printf("  6. Change User Public Key\n");
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
            case 6: admin_change_userkey();    break;
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
        printf("  6. Change Oper Public Key\n");
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
            case 6: admin_change_userkey();     break;
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

static void admin_show_stats(void) {
    char *response = malloc(MAX_BUFFER);
    if (!response) return;
    send_packet(g_fd, CMD_ADMIN_STATS, NULL, g_key);
    read_response(g_fd, g_key, response, MAX_BUFFER);
    printf("\nTraffic since this hub started (cfg: full config pushes to bots,\n"
           "same = skipped as identical; sync: peer sync frames/records in;\n"
           "op: frames/bytes by opcode):\n%s\n", response);
    free(response);
    pause_and_continue();
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
    printf("     chkey; users, masks, keys and channels change only here)\n\n");
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

/* ---- Network upgrade (hub-orchestrated rolling upgrade) ---- */

/* Start a run.  Everything past the version is optional: an empty variant
 * keeps each node on the one it is already running, an empty kind lets each
 * node pick a prebuilt binary or a source build, and an empty base uses the
 * release URL compiled into the daemons.  Bots and hubs are separate
 * products on separate version lines, so the hubs get their own target and
 * base; a blank hub target leaves every hub on the build it runs.  The hub
 * freezes the config for the
 * duration and drives the rolling plan itself, so this is fire-and-poll: the
 * status screen is where the run is watched. */
void admin_upgrade_network(void) {
    char response[MAX_BUFFER];
    char version[64], variant[16], kind[16], min_from[64], base[512];
    char hub_version[64], hub_base[512];

    printf("\n═══════════════════════════════════════════════════\n");
    printf("                 UPGRADE NETWORK\n");
    printf("═══════════════════════════════════════════════════\n\n");
    printf("  Bots are upgraded in waves, peer hubs afterwards one at a\n");
    printf("  time, this hub last.  The config is frozen until the run\n");
    printf("  finishes, and any failure rolls the whole mesh back.\n\n");

    get_input("Bot target version (e.g. 2.4.0, blank to cancel): ", version,
              sizeof(version));
    if (strlen(version) == 0) {
        printf("[*] Cancelled.\n");
        pause_and_continue();
        return;
    }
    get_input("Variant c/rs (blank = keep each node's own): ", variant,
              sizeof(variant));
    get_input("Artifact bin/src (blank = let each node choose): ", kind,
              sizeof(kind));
    get_input("Minimum version to upgrade from (blank = any): ", min_from,
              sizeof(min_from));
    get_input("Bot release base URL override (blank = built-in): ", base,
              sizeof(base));
    get_input("Hub target version (blank = hubs stay on their build): ",
              hub_version, sizeof(hub_version));
    hub_base[0] = '\0';
    if (strlen(hub_version) > 0)
        get_input("Hub release base URL override (blank = built-in): ",
                  hub_base, sizeof(hub_base));

    char payload[1400];
    snprintf(payload, sizeof(payload), "%s|%s|%s|%s|%s|%s|%s", version, variant,
             kind, min_from, base, hub_version, hub_base);

    printf("\n[*] Asking the hub to upgrade the network to %s...\n", version);
    send_packet(g_fd, CMD_ADMIN_UPGRADE_NET, payload, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("\nHub: %s\n", response);
    printf("\n[*] Watch it with \"Upgrade status\"; the run continues whether\n");
    printf("    or not this console stays connected.\n");
    pause_and_continue();
}

void admin_upgrade_status(void) {
    char response[MAX_BUFFER];
    printf("\n");
    send_packet(g_fd, CMD_ADMIN_UPGRADE_STATUS, NULL, g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("%s\n", response);
    pause_and_continue();
}

/* Stop a run in flight: every node that already moved is told to restore its
 * retained build, and the config freeze lifts. */
void admin_upgrade_abort(void) {
    char response[MAX_BUFFER], confirm[16];
    printf("\n═══════════════════════════════════════════════════\n");
    printf("                  ABORT UPGRADE\n");
    printf("═══════════════════════════════════════════════════\n\n");
    printf("  Every node that already upgraded rolls back to its previous\n");
    printf("  build.  Type 'yes' to confirm.\n\n");
    get_input("Confirm: ", confirm, sizeof(confirm));
    if (strcmp(confirm, "yes") != 0) {
        printf("[*] Cancelled.\n");
        pause_and_continue();
        return;
    }
    send_packet(g_fd, CMD_ADMIN_UPGRADE_STATUS, "abort", g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("\nHub: %s\n", response);
    pause_and_continue();
}

/* Drop the roll-up plan the last finished run left behind, on every hub:
 * until then, any bot that comes back on an older build is walked up to the
 * plan's target by its hub. */
void admin_upgrade_forget(void) {
    char response[MAX_BUFFER], confirm[16];
    printf("\n═══════════════════════════════════════════════════\n");
    printf("               FORGET ROLL-UP PLAN\n");
    printf("═══════════════════════════════════════════════════\n\n");
    printf("  Every hub stops walking returning bots up to the last\n");
    printf("  run's target.  Nothing already upgraded is touched.\n");
    printf("  Type 'yes' to confirm.\n\n");
    get_input("Confirm: ", confirm, sizeof(confirm));
    if (strcmp(confirm, "yes") != 0) {
        printf("[*] Cancelled.\n");
        pause_and_continue();
        return;
    }
    send_packet(g_fd, CMD_ADMIN_UPGRADE_STATUS, "forget", g_key);
    read_response(g_fd, g_key, response, sizeof(response));
    printf("\nHub: %s\n", response);
    pause_and_continue();
}

void menu_upgrade_network(void) {
    while (1) {
        printf("\n");
        printf("╔══════════════════════════════════════════════════╗\n");
        printf("║                UPGRADE NETWORK                   ║\n");
        printf("╚══════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("  1. Upgrade network to a version\n");
        printf("  2. Upgrade status\n");
        printf("  3. Abort the running upgrade\n");
        printf("  4. Forget the roll-up plan\n");
        printf("  5. Back to Main Menu\n");
        printf("\n");
        printf("Select: ");
        fflush(stdout);

        char buf[10];
        if (!wait_for_input_or_socket(buf, sizeof(buf))) {
            printf("\n[!] Connection lost.\n");
            exit(1);
        }

        switch (atoi(buf)) {
            case 1: admin_upgrade_network(); break;
            case 2: admin_upgrade_status();  break;
            case 3: admin_upgrade_abort();   break;
            case 4: admin_upgrade_forget();  break;
            case 5: return;
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
        printf("  4. Set Peer Pubkey\n");
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
        printf(" 12. Show Traffic Stats\n");
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
                admin_show_stats();
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

static void usage(void) {
    printf("Usage: ./hub_admin <ip> <port> <private-key-file>\n");
    printf("\n");
    printf("<private-key-file> is your <YYYYMMDDHHMMSS>_<name>.private.b64 from\n");
    printf("keygen (or the admin_<name>.b64 an older hub printed when it created\n");
    printf("you). There is no username or password: the hub finds your admin\n");
    printf("record by the key and you prove you hold it by signing a one-time\n");
    printf("challenge. Keep the file chmod 600.\n");
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        usage();
        return 1;
    }

    /* Load the admin's combined Curve25519 PRIVATE key (88 chars base64). */
    struct stat kst;
    if (stat(argv[3], &kst) == 0 && (kst.st_mode & 0077) != 0)
        fprintf(stderr, "[!] Warning: %s is readable by others (mode %04o) — "
                        "chmod 600 it.\n", argv[3], (unsigned)(kst.st_mode & 0777));
    FILE *f = fopen(argv[3], "r");
    if (!f) {
        perror("Failed to open private key file");
        return 1;
    }
    char ab64[128] = {0};
    if (!fgets(ab64, sizeof(ab64), f)) {
        fprintf(stderr, "Failed to read private key file\n");
        fclose(f);
        return 1;
    }
    fclose(f);
    ab64[strcspn(ab64, " \t\r\n")] = 0;

    int adec_len = 0;
    unsigned char *admin_priv_combined = base64_decode(ab64, &adec_len);
    secure_wipe(ab64, sizeof(ab64));
    if (!admin_priv_combined || adec_len != COMBINED_KEY_LEN) {
        fprintf(stderr, "Invalid private key file: expected the 88-char base64 "
                        "of a 64-byte Curve25519 combined key (a .private.b64).\n");
        if (admin_priv_combined) { secure_wipe(admin_priv_combined, adec_len); free(admin_priv_combined); }
        return 1;
    }
    /* Layout: ed_priv(32) || x_priv(32).  The Ed25519 half signs the login
     * challenge; the public key identifies the admin record. */
    unsigned char admin_priv[COMBINED_KEY_LEN], admin_pub[COMBINED_KEY_LEN];
    memcpy(admin_priv, admin_priv_combined, COMBINED_KEY_LEN);
    secure_wipe(admin_priv_combined, COMBINED_KEY_LEN);
    free(admin_priv_combined);
    if (!hub_crypto_combined_pub_from_priv(admin_priv, admin_pub)) {
        fprintf(stderr, "Failed to derive the public key from the private key.\n");
        secure_wipe(admin_priv, sizeof(admin_priv));
        return 1;
    }
    {
        char fp[KEY_FP_LEN + 1];
        hub_crypto_key_fingerprint(admin_pub, fp);
        printf("[*] Using key %s\n", fp);
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(atoi(argv[2]))
    };
    if (fd < 0 || inet_pton(AF_INET, argv[1], &addr.sin_addr) != 1) {
        fprintf(stderr, "Bad hub address '%s' (IPv4 literal expected).\n", argv[1]);
        secure_wipe(admin_priv, sizeof(admin_priv));
        return 1;
    }

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("Connect failed");
        secure_wipe(admin_priv, sizeof(admin_priv));
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    g_fd = fd;

    /* Step 1: ADMIN-HELLO.  The hub answers with its X25519 pubkey, its UUID
     * and a one-time 32-byte login challenge:
     *   HUB-PUBKEY2|<x_pub_b64>|<hub_uuid>|<nonce_b64> */
    {
        const char *hello = "ADMIN-HELLO";
        uint32_t nl = htonl(11);
        if (write(fd, &nl, 4) != 4 || write(fd, hello, 11) != 11) {
            perror("HELLO write failed");
            secure_wipe(admin_priv, sizeof(admin_priv));
            close(fd);
            return 1;
        }
    }

    unsigned char hub_x25519_pub[32] = {0}, nonce[32] = {0};
    char hub_uuid[64] = {0};
    {
        uint32_t rnl;
        char reply[256] = {0};
        int rl = -1;
        if (recv_all(fd, &rnl, 4) == 4) {
            rl = (int)ntohl(rnl);
            if (rl < 14 || rl > 200 || recv_all(fd, reply, rl) != rl) rl = -1;
        }
        if (rl < 0) {
            fprintf(stderr, "No usable HELLO reply from hub.\n");
            secure_wipe(admin_priv, sizeof(admin_priv));
            close(fd);
            return 1;
        }
        reply[rl] = 0;
        if (strncmp(reply, "HUB-PUBKEY|", 11) == 0) {
            fprintf(stderr, "This hub predates passwordless login (HUB-PUBKEY v1); "
                            "upgrade it.\n");
            secure_wipe(admin_priv, sizeof(admin_priv));
            close(fd);
            return 1;
        }
        char *f_pub = NULL, *f_uuid = NULL, *f_nonce = NULL, *sp = NULL;
        if (strncmp(reply, "HUB-PUBKEY2|", 12) == 0) {
            f_pub = strtok_r(reply + 12, "|", &sp);
            f_uuid = strtok_r(NULL, "|", &sp);
            f_nonce = strtok_r(NULL, "|", &sp);
        }
        int xl = 0, nlen = 0;
        unsigned char *xb = f_pub ? base64_decode(f_pub, &xl) : NULL;
        unsigned char *nb = f_nonce ? base64_decode(f_nonce, &nlen) : NULL;
        bool ok = xb && xl == 32 && nb && nlen == 32 && f_uuid &&
                  strlen(f_uuid) < sizeof(hub_uuid);
        if (ok) {
            memcpy(hub_x25519_pub, xb, 32);
            memcpy(nonce, nb, 32);
            snprintf(hub_uuid, sizeof(hub_uuid), "%s", f_uuid);
        }
        free(xb);
        if (nb) { secure_wipe(nb, (size_t)nlen); free(nb); }
        if (!ok) {
            fprintf(stderr, "Unexpected HELLO reply from hub.\n");
            secure_wipe(admin_priv, sizeof(admin_priv));
            close(fd);
            return 1;
        }
        printf("[*] Hub %s answered; signing its login challenge.\n", hub_uuid);
    }

    /* Step 2: fresh ephemeral X25519 key -> session key (forward secrecy);
     * Ed25519 signature over the transcript proves we hold the admin key and
     * binds it to this hub, this challenge and this session. */
    unsigned char eph_priv[32], eph_pub[32];
    {
        EVP_PKEY_CTX *kc = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
        EVP_PKEY *ek = NULL;
        size_t l1 = 32, l2 = 32;
        bool ok = kc && EVP_PKEY_keygen_init(kc) == 1 && EVP_PKEY_keygen(kc, &ek) == 1 &&
                  EVP_PKEY_get_raw_private_key(ek, eph_priv, &l1) == 1 && l1 == 32 &&
                  EVP_PKEY_get_raw_public_key(ek, eph_pub, &l2) == 1 && l2 == 32;
        if (ek) EVP_PKEY_free(ek);
        if (kc) EVP_PKEY_CTX_free(kc);
        if (!ok) {
            fprintf(stderr, "Ephemeral key generation failed.\n");
            secure_wipe(admin_priv, sizeof(admin_priv));
            close(fd);
            return 1;
        }
    }

    unsigned char transcript[64 + 64 + 32 + 32 + 32 + COMBINED_KEY_LEN];
    size_t tl = 0;
    {
        static const char AUTH_CTX[] = "irchub-admin-auth-v2";
        size_t ul = strlen(hub_uuid);
        memcpy(transcript + tl, AUTH_CTX, sizeof(AUTH_CTX)); tl += sizeof(AUTH_CTX);
        memcpy(transcript + tl, hub_uuid, ul);               tl += ul;
        transcript[tl++] = '\0';
        memcpy(transcript + tl, hub_x25519_pub, 32);         tl += 32;
        memcpy(transcript + tl, nonce, 32);                  tl += 32;
        memcpy(transcript + tl, eph_pub, 32);                tl += 32;
        memcpy(transcript + tl, admin_pub, COMBINED_KEY_LEN); tl += COMBINED_KEY_LEN;
    }
    unsigned char sig[ED25519_SIG_LEN];
    bool signed_ok = hub_crypto_ed25519_sign(admin_priv, transcript, tl, sig);
    secure_wipe(admin_priv, sizeof(admin_priv));
    secure_wipe(nonce, sizeof(nonce));
    if (!signed_ok) {
        fprintf(stderr, "Signing the login challenge failed.\n");
        secure_wipe(eph_priv, sizeof(eph_priv));
        close(fd);
        return 1;
    }

    unsigned char shared[32], session_key[32];
    static const unsigned char ADMIN_INFO[] = "irchub-admin-session-v2";
    bool kdf_ok = hub_crypto_x25519_derive(eph_priv, hub_x25519_pub, shared) &&
                  hub_crypto_hkdf_sha256(shared, 32, eph_pub, 32,
                                         ADMIN_INFO, sizeof(ADMIN_INFO) - 1,
                                         session_key, 32);
    secure_wipe(eph_priv, sizeof(eph_priv));
    secure_wipe(shared, sizeof(shared));
    if (!kdf_ok) {
        fprintf(stderr, "Session key derivation failed.\n");
        close(fd);
        return 1;
    }
    memcpy(g_key, session_key, 32);
    secure_wipe(session_key, sizeof(session_key));

    char *pub_b64 = base64_encode(admin_pub, COMBINED_KEY_LEN);
    char *sig_b64 = base64_encode(sig, ED25519_SIG_LEN);
    char plain[512];
    int msg_len = (pub_b64 && sig_b64)
        ? snprintf(plain, sizeof(plain), "ADMIN2|%s|%s|%s:%s", pub_b64, sig_b64,
                   argv[1], argv[2])
        : -1;
    free(pub_b64);
    free(sig_b64);
    if (msg_len <= 0 || msg_len >= (int)sizeof(plain)) {
        fprintf(stderr, "Could not build the login message.\n");
        close(fd);
        return 1;
    }

    /* Sealed-box wire layout (hub_seal_open): eph_pub(32) || iv || ct || tag */
    unsigned char enc[32 + GCM_IV_LEN + sizeof(plain) + GCM_TAG_LEN];
    unsigned char tag[GCM_TAG_LEN];
    memcpy(enc, eph_pub, 32);
    int ct_len = aes_gcm_encrypt((unsigned char *)plain, msg_len + 1, g_key,
                                 enc + 32, tag);
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

    /* Step 3: the hub confirms (encrypted) or hangs up. */
    {
        char response[256];
        read_response(fd, g_key, response, sizeof(response));
        if (strncmp(response, "AUTH-OK|", 8) != 0) {
            fprintf(stderr, "[!] Login refused by the hub (%s).\n"
                            "    The key must be on an active admin record; "
                            "see the hub log for the reason.\n", response);
            secure_wipe(g_key, sizeof(g_key));
            close(fd);
            return 1;
        }
        printf("[+] Authenticated to hub as '%s'.\n", response + 8);
    }

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
        printf("  6. Upgrade Network\n");
        printf("  7. Exit\n");
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
                menu_upgrade_network();
                break;

            case 7:
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
