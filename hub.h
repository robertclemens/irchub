#ifndef HUB_H
#define HUB_H

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
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
#define MAX_KEY 31
#define MAX_MASK_LEN 128
#define MAX_PASS 128
#define MAX_BUFFER 16384
#define SALT_SIZE 16 // FIXED: Increased from 8 to 16 bytes (128 bits)
#define GCM_IV_LEN 12
#define GCM_TAG_LEN 16
#define HEADER_SIZE 4
#define MAX_PENDING_BOTS 10
#define PBKDF2_ITERATIONS 100000 // NEW: For password-based key derivation

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

#define MESH_ANTI_ENTROPY_INTERVAL 300
#define MAX_BOT_ENTRIES 64

typedef struct {
  char key[32];
  char value[1024];
  time_t timestamp;
} config_entry_t;

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
  char ip[64];
  int port;
  bool connected;
  int fd;
  int remote_connected_count;
  int remote_total_peers;
  time_t last_mesh_report;
  char last_gossip[1024];
} hub_peer_config_t;

typedef enum { CLIENT_BOT, CLIENT_ADMIN, CLIENT_HUB } client_type_t;

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
  int recv_len;
} hub_client_t;

typedef struct {
  int listen_fd;
  int port;
  char admin_password[128];
  char config_pass[128];

  char *private_key_pem;
  char *public_key_pem;
  EVP_PKEY *priv_key; // FIXED: Changed from RSA* to EVP_PKEY*

  hub_client_t *clients[MAX_CLIENTS];
  int client_count;

  bot_config_t bots[MAX_BOTS];
  int bot_count;

  // GLOBAL CONFIG STORE (Shared by all bots)
  config_entry_t global_entries[MAX_BOT_ENTRIES];
  int global_entry_count;

  hub_peer_config_t peers[MAX_PEERS];
  int peer_count;

  pending_bot_t pending[MAX_PENDING_BOTS];
  int pending_head;
  int pending_count;

  volatile bool running;
} hub_state_t;

// --- Prototypes ---
void hub_log(const char *format, ...);
bool hub_config_load(hub_state_t *state, const char *password);
void hub_config_write(hub_state_t *state);

// FIXED: Updated crypto function signatures
EVP_PKEY *load_private_key_from_memory(const char *pem_data);
bool hub_crypto_generate_keypair(char **priv_pem_out, char **pub_pem_out);
int evp_private_decrypt(EVP_PKEY *pkey, const unsigned char *enc, int enc_len,
                        unsigned char *dec);
int evp_public_encrypt(EVP_PKEY *pkey, const unsigned char *plain,
                       int plain_len, unsigned char *enc);

// FIXED: Simplified - removed AAD parameters (not needed since we encrypt
// everything)
int aes_gcm_decrypt(const unsigned char *input, int input_len,
                    const unsigned char *key, unsigned char *output,
                    unsigned char *tag);
int aes_gcm_encrypt(const unsigned char *plain, int plain_len,
                    const unsigned char *key, unsigned char *output,
                    unsigned char *tag);

void hub_storage_init(void);
bool hub_storage_update_entry(hub_state_t *state, const char *uuid,
                              const char *key, const char *value,
                              const char *extra, const char *op, time_t ts);
bool hub_storage_delete(hub_state_t *state, const char *uuid);
int hub_storage_get_full_list(hub_state_t *state, char *buffer, int max_len);
int hub_storage_get_summary_list(hub_state_t *state, char *buffer, int max_len);

void hub_generate_sync_packet(hub_state_t *state, char *buffer, int max_len);
void hub_generate_bot_payload(hub_state_t *state, const char *uuid,
                              char *buffer, int max_len);
void hub_broadcast_sync_to_peers(hub_state_t *state, const char *payload,
                                 int exclude_fd);

bool hub_handle_client_data(hub_state_t *state, hub_client_t *client);
void hub_disconnect_client(hub_state_t *state, hub_client_t *c);
void hub_broadcast_mesh_state(hub_state_t *state);

// NEW: Crypto utility functions
bool hub_crypto_generate_bot_creds(char **out_uuid, char **out_priv_b64,
                                   char **out_pub_b64);
void secure_wipe(void *ptr, size_t len);

char *base64_encode(const unsigned char *input, int length);
unsigned char *base64_decode(const char *input, int *out_len);

#endif
