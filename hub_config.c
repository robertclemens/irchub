#include "hub.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

// Helper to extract PubKey from EVP_PKEY
static char* extract_pubkey(EVP_PKEY *pkey) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return NULL;
    
    if (!PEM_write_bio_PUBKEY(bio, pkey)) {
        BIO_free(bio);
        return NULL;
    }
    
    int len = BIO_pending(bio);
    char *pem = malloc(len + 1);
    if (pem) {
        BIO_read(bio, pem, len);
        pem[len] = 0;
    }
    BIO_free(bio);
    return pem;
}

// FIXED: Replaced EVP_BytesToKey with PKCS5_PBKDF2_HMAC
void hub_config_write(hub_state_t *state) {
    int estimated_size = 8192 + (state->bot_count * MAX_BOT_ENTRIES * 1100);
    char *buffer = malloc(estimated_size);
    if (!buffer) return;

    int offset = 0, written = 0;

    #define SAFE_WRITE(...) do { \
        if (offset < estimated_size) { \
            written = snprintf(buffer + offset, estimated_size - offset, __VA_ARGS__); \
            if (written < 0 || written >= (estimated_size - offset)) { \
                fprintf(stderr, "Buffer overflow in config write\n"); \
                offset = estimated_size; \
            } else { \
                offset += written; \
            } \
        } \
    } while(0)

    SAFE_WRITE("port|%d\n", state->port);
    SAFE_WRITE("admin|%s\n", state->admin_password);

    for(int i=0; i<state->peer_count; i++) {
        SAFE_WRITE("peer|%s|%d\n", state->peers[i].ip, state->peers[i].port);
    }

    if (state->private_key_pem) {
        char *b64 = base64_encode((unsigned char*)state->private_key_pem, 
                                  strlen(state->private_key_pem));
        if (b64) { 
            SAFE_WRITE("key|%s\n", b64); 
            secure_wipe(b64, strlen(b64));  // ADDED: Wipe sensitive data
            free(b64); 
        }
    }

    if (state->priv_key) {
        char *pub_pem = state->public_key_pem;
        bool free_pub = false;
        if (!pub_pem) {
            pub_pem = extract_pubkey(state->priv_key);
            free_pub = true;
        }
        if (pub_pem) {
            char *b64 = base64_encode((unsigned char*)pub_pem, strlen(pub_pem));
            if (b64) {
                SAFE_WRITE("pub|%s\n", b64);
                free(b64);
            }
            if (free_pub) free(pub_pem);
        }
    }

    for (int i = 0; i < state->bot_count; i++) {
        bot_config_t *b = &state->bots[i];
        if (b->uuid[0] == 0) continue;
        
        SAFE_WRITE("b|%s|t|%ld\n", b->uuid, (long)b->last_sync_time);
        
        for (int j = 0; j < b->entry_count; j++) {
            SAFE_WRITE("b|%s|%s|%s|%ld\n", 
                      b->uuid, b->entries[j].key, 
                      b->entries[j].value, (long)b->entries[j].timestamp);
        }
        
        if (offset >= estimated_size) break;
    }

    // FIXED: Use PBKDF2 instead of EVP_BytesToKey
    unsigned char salt[SALT_SIZE], key[32], iv[GCM_IV_LEN], tag[GCM_TAG_LEN];
    RAND_bytes(salt, sizeof(salt));
    RAND_bytes(iv, sizeof(iv));

    // FIXED: Proper PBKDF2 with 100,000 iterations
    if (PKCS5_PBKDF2_HMAC(state->config_pass, strlen(state->config_pass),
                          salt, SALT_SIZE, PBKDF2_ITERATIONS,
                          EVP_sha256(), 32, key) != 1) {
        fprintf(stderr, "PBKDF2 failed\n");
        secure_wipe(buffer, offset);
        free(buffer);
        return;
    }

    unsigned char *ciphertext = malloc(offset + 16);
    if (!ciphertext) {
        secure_wipe(buffer, offset);
        free(buffer);
        return;
    }

    int len, cipher_len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(ciphertext);
        secure_wipe(buffer, offset);
        free(buffer);
        return;
    }

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &cipher_len, (unsigned char*)buffer, offset);
    EVP_EncryptFinal_ex(ctx, ciphertext + cipher_len, &len);
    cipher_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag);
    EVP_CIPHER_CTX_free(ctx);

    // Write to temp file then rename (atomic operation)
    char tmp[64];
    snprintf(tmp, sizeof(tmp), "%s.tmp", HUB_CONFIG_FILE);
    FILE *fp = fopen(tmp, "wb");
    if (fp) {
        fwrite(salt, 1, SALT_SIZE, fp);
        fwrite(iv, 1, GCM_IV_LEN, fp);
        fwrite(tag, 1, GCM_TAG_LEN, fp);
        fwrite(ciphertext, 1, cipher_len, fp);
        fflush(fp);
        fsync(fileno(fp));
        fclose(fp);
        rename(tmp, HUB_CONFIG_FILE);
    }

    // ADDED: Secure cleanup
    secure_wipe(key, sizeof(key));
    secure_wipe(ciphertext, cipher_len);
    free(ciphertext);
    secure_wipe(buffer, offset);
    free(buffer);
    
    #undef SAFE_WRITE
}

// FIXED: Use PBKDF2 and improved error handling
bool hub_config_load(hub_state_t *state, const char *password) {
    FILE *fp = fopen(HUB_CONFIG_FILE, "rb");
    if (!fp) {
        fprintf(stderr, "Config file not found\n");
        return false;
    }

    unsigned char salt[SALT_SIZE], iv[GCM_IV_LEN], tag[GCM_TAG_LEN];
    
    if (fread(salt, 1, SALT_SIZE, fp) != SALT_SIZE) {
        fprintf(stderr, "Failed to read salt\n");
        fclose(fp);
        return false;
    }
    if (fread(iv, 1, GCM_IV_LEN, fp) != GCM_IV_LEN) {
        fprintf(stderr, "Failed to read IV\n");
        fclose(fp);
        return false;
    }
    if (fread(tag, 1, GCM_TAG_LEN, fp) != GCM_TAG_LEN) {
        fprintf(stderr, "Failed to read tag\n");
        fclose(fp);
        return false;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    long cipher_len = fsize - SALT_SIZE - GCM_IV_LEN - GCM_TAG_LEN;
    
    if (cipher_len <= 0) {
        fprintf(stderr, "Invalid config file size\n");
        fclose(fp);
        return false;
    }

    fseek(fp, SALT_SIZE + GCM_IV_LEN + GCM_TAG_LEN, SEEK_SET);
    unsigned char *ciphertext = malloc(cipher_len);
    if (!ciphertext) {
        fclose(fp);
        return false;
    }
    
    if (fread(ciphertext, 1, cipher_len, fp) != (size_t)cipher_len) {
        fprintf(stderr, "Failed to read ciphertext\n");
        free(ciphertext);
        fclose(fp);
        return false;
    }
    fclose(fp);

    // FIXED: Use PBKDF2 instead of EVP_BytesToKey
    unsigned char key[32];
    if (PKCS5_PBKDF2_HMAC(password, strlen(password),
                          salt, SALT_SIZE, PBKDF2_ITERATIONS,
                          EVP_sha256(), 32, key) != 1) {
        fprintf(stderr, "PBKDF2 failed\n");
        free(ciphertext);
        return false;
    }

    unsigned char *plaintext = malloc(cipher_len + 1);
    if (!plaintext) {
        secure_wipe(key, sizeof(key));
        free(ciphertext);
        return false;
    }

    int len, plain_len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        secure_wipe(key, sizeof(key));
        free(ciphertext);
        free(plaintext);
        return false;
    }

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &plain_len, ciphertext, cipher_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag);

    if (EVP_DecryptFinal_ex(ctx, plaintext + plain_len, &len) <= 0) {
        fprintf(stderr, "Config decryption failed (wrong password or corrupted file)\n");
        EVP_CIPHER_CTX_free(ctx);
        secure_wipe(key, sizeof(key));
        free(ciphertext);
        free(plaintext);
        return false;
    }
    
    plain_len += len;
    plaintext[plain_len] = 0;
    EVP_CIPHER_CTX_free(ctx);

    // Cleanup sensitive data
    secure_wipe(key, sizeof(key));
    free(ciphertext);

    // Parse configuration
    state->bot_count = 0;
    state->peer_count = 0;
    if (state->public_key_pem) {
        free(state->public_key_pem);
        state->public_key_pem = NULL;
    }

    char *saveptr;
    char *line = strtok_r((char*)plaintext, "\n", &saveptr);
    
    while (line) {
        char *sep = strchr(line, '|');
        if (!sep) sep = strchr(line, ':');

        if (sep) {
            *sep = 0;
            char *k = line;
            char *v = sep + 1;
            
            if (strcmp(k, "port") == 0) {
                state->port = atoi(v);
            }
            else if (strcmp(k, "admin") == 0) {
                strncpy(state->admin_password, v, sizeof(state->admin_password) - 1);
                state->admin_password[sizeof(state->admin_password) - 1] = 0;
            }
            else if (strcmp(k, "key") == 0) {
                int out;
                unsigned char *d = base64_decode(v, &out);
                if (d) {
                    state->private_key_pem = malloc(out + 1);
                    if (state->private_key_pem) {
                        memcpy(state->private_key_pem, d, out);
                        state->private_key_pem[out] = 0;
                    }
                    secure_wipe(d, out);  // ADDED: Wipe decoded key
                    free(d);
                }
            }
            else if (strcmp(k, "pub") == 0) {
                int out;
                unsigned char *d = base64_decode(v, &out);
                if (d) {
                    state->public_key_pem = malloc(out + 1);
                    if (state->public_key_pem) {
                        memcpy(state->public_key_pem, d, out);
                        state->public_key_pem[out] = 0;
                    }
                    free(d);
                }
            }
            else if (strcmp(k, "peer") == 0) {
                char *s2 = strchr(v, '|');
                if (!s2) s2 = strchr(v, ':');
                if (s2 && state->peer_count < MAX_PEERS) {
                    *s2 = 0;
                    strncpy(state->peers[state->peer_count].ip, v, 
                           sizeof(state->peers[state->peer_count].ip) - 1);
                    state->peers[state->peer_count].ip[sizeof(state->peers[state->peer_count].ip) - 1] = 0;
                    state->peers[state->peer_count].port = atoi(s2 + 1);
                    state->peers[state->peer_count].fd = -1;
                    state->peer_count++;
                }
            }
            else if (strcmp(k, "b") == 0) {
                char *s2 = strchr(v, '|');
                if (s2) {
                    *s2 = 0;
                    char *uuid = v;
                    char *rest = s2 + 1;
                    char *s3 = strchr(rest, '|');
                    if (s3) {
                        *s3 = 0;
                        char *bk = rest;
                        char *bv = s3 + 1;
                        
                        if (strcmp(bk, "t") == 0) {
                            hub_storage_update_entry(state, uuid, bk, "", atol(bv));
                        } else {
                            char *s4 = strrchr(bv, '|');
                            if (s4) {
                                *s4 = 0;
                                hub_storage_update_entry(state, uuid, bk, bv, atol(s4 + 1));
                            }
                        }
                    }
                }
            }
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }

    secure_wipe(plaintext, plain_len);
    free(plaintext);
    return true;
}
