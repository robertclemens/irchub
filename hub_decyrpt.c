#include "hub.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>

// Secure password input without echo
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

int main(int argc, char *argv[]) {
    const char *config_file = HUB_CONFIG_FILE;
    char password[128];
    
    printf("IRCHub Config Decryption Utility v1.0\n");
    printf("======================================\n\n");
    
    // Allow custom config file path
    if (argc > 1) {
        config_file = argv[1];
    }
    
    printf("Config file: %s\n\n", config_file);
    
    // Open config file
    FILE *fp = fopen(config_file, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open config file '%s'\n", config_file);
        fprintf(stderr, "Make sure the file exists and you have read permissions.\n");
        return 1;
    }

    // Read salt, IV, tag
    unsigned char salt[SALT_SIZE], iv[GCM_IV_LEN], tag[GCM_TAG_LEN];
    
    if (fread(salt, 1, SALT_SIZE, fp) != SALT_SIZE) {
        fprintf(stderr, "Error: Failed to read salt\n");
        fclose(fp);
        return 1;
    }
    
    if (fread(iv, 1, GCM_IV_LEN, fp) != GCM_IV_LEN) {
        fprintf(stderr, "Error: Failed to read IV\n");
        fclose(fp);
        return 1;
    }
    
    if (fread(tag, 1, GCM_TAG_LEN, fp) != GCM_TAG_LEN) {
        fprintf(stderr, "Error: Failed to read tag\n");
        fclose(fp);
        return 1;
    }

    // Calculate ciphertext size
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    long cipher_len = fsize - SALT_SIZE - GCM_IV_LEN - GCM_TAG_LEN;
    
    if (cipher_len <= 0) {
        fprintf(stderr, "Error: Invalid config file size\n");
        fclose(fp);
        return 1;
    }

    fseek(fp, SALT_SIZE + GCM_IV_LEN + GCM_TAG_LEN, SEEK_SET);
    unsigned char *ciphertext = malloc(cipher_len);
    if (!ciphertext) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(fp);
        return 1;
    }
    
    if (fread(ciphertext, 1, cipher_len, fp) != (size_t)cipher_len) {
        fprintf(stderr, "Error: Failed to read ciphertext\n");
        free(ciphertext);
        fclose(fp);
        return 1;
    }
    fclose(fp);

    // Get password
    get_password_secure("Enter decryption password: ", password, sizeof(password));
    
    if (strlen(password) == 0) {
        fprintf(stderr, "Error: Password cannot be empty\n");
        free(ciphertext);
        return 1;
    }

    // Derive key using PBKDF2
    unsigned char key[32];
    printf("Deriving key (this may take a moment)...\n");
    
    if (PKCS5_PBKDF2_HMAC(password, strlen(password),
                          salt, SALT_SIZE, PBKDF2_ITERATIONS,
                          EVP_sha256(), 32, key) != 1) {
        fprintf(stderr, "Error: PBKDF2 key derivation failed\n");
        secure_wipe(password, sizeof(password));
        free(ciphertext);
        return 1;
    }
    
    // Wipe password from memory
    secure_wipe(password, sizeof(password));

    // Decrypt
    unsigned char *plaintext = malloc(cipher_len + 1);
    if (!plaintext) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        secure_wipe(key, sizeof(key));
        free(ciphertext);
        return 1;
    }

    int len, plain_len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create cipher context\n");
        secure_wipe(key, sizeof(key));
        free(ciphertext);
        free(plaintext);
        return 1;
    }

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &plain_len, ciphertext, cipher_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag);

    if (EVP_DecryptFinal_ex(ctx, plaintext + plain_len, &len) <= 0) {
        fprintf(stderr, "\nError: Decryption failed!\n");
        fprintf(stderr, "This could mean:\n");
        fprintf(stderr, "  - Wrong password\n");
        fprintf(stderr, "  - Corrupted config file\n");
        fprintf(stderr, "  - File has been tampered with\n");
        EVP_CIPHER_CTX_free(ctx);
        secure_wipe(key, sizeof(key));
        free(ciphertext);
        secure_wipe(plaintext, plain_len);
        free(plaintext);
        return 1;
    }
    
    plain_len += len;
    plaintext[plain_len] = 0;
    EVP_CIPHER_CTX_free(ctx);

    // Cleanup sensitive data
    secure_wipe(key, sizeof(key));
    free(ciphertext);

    // Display decrypted config
    printf("\n");
    printf("========================================\n");
    printf("DECRYPTED CONFIG\n");
    printf("========================================\n\n");
    
    // Parse and display nicely
    char *saveptr;
    char *line_copy = strdup((char*)plaintext);
    char *line = strtok_r(line_copy, "\n", &saveptr);
    
    while (line) {
        char *sep = strchr(line, '|');
        if (!sep) sep = strchr(line, ':');
        
        if (sep) {
            *sep = 0;
            char *key_str = line;
            char *val_str = sep + 1;
            
            if (strcmp(key_str, "port") == 0) {
                printf("Port: %s\n", val_str);
            }
            else if (strcmp(key_str, "admin") == 0) {
                printf("Admin Password: %s\n", val_str);
            }
            else if (strcmp(key_str, "key") == 0) {
                printf("Private Key (Base64): %.60s...\n", val_str);
            }
            else if (strcmp(key_str, "pub") == 0) {
                printf("Public Key (Base64): %.60s...\n", val_str);
            }
            else if (strcmp(key_str, "peer") == 0) {
                printf("Peer: %s\n", val_str);
            }
            else if (strcmp(key_str, "b") == 0) {
                // Bot entry
                char *s2 = strchr(val_str, '|');
                if (s2) {
                    *s2 = 0;
                    char *uuid = val_str;
                    char *rest = s2 + 1;
                    char *s3 = strchr(rest, '|');
                    if (s3) {
                        *s3 = 0;
                        char *bk = rest;
                        char *bv = s3 + 1;
                        
                        if (strcmp(bk, "t") == 0) {
                            printf("Bot [%s] - Last Sync: %s\n", uuid, bv);
                        } else {
                            char *s4 = strrchr(bv, '|');
                            if (s4) {
                                *s4 = 0;
                                printf("Bot [%s] - %s = %s (ts: %s)\n", 
                                       uuid, bk, bv, s4 + 1);
                            }
                        }
                    }
                }
            }
            else {
                printf("%s: %s\n", key_str, val_str);
            }
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }
    free(line_copy);
    
    printf("\n========================================\n");
    printf("RAW CONFIG (for debugging)\n");
    printf("========================================\n\n");
    printf("%s\n", plaintext);
    printf("\n========================================\n");

    // Option to save to file
    printf("\nSave decrypted config to file? (y/n): ");
    char answer[10];
    if (fgets(answer, sizeof(answer), stdin) && 
        (answer[0] == 'y' || answer[0] == 'Y')) {
        
        char filename[256];
        printf("Enter filename (default: config_decrypted.txt): ");
        if (!fgets(filename, sizeof(filename), stdin) || 
            strlen(filename) <= 1) {
            strcpy(filename, "config_decrypted.txt");
        }
        filename[strcspn(filename, "\n")] = 0;
        
        FILE *out = fopen(filename, "w");
        if (out) {
            fwrite(plaintext, 1, plain_len, out);
            fclose(out);
            printf("Saved to: %s\n", filename);
            printf("WARNING: This file contains sensitive data! Protect it carefully.\n");
        } else {
            fprintf(stderr, "Error: Could not create output file\n");
        }
    }

    // Cleanup
    secure_wipe(plaintext, plain_len);
    free(plaintext);
    
    printf("\nDone!\n");
    return 0;
}
