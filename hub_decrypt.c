#include "hub.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>

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
    
    printf("IRCHub Config Decryption Utility\n");
    printf("=================================\n\n");
    
    if (argc > 1) config_file = argv[1];
    
    printf("Config file: %s\n\n", config_file);
    
    FILE *fp = fopen(config_file, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open '%s'\n", config_file);
        return 1;
    }

    unsigned char salt[SALT_SIZE], iv[GCM_IV_LEN], tag[GCM_TAG_LEN];
    
    if (fread(salt, 1, SALT_SIZE, fp) != SALT_SIZE ||
        fread(iv, 1, GCM_IV_LEN, fp) != GCM_IV_LEN ||
        fread(tag, 1, GCM_TAG_LEN, fp) != GCM_TAG_LEN) {
        fprintf(stderr, "Error: Failed to read headers\n");
        fclose(fp);
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    long cipher_len = fsize - SALT_SIZE - GCM_IV_LEN - GCM_TAG_LEN;
    
    if (cipher_len <= 0) {
        fprintf(stderr, "Error: Invalid file size\n");
        fclose(fp);
        return 1;
    }

    fseek(fp, SALT_SIZE + GCM_IV_LEN + GCM_TAG_LEN, SEEK_SET);
    unsigned char *ciphertext = malloc(cipher_len);
    
    if (fread(ciphertext, 1, cipher_len, fp) != (size_t)cipher_len) {
        fprintf(stderr, "Error: Read failed\n");
        free(ciphertext);
        fclose(fp);
        return 1;
    }
    fclose(fp);

    get_password_secure("Enter password: ", password, sizeof(password));
    
    unsigned char key[32];
    printf("Deriving key...\n");
    
    if (PKCS5_PBKDF2_HMAC(password, strlen(password),
                          salt, SALT_SIZE, PBKDF2_ITERATIONS,
                          EVP_sha256(), 32, key) != 1) {
        fprintf(stderr, "Error: PBKDF2 failed\n");
        secure_wipe(password, sizeof(password));
        free(ciphertext);
        return 1;
    }
    
    secure_wipe(password, sizeof(password));

    unsigned char *plaintext = malloc(cipher_len + 1);
    int len, plain_len;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &plain_len, ciphertext, cipher_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag);

    if (EVP_DecryptFinal_ex(ctx, plaintext + plain_len, &len) <= 0) {
        fprintf(stderr, "\nDecryption failed (wrong password?)\n");
        EVP_CIPHER_CTX_free(ctx);
        secure_wipe(key, sizeof(key));
        free(ciphertext);
        free(plaintext);
        return 1;
    }
    
    plain_len += len;
    plaintext[plain_len] = 0;
    EVP_CIPHER_CTX_free(ctx);
    secure_wipe(key, sizeof(key));
    free(ciphertext);

    printf("\n=== DECRYPTED CONFIG ===\n\n%s\n", plaintext);
    
    secure_wipe(plaintext, plain_len);
    free(plaintext);
    return 0;
}
