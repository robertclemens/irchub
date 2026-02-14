#include "hub.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

// Stub hub_log for hub_crypto.c (encrypt tool doesn't use file logging)
void hub_log(const char *format, ...) {
    (void)format;
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

int main(int argc, char *argv[]) {
    const char *input_file = "config.txt";
    const char *output_file = HUB_CONFIG_FILE;
    char password[128], password_confirm[128];

    printf("IRCHub Config Encryption Utility\n");
    printf("=================================\n\n");

    if (argc > 1) input_file = argv[1];
    if (argc > 2) output_file = argv[2];

    printf("Input file:  %s\n", input_file);
    printf("Output file: %s\n\n", output_file);

    // Read plaintext input file
    FILE *fp = fopen(input_file, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open input file '%s'\n", input_file);
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long plaintext_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (plaintext_len <= 0) {
        fprintf(stderr, "Error: Input file is empty\n");
        fclose(fp);
        return 1;
    }

    unsigned char *plaintext = malloc(plaintext_len);
    if (!plaintext) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(fp);
        return 1;
    }

    if (fread(plaintext, 1, plaintext_len, fp) != (size_t)plaintext_len) {
        fprintf(stderr, "Error: Failed to read input file\n");
        free(plaintext);
        fclose(fp);
        return 1;
    }
    fclose(fp);

    printf("Read %ld bytes from input file\n\n", plaintext_len);

    // Get password
    get_password_secure("Enter encryption password: ", password, sizeof(password));
    get_password_secure("Confirm password: ", password_confirm, sizeof(password_confirm));

    if (strcmp(password, password_confirm) != 0) {
        fprintf(stderr, "\nError: Passwords do not match\n");
        secure_wipe(password, sizeof(password));
        secure_wipe(password_confirm, sizeof(password_confirm));
        secure_wipe(plaintext, plaintext_len);
        free(plaintext);
        return 1;
    }
    secure_wipe(password_confirm, sizeof(password_confirm));

    if (strlen(password) == 0) {
        fprintf(stderr, "\nError: Password cannot be empty\n");
        secure_wipe(password, sizeof(password));
        secure_wipe(plaintext, plaintext_len);
        free(plaintext);
        return 1;
    }

    // Generate random salt and IV
    unsigned char salt[SALT_SIZE];
    unsigned char iv[GCM_IV_LEN];

    if (RAND_bytes(salt, SALT_SIZE) != 1 || RAND_bytes(iv, GCM_IV_LEN) != 1) {
        fprintf(stderr, "\nError: Failed to generate random bytes\n");
        secure_wipe(password, sizeof(password));
        secure_wipe(plaintext, plaintext_len);
        free(plaintext);
        return 1;
    }

    // Derive key from password
    unsigned char key[32];
    printf("\nDeriving encryption key (this may take a moment)...\n");

    if (PKCS5_PBKDF2_HMAC(password, strlen(password),
                          salt, SALT_SIZE, PBKDF2_ITERATIONS,
                          EVP_sha256(), 32, key) != 1) {
        fprintf(stderr, "Error: PBKDF2 key derivation failed\n");
        secure_wipe(password, sizeof(password));
        secure_wipe(plaintext, plaintext_len);
        free(plaintext);
        return 1;
    }

    secure_wipe(password, sizeof(password));

    // Encrypt the plaintext
    unsigned char *ciphertext = malloc(plaintext_len + EVP_CIPHER_block_size(EVP_aes_256_gcm()));
    unsigned char tag[GCM_TAG_LEN];
    if (!ciphertext) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        secure_wipe(key, sizeof(key));
        secure_wipe(plaintext, plaintext_len);
        free(plaintext);
        return 1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create cipher context\n");
        secure_wipe(key, sizeof(key));
        secure_wipe(plaintext, plaintext_len);
        free(plaintext);
        free(ciphertext);
        return 1;
    }

    int len, ciphertext_len;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) {
        fprintf(stderr, "Error: Encryption initialization failed\n");
        EVP_CIPHER_CTX_free(ctx);
        secure_wipe(key, sizeof(key));
        secure_wipe(plaintext, plaintext_len);
        free(plaintext);
        free(ciphertext);
        return 1;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        fprintf(stderr, "Error: Encryption failed\n");
        EVP_CIPHER_CTX_free(ctx);
        secure_wipe(key, sizeof(key));
        secure_wipe(plaintext, plaintext_len);
        free(plaintext);
        free(ciphertext);
        return 1;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        fprintf(stderr, "Error: Encryption finalization failed\n");
        EVP_CIPHER_CTX_free(ctx);
        secure_wipe(key, sizeof(key));
        secure_wipe(plaintext, plaintext_len);
        free(plaintext);
        free(ciphertext);
        return 1;
    }
    ciphertext_len += len;

    // Get the authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1) {
        fprintf(stderr, "Error: Failed to get authentication tag\n");
        EVP_CIPHER_CTX_free(ctx);
        secure_wipe(key, sizeof(key));
        secure_wipe(plaintext, plaintext_len);
        free(plaintext);
        free(ciphertext);
        return 1;
    }

    EVP_CIPHER_CTX_free(ctx);
    secure_wipe(key, sizeof(key));
    secure_wipe(plaintext, plaintext_len);
    free(plaintext);

    // Write encrypted file
    printf("Encrypting...\n");

    FILE *out = fopen(output_file, "wb");
    if (!out) {
        fprintf(stderr, "Error: Cannot create output file '%s'\n", output_file);
        secure_wipe(ciphertext, ciphertext_len);
        free(ciphertext);
        return 1;
    }

    // Write: salt + iv + tag + ciphertext
    if (fwrite(salt, 1, SALT_SIZE, out) != SALT_SIZE ||
        fwrite(iv, 1, GCM_IV_LEN, out) != GCM_IV_LEN ||
        fwrite(tag, 1, GCM_TAG_LEN, out) != GCM_TAG_LEN ||
        fwrite(ciphertext, 1, ciphertext_len, out) != (size_t)ciphertext_len) {
        fprintf(stderr, "Error: Failed to write output file\n");
        fclose(out);
        secure_wipe(ciphertext, ciphertext_len);
        free(ciphertext);
        return 1;
    }

    fclose(out);
    secure_wipe(ciphertext, ciphertext_len);
    free(ciphertext);

    printf("\nSuccess! Encrypted config written to: %s\n", output_file);
    printf("Total size: %ld bytes (salt + iv + tag + ciphertext)\n",
           (long)(SALT_SIZE + GCM_IV_LEN + GCM_TAG_LEN + ciphertext_len));

    return 0;
}
