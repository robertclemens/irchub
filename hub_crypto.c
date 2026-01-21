#include "hub.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/bn.h> 
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/kdf.h>

// NEW: Secure memory wiping function
void secure_wipe(void *ptr, size_t len) {
    if (!ptr) return;
    volatile unsigned char *p = ptr;
    while (len--) *p++ = 0;
}

// --- Base64 Helpers ---
char *base64_encode(const unsigned char *input, int length) {
    BIO *bmem, *b64;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char *buff = (char *)malloc(bptr->length + 1);
    if (buff) {
        memcpy(buff, bptr->data, bptr->length);
        buff[bptr->length] = 0;
    }

    BIO_free_all(b64);
    return buff;
}

unsigned char *base64_decode(const char *input, int *out_len) {
    BIO *b64, *bmem;
    int len = strlen(input);
    unsigned char *buffer = (unsigned char *)malloc(len);
    memset(buffer, 0, len);

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf((void *)input, len);
    bmem = BIO_push(b64, bmem);

    *out_len = BIO_read(bmem, buffer, len);
    BIO_free_all(bmem);

    return buffer;
}

// --- UUID Logic ---
void generate_uuid_v4(char *buffer, size_t len) {
    unsigned char b[16];
    if (RAND_bytes(b, 16) != 1) {
        for(int i=0; i<16; i++) b[i] = rand() % 255;
    }

    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;

    snprintf(buffer, len, 
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

// FIXED: Modernized RSA key generation using EVP API
bool hub_crypto_generate_keypair(char **priv_pem_out, char **pub_pem_out) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *bio_priv = NULL;
    BIO *bio_pub = NULL;
    bool success = false;

    // Create context for RSA key generation
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) goto cleanup;

    if (EVP_PKEY_keygen_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) goto cleanup;

    // Generate key
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) goto cleanup;

    // Export private key
    bio_priv = BIO_new(BIO_s_mem());
    if (!bio_priv) goto cleanup;
    
    if (!PEM_write_bio_PrivateKey(bio_priv, pkey, NULL, NULL, 0, NULL, NULL)) {
        goto cleanup;
    }

    BUF_MEM *bptr_priv;
    BIO_get_mem_ptr(bio_priv, &bptr_priv);
    *priv_pem_out = malloc(bptr_priv->length + 1);
    if (!*priv_pem_out) goto cleanup;
    
    memcpy(*priv_pem_out, bptr_priv->data, bptr_priv->length);
    (*priv_pem_out)[bptr_priv->length] = 0;

    // Export public key
    bio_pub = BIO_new(BIO_s_mem());
    if (!bio_pub) goto cleanup;
    
    if (!PEM_write_bio_PUBKEY(bio_pub, pkey)) goto cleanup;

    BUF_MEM *bptr_pub;
    BIO_get_mem_ptr(bio_pub, &bptr_pub);
    *pub_pem_out = malloc(bptr_pub->length + 1);
    if (!*pub_pem_out) {
        free(*priv_pem_out);
        *priv_pem_out = NULL;
        goto cleanup;
    }
    
    memcpy(*pub_pem_out, bptr_pub->data, bptr_pub->length);
    (*pub_pem_out)[bptr_pub->length] = 0;

    success = true;

cleanup:
    if (bio_priv) BIO_free(bio_priv);
    if (bio_pub) BIO_free(bio_pub);
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    
    return success;
}

// FIXED: Load private key using EVP API
EVP_PKEY *load_private_key_from_memory(const char *pem_data) {
    BIO *bio = BIO_new_mem_buf((void*)pem_data, -1);
    if (!bio) return NULL;
    
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    
    if (!pkey) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    // ADDED: Validate key size
    if (EVP_PKEY_bits(pkey) < 2048) {
        fprintf(stderr, "Key size too small: %d bits (minimum 2048)\n", 
                EVP_PKEY_bits(pkey));
        EVP_PKEY_free(pkey);
        return NULL;
    }
    
    return pkey;
}

// FIXED: Modern EVP-based private decryption
int evp_private_decrypt(EVP_PKEY *pkey, const unsigned char *enc, 
                        int enc_len, unsigned char *dec) {
    EVP_PKEY_CTX *ctx = NULL;
    size_t outlen;
    int ret = -1;

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) goto cleanup;

    if (EVP_PKEY_decrypt_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) goto cleanup;

    // Determine buffer size
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, enc, enc_len) <= 0) goto cleanup;

    // Perform decryption
    if (EVP_PKEY_decrypt(ctx, dec, &outlen, enc, enc_len) <= 0) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    ret = (int)outlen;

cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return ret;
}

// FIXED: Modern EVP-based public encryption
int evp_public_encrypt(EVP_PKEY *pkey, const unsigned char *plain, 
                       int plain_len, unsigned char *enc) {
    EVP_PKEY_CTX *ctx = NULL;
    size_t outlen;
    int ret = -1;

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx) goto cleanup;

    if (EVP_PKEY_encrypt_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) goto cleanup;

    // Determine buffer size
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, plain, plain_len) <= 0) goto cleanup;

    // Perform encryption
    if (EVP_PKEY_encrypt(ctx, enc, &outlen, plain, plain_len) <= 0) {
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    ret = (int)outlen;

cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return ret;
}

// FIXED: Simplified - no AAD needed (command byte is encrypted)
int aes_gcm_decrypt(const unsigned char *input_buffer, int input_len,
                    const unsigned char *key, unsigned char *plaintext, 
                    unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len, plaintext_len;
    unsigned char iv[GCM_IV_LEN];

    // ADDED: Minimum size check
    if (input_len < GCM_IV_LEN) {
        fprintf(stderr, "Input too small for IV\n");
        return -1;
    }

    memcpy(iv, input_buffer, GCM_IV_LEN);
    const unsigned char *ciphertext = input_buffer + GCM_IV_LEN;
    int ciphertext_len = input_len - GCM_IV_LEN;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;
    
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto err;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL)) goto err;
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) goto err;

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) goto err;
    plaintext_len = len;
    
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, tag)) goto err;
    
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        fprintf(stderr, "GCM tag verification failed\n");
        goto err;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
    
err:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return -1;
}

// FIXED: Simplified - no AAD needed
int aes_gcm_encrypt(const unsigned char *plain, int plain_len,
                    const unsigned char *key, unsigned char *output, 
                    unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len, ciphertext_len;
    unsigned char iv[GCM_IV_LEN];

    if (RAND_bytes(iv, sizeof(iv)) != 1) return -1;
    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto err;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL)) goto err;
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) goto err;

    memcpy(output, iv, GCM_IV_LEN);
    unsigned char *cipher_ptr = output + GCM_IV_LEN;

    if (1 != EVP_EncryptUpdate(ctx, cipher_ptr, &len, plain, plain_len)) goto err;
    ciphertext_len = len;
    
    if (1 != EVP_EncryptFinal_ex(ctx, cipher_ptr + len, &len)) goto err;
    ciphertext_len += len;
    
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag)) goto err;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len + GCM_IV_LEN;
    
err:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return -1;
}

// FIXED: Updated to use EVP API
bool hub_crypto_generate_bot_creds(char **out_uuid, char **out_priv_b64,
                                    char **out_pub_b64) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *bio_priv = NULL;
    BIO *bio_pub = NULL;
    bool success = false;

    // 1. Generate UUID
    *out_uuid = malloc(37);
    if (!*out_uuid) return false;
    generate_uuid_v4(*out_uuid, 37);

    // 2. Generate RSA Keypair using EVP API
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) goto cleanup;

    if (EVP_PKEY_keygen_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) goto cleanup;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) goto cleanup;

    // 3. Export Private Key -> Base64(FULL PEM WITH HEADERS)
    bio_priv = BIO_new(BIO_s_mem());
    if (!bio_priv) goto cleanup;
    
    if (!PEM_write_bio_PrivateKey(bio_priv, pkey, NULL, NULL, 0, NULL, NULL)) {
        goto cleanup;
    }

    char *priv_data;
    long priv_len = BIO_get_mem_data(bio_priv, &priv_data);
    *out_priv_b64 = base64_encode((unsigned char*)priv_data, priv_len);
    if (!*out_priv_b64) goto cleanup;

    // 4. Export Public Key -> Base64(FULL PEM WITH HEADERS)
    bio_pub = BIO_new(BIO_s_mem());
    if (!bio_pub) goto cleanup;
    
    if (!PEM_write_bio_PUBKEY(bio_pub, pkey)) goto cleanup;

    char *pub_data;
    long pub_len = BIO_get_mem_data(bio_pub, &pub_data);
    *out_pub_b64 = base64_encode((unsigned char*)pub_data, pub_len);
    if (!*out_pub_b64) goto cleanup;

    success = true;

cleanup:
    if (!success) {
        if (*out_uuid) {
            free(*out_uuid);
            *out_uuid = NULL;
        }
        if (*out_priv_b64) {
            secure_wipe(*out_priv_b64, strlen(*out_priv_b64));
            free(*out_priv_b64);
            *out_priv_b64 = NULL;
        }
        if (*out_pub_b64) {
            free(*out_pub_b64);
            *out_pub_b64 = NULL;
        }
    }
    if (bio_priv) BIO_free(bio_priv);
    if (bio_pub) BIO_free(bio_pub);
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    
    return success;
}
