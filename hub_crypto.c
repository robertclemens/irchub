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
        // Fallback if RAND fails
        for(int i=0; i<16; i++) b[i] = rand() % 255;
    }

    // Version 4 (Random)
    b[6] = (b[6] & 0x0F) | 0x40;
    // Variant 1 (DCE)
    b[8] = (b[8] & 0x3F) | 0x80;

    snprintf(buffer, len, 
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

// --- Bot Credentials Generation ---
bool hub_crypto_generate_bot_creds(char **out_uuid, char **out_priv_b64, char **out_pub_b64) {
    // 1. Generate UUID
    *out_uuid = malloc(37); 
    if (!*out_uuid) return false;
    generate_uuid_v4(*out_uuid, 37);

    // 2. Generate RSA Keypair
    BIGNUM *bne = BN_new();
    RSA *rsa = RSA_new();
    
    BN_set_word(bne, RSA_F4);
    if (RSA_generate_key_ex(rsa, 2048, bne, NULL) != 1) {
        BN_free(bne); RSA_free(rsa); free(*out_uuid);
        return false;
    }

    // 3. Export Private Key -> Base64
    BIO *bio_priv = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio_priv, rsa, NULL, NULL, 0, NULL, NULL);
    char *priv_data;
    long priv_len = BIO_get_mem_data(bio_priv, &priv_data);
    *out_priv_b64 = base64_encode((unsigned char*)priv_data, priv_len);
    BIO_free(bio_priv);

    // 4. Export Public Key -> Base64
    BIO *bio_pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio_pub, rsa);
    char *pub_data;
    long pub_len = BIO_get_mem_data(bio_pub, &pub_data);
    *out_pub_b64 = base64_encode((unsigned char*)pub_data, pub_len);
    BIO_free(bio_pub);

    BN_free(bne);
    RSA_free(rsa);
    return true;
}

// --- RSA Logic (Existing) ---
bool hub_crypto_generate_keypair(char **priv_pem_out, char **pub_pem_out) {
    BIGNUM *bne = BN_new();
    if(BN_set_word(bne, RSA_F4) != 1) { BN_free(bne); return false; }

    RSA *rsa = RSA_new();
    if(RSA_generate_key_ex(rsa, 2048, bne, NULL) != 1) {
        RSA_free(rsa); BN_free(bne); return false;
    }

    BIO *bio_priv = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio_priv, rsa, NULL, NULL, 0, NULL, NULL);
    BUF_MEM *bptr_priv;
    BIO_get_mem_ptr(bio_priv, &bptr_priv);
    *priv_pem_out = malloc(bptr_priv->length + 1);
    memcpy(*priv_pem_out, bptr_priv->data, bptr_priv->length);
    (*priv_pem_out)[bptr_priv->length] = 0;
    BIO_free(bio_priv);

    BIO *bio_pub = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio_pub, rsa);
    BUF_MEM *bptr_pub;
    BIO_get_mem_ptr(bio_pub, &bptr_pub);
    *pub_pem_out = malloc(bptr_pub->length + 1);
    memcpy(*pub_pem_out, bptr_pub->data, bptr_pub->length);
    (*pub_pem_out)[bptr_pub->length] = 0;
    BIO_free(bio_pub);

    RSA_free(rsa);
    BN_free(bne);
    return true;
}

RSA *load_private_key_from_memory(const char *pem_data) {
    BIO *bio = BIO_new_mem_buf((void*)pem_data, -1);
    if (!bio) return NULL;
    RSA *rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!rsa) ERR_print_errors_fp(stderr);
    return rsa;
}

int rsa_private_decrypt(RSA *rsa, const unsigned char *enc, int enc_len, unsigned char *dec) {
    return RSA_private_decrypt(enc_len, enc, dec, rsa, RSA_PKCS1_OAEP_PADDING);
}

// --- AES GCM Logic (Existing) ---
int aes_gcm_decrypt(const unsigned char *input_buffer, int input_len,
                    const unsigned char *key, unsigned char *plaintext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len, plaintext_len;
    unsigned char iv[GCM_IV_LEN];

    if (input_len < GCM_IV_LEN) return -1;

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
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) goto err;
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
err:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int aes_gcm_encrypt(const unsigned char *plain, int plain_len,
                    const unsigned char *key, unsigned char *output, unsigned char *tag) {
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
