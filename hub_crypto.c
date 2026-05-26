#include "hub.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/kdf.h>

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
    if (!buffer) {
        *out_len = 0;
        return NULL;
    }
    memset(buffer, 0, len);

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf((void *)input, len);
    bmem = BIO_push(b64, bmem);

    *out_len = BIO_read(bmem, buffer, len);
    BIO_free_all(bmem);

    if (*out_len <= 0) {
        free(buffer);
        *out_len = 0;
        return NULL;
    }
    return buffer;
}

// --- UUID Logic ---
void generate_uuid_v4(char *buffer, size_t len) {
    unsigned char b[16];
    if (RAND_bytes(b, 16) != 1) {
        hub_log("RAND_bytes failed in generate_uuid_v4; aborting\n");
        abort();
    }

    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;

    snprintf(buffer, len,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

// --- Curve25519 Keypair Generation ---
bool hub_crypto_generate_combined_keypair(unsigned char priv_out[64],
                                          unsigned char pub_out[64]) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *ed = NULL, *x = NULL;
    size_t len;
    bool ok = false;

    // Ed25519
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) goto out;
    if (EVP_PKEY_keygen(ctx, &ed) <= 0) goto out;
    len = 32;
    if (EVP_PKEY_get_raw_private_key(ed, priv_out, &len) <= 0 || len != 32) goto out;
    len = 32;
    if (EVP_PKEY_get_raw_public_key(ed, pub_out, &len) <= 0 || len != 32) goto out;
    EVP_PKEY_CTX_free(ctx); ctx = NULL;

    // X25519
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) goto out;
    if (EVP_PKEY_keygen(ctx, &x) <= 0) goto out;
    len = 32;
    if (EVP_PKEY_get_raw_private_key(x, priv_out + 32, &len) <= 0 || len != 32) goto out;
    len = 32;
    if (EVP_PKEY_get_raw_public_key(x, pub_out + 32, &len) <= 0 || len != 32) goto out;

    ok = true;
out:
    if (ed)  EVP_PKEY_free(ed);
    if (x)   EVP_PKEY_free(x);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (!ok) { secure_wipe(priv_out, 64); memset(pub_out, 0, 64); }
    return ok;
}

void hub_crypto_split_combined(const unsigned char in[64],
                               unsigned char ed_out[32],
                               unsigned char x_out[32]) {
    memcpy(ed_out, in,      32);
    memcpy(x_out,  in + 32, 32);
}

bool hub_crypto_ed25519_sign(const unsigned char ed_priv[32],
                             const unsigned char *msg, size_t msg_len,
                             unsigned char sig_out[64]) {
    EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, ed_priv, 32);
    if (!pk) return false;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    bool ok = false;
    size_t siglen = 64;
    if (md && EVP_DigestSignInit(md, NULL, NULL, NULL, pk) == 1
           && EVP_DigestSign(md, sig_out, &siglen, msg, msg_len) == 1
           && siglen == 64)
        ok = true;
    if (md) EVP_MD_CTX_free(md);
    EVP_PKEY_free(pk);
    return ok;
}

bool hub_crypto_ed25519_verify(const unsigned char ed_pub[32],
                               const unsigned char *msg, size_t msg_len,
                               const unsigned char sig[64]) {
    EVP_PKEY *pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, ed_pub, 32);
    if (!pk) return false;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    bool ok = false;
    if (md && EVP_DigestVerifyInit(md, NULL, NULL, NULL, pk) == 1
           && EVP_DigestVerify(md, sig, 64, msg, msg_len) == 1)
        ok = true;
    if (md) EVP_MD_CTX_free(md);
    EVP_PKEY_free(pk);
    return ok;
}

bool hub_crypto_x25519_derive(const unsigned char x_priv[32],
                              const unsigned char x_peer_pub[32],
                              unsigned char shared_out[32]) {
    EVP_PKEY *priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, x_priv, 32);
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, x_peer_pub, 32);
    EVP_PKEY_CTX *ctx = NULL;
    bool ok = false;
    size_t len = 32;
    if (priv && peer) {
        ctx = EVP_PKEY_CTX_new(priv, NULL);
        if (ctx && EVP_PKEY_derive_init(ctx) == 1
                && EVP_PKEY_derive_set_peer(ctx, peer) == 1
                && EVP_PKEY_derive(ctx, shared_out, &len) == 1
                && len == 32)
            ok = true;
    }
    if (ctx)  EVP_PKEY_CTX_free(ctx);
    if (priv) EVP_PKEY_free(priv);
    if (peer) EVP_PKEY_free(peer);
    if (!ok)  memset(shared_out, 0, 32);
    return ok;
}

bool hub_crypto_hkdf_sha256(const unsigned char *ikm, size_t ikm_len,
                            const unsigned char *salt, size_t salt_len,
                            const unsigned char *info, size_t info_len,
                            unsigned char *out, size_t out_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    bool ok = false;
    size_t outlen = out_len;
    if (!ctx) return false;
    if (EVP_PKEY_derive_init(ctx) == 1
        && EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) == 1
        && EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, (int)salt_len) == 1
        && EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm, (int)ikm_len) == 1
        && EVP_PKEY_CTX_add1_hkdf_info(ctx, info, (int)info_len) == 1
        && EVP_PKEY_derive(ctx, out, &outlen) == 1
        && outlen == out_len)
        ok = true;
    EVP_PKEY_CTX_free(ctx);
    if (!ok) memset(out, 0, out_len);
    return ok;
}

// --- Bot Credential Generation ---
bool hub_crypto_generate_bot_creds(char **out_uuid,
                                   char **out_priv_b64,
                                   char **out_pub_b64) {
    *out_uuid = NULL; *out_priv_b64 = NULL; *out_pub_b64 = NULL;
    unsigned char priv[64], pub[64];

    *out_uuid = malloc(37);
    if (!*out_uuid) return false;
    generate_uuid_v4(*out_uuid, 37);

    if (!hub_crypto_generate_combined_keypair(priv, pub)) goto fail;

    *out_priv_b64 = base64_encode(priv, 64);
    *out_pub_b64  = base64_encode(pub,  64);
    secure_wipe(priv, 64);
    if (!*out_priv_b64 || !*out_pub_b64) goto fail;
    return true;

fail:
    secure_wipe(priv, 64);
    if (*out_uuid)     { free(*out_uuid);     *out_uuid     = NULL; }
    if (*out_priv_b64) { secure_wipe(*out_priv_b64, strlen(*out_priv_b64));
                         free(*out_priv_b64); *out_priv_b64 = NULL; }
    if (*out_pub_b64)  { free(*out_pub_b64);  *out_pub_b64  = NULL; }
    return false;
}

// --- AES-256-GCM ---
int aes_gcm_decrypt(const unsigned char *input_buffer, int input_len,
                    const unsigned char *key, unsigned char *plaintext,
                    unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len, plaintext_len;
    unsigned char iv[GCM_IV_LEN];

    if (input_len < GCM_IV_LEN) {
        hub_log("Input too small for IV\n");
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
        goto err;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;

err:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    /* GCM is online: EVP_DecryptUpdate may have written partial plaintext before
     * the tag check failed.  Zero it now so unauthenticated bytes never escape. */
    if (ciphertext_len > 0)
        secure_wipe(plaintext, (size_t)ciphertext_len);
    return -1;
}

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

