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
    if (ok) {
        /* A low-order peer point yields an all-zero secret that anyone can
         * compute: never let it key a session. */
        unsigned char acc = 0;
        for (int i = 0; i < 32; i++) acc |= shared_out[i];
        ok = (acc != 0);
    }
    if (!ok)  secure_wipe(shared_out, 32);
    return ok;
}

bool hub_crypto_combined_pub_from_priv(const unsigned char priv[64],
                                       unsigned char pub[64]) {
    EVP_PKEY *ep = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, priv, 32);
    EVP_PKEY *xp = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv + 32, 32);
    size_t l1 = 32, l2 = 32;
    bool ok = (ep && xp
            && EVP_PKEY_get_raw_public_key(ep, pub, &l1) == 1 && l1 == 32
            && EVP_PKEY_get_raw_public_key(xp, pub + 32, &l2) == 1 && l2 == 32);
    if (ep) EVP_PKEY_free(ep);
    if (xp) EVP_PKEY_free(xp);
    if (!ok) memset(pub, 0, 64);
    return ok;
}

/* Strict decode of an 88-char combined public key: only the canonical base64
 * of exactly 64 bytes (one key, one spelling — uniqueness checks and
 * record matching compare strings), neither half all zero. */
bool hub_crypto_pubkey_b64_decode(const char *b64, unsigned char out[64]) {
    memset(out, 0, 64);
    if (!b64 || strlen(b64) != COMBINED_KEY_B64) return false;
    for (int i = 0; i < COMBINED_KEY_B64; i++) {
        char c = b64[i];
        bool alpha = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                     (c >= '0' && c <= '9') || c == '+' || c == '/';
        if (i >= COMBINED_KEY_B64 - 2 ? c != '=' : !alpha) return false;
    }
    int n = 0;
    unsigned char *dec = base64_decode(b64, &n);
    if (!dec || n != 64) { free(dec); return false; }
    char *re = base64_encode(dec, n);
    bool ok = re && strcmp(re, b64) == 0;
    free(re);
    if (ok) {
        unsigned char a = 0, b = 0;
        for (int i = 0; i < 32; i++) { a |= dec[i]; b |= dec[32 + i]; }
        ok = (a != 0 && b != 0);
    }
    if (ok) memcpy(out, dec, 64);
    free(dec);
    return ok;
}

void hub_crypto_key_fingerprint(const unsigned char pub[64],
                                char out[KEY_FP_LEN + 1]) {
    unsigned char h[32];
    unsigned int hl = 0;
    if (EVP_Digest(pub, 64, h, &hl, EVP_sha256(), NULL) != 1 || hl != 32) {
        snprintf(out, KEY_FP_LEN + 1, "????:????:????:????");
        return;
    }
    snprintf(out, KEY_FP_LEN + 1, "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
             h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
}

void hub_crypto_key_fingerprint_b64(const char *b64, char out[KEY_FP_LEN + 1]) {
    unsigned char pub[64];
    if (!b64 || !b64[0])
        snprintf(out, KEY_FP_LEN + 1, "(no key)");
    else if (!hub_crypto_pubkey_b64_decode(b64, pub))
        snprintf(out, KEY_FP_LEN + 1, "(bad key)");
    else
        hub_crypto_key_fingerprint(pub, out);
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

