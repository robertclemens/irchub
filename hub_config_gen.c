/* hub_config_gen.c — standalone encrypted .irchub.cnf generator
 * Usage: hub_config_gen <outfile> <cfgpass> <port> <bind_ip> <uuid>
 *                       <admin_pass> <key_file> <name>
 *                       [peer:IP:PORT:UUID:NAME ...]
 *
 * Key file: path to hub_private.b64 (88-char base64, 64-byte Curve25519 combined key)
 * Peers:    repeat "peer:IP:PORT:UUID:NAME" for each peer hub
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define SALT_SIZE        16
#define GCM_IV_LEN       12
#define GCM_TAG_LEN      16
#define PBKDF2_ITER      100000

static unsigned char *b64_decode(const char *input, int *out_len) {
    BIO *b64, *bmem;
    int len = (int)strlen(input);
    unsigned char *buf = malloc((size_t)len);
    if (!buf) { *out_len = 0; return NULL; }
    memset(buf, 0, (size_t)len);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf((void *)input, len);
    bmem = BIO_push(b64, bmem);
    *out_len = BIO_read(bmem, buf, len);
    BIO_free_all(bmem);
    if (*out_len <= 0) { free(buf); *out_len = 0; return NULL; }
    return buf;
}

static char *b64_encode(const unsigned char *input, int length) {
    BIO *bio, *b64;
    BUF_MEM *bp;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bp);
    char *out = malloc(bp->length + 1);
    if (!out) { BIO_free_all(bio); return NULL; }
    memcpy(out, bp->data, bp->length);
    out[bp->length] = '\0';
    BIO_free_all(bio);
    return out;
}

static int write_config(const char *path, const char *pass, const char *plain) {
    int plen = (int)strlen(plain);
    unsigned char salt[SALT_SIZE], iv[GCM_IV_LEN], tag[GCM_TAG_LEN], key[32];

    if (RAND_bytes(salt, SALT_SIZE) != 1) return -1;
    if (RAND_bytes(iv,   GCM_IV_LEN) != 1) return -1;

    if (PKCS5_PBKDF2_HMAC(pass, (int)strlen(pass), salt, SALT_SIZE,
                           PBKDF2_ITER, EVP_sha256(), 32, key) != 1) {
        fprintf(stderr, "PBKDF2 failed\n");
        return -1;
    }

    unsigned char *ct = malloc((size_t)plen + 16);
    if (!ct) { memset(key, 0, 32); return -1; }

    int len, ctlen;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(ct); memset(key, 0, 32); return -1; }

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ct, &len, (unsigned char *)plain, plen);
    ctlen = len;
    EVP_EncryptFinal_ex(ctx, ct + len, &len); ctlen += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag);
    EVP_CIPHER_CTX_free(ctx);
    memset(key, 0, 32);

    FILE *f = fopen(path, "wb");
    if (!f) { free(ct); return -1; }
    fwrite(salt, 1, SALT_SIZE,   f);
    fwrite(iv,   1, GCM_IV_LEN,  f);
    fwrite(tag,  1, GCM_TAG_LEN, f);
    fwrite(ct,   1, (size_t)ctlen, f);
    fclose(f);
    free(ct);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 9) {
        fprintf(stderr,
            "Usage: %s <outfile> <cfgpass> <port> <bind_ip> <uuid>\n"
            "          <admin_pass> <keyfile> <name>\n"
            "          [peer:IP:PORT:UUID:NAME ...]\n",
            argv[0]);
        return 1;
    }

    const char *outfile    = argv[1];
    const char *cfgpass    = argv[2];
    int         port       = atoi(argv[3]);
    const char *bind_ip    = argv[4];
    const char *uuid       = argv[5];
    const char *admin_pass = argv[6];
    const char *keyfile    = argv[7];
    const char *name       = argv[8];

    /* Load private key from file */
    FILE *kf = fopen(keyfile, "r");
    if (!kf) { fprintf(stderr, "Cannot open key file: %s\n", keyfile); return 1; }
    char b64line[128] = {0};
    if (!fgets(b64line, sizeof(b64line), kf)) {
        fprintf(stderr, "Error reading key file\n"); fclose(kf); return 1;
    }
    fclose(kf);
    b64line[strcspn(b64line, "\r\n")] = 0;

    int dec_len = 0;
    unsigned char *priv64 = b64_decode(b64line, &dec_len);
    if (!priv64 || dec_len != 64) {
        fprintf(stderr, "Invalid key file: expected 64-byte Curve25519 key (88-char base64)\n");
        if (priv64) free(priv64);
        return 1;
    }

    /* Derive public keys from private */
    unsigned char ed25519_pub[32], x25519_pub[32];
    EVP_PKEY *ep = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, priv64, 32);
    EVP_PKEY *xp = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519,  NULL, priv64 + 32, 32);
    memset(priv64, 0, 64); free(priv64);
    if (!ep || !xp) {
        fprintf(stderr, "Failed to load Curve25519 key material\n");
        if (ep) EVP_PKEY_free(ep); if (xp) EVP_PKEY_free(xp);
        return 1;
    }
    size_t klen = 32;
    EVP_PKEY_get_raw_public_key(ep, ed25519_pub, &klen);
    klen = 32;
    EVP_PKEY_get_raw_public_key(xp, x25519_pub, &klen);

    /* Re-read private key to build pub64 blob */
    kf = fopen(keyfile, "r");
    memset(b64line, 0, sizeof(b64line));
    fgets(b64line, sizeof(b64line), kf); fclose(kf);
    b64line[strcspn(b64line, "\r\n")] = 0;
    dec_len = 0;
    priv64 = b64_decode(b64line, &dec_len);

    unsigned char pub64[64];
    memcpy(pub64,      ed25519_pub, 32);
    memcpy(pub64 + 32, x25519_pub,  32);

    char *priv_b64 = b64_encode(priv64, 64);
    char *pub_b64  = b64_encode(pub64,  64);
    memset(priv64, 0, 64); free(priv64);
    EVP_PKEY_free(ep); EVP_PKEY_free(xp);

    if (!priv_b64 || !pub_b64) {
        fprintf(stderr, "base64 encode failed\n");
        if (priv_b64) free(priv_b64); if (pub_b64) free(pub_b64);
        return 1;
    }

    /* Build plaintext config */
    char buf[65536];
    int n = 0, rem = (int)sizeof(buf);
#define APP(...) do { int w = snprintf(buf+n, (size_t)rem, __VA_ARGS__); \
                      if (w>0&&w<rem){n+=w;rem-=w;} } while(0)

    APP("port|%d\n", port);
    APP("bind_ip|%s\n", bind_ip[0] ? bind_ip : "0.0.0.0");
    APP("uuid|%s\n", uuid);
    APP("hub_name|%s\n", name);
    APP("admin|%s\n", admin_pass);

    /* Peer entries: each argv[9+] is "peer:IP:PORT:UUID:NAME" */
    for (int i = 9; i < argc; i++) {
        if (strncmp(argv[i], "peer:", 5) == 0) {
            const char *p = argv[i] + 5;
            /* format: IP:PORT:UUID:NAME — write as-is into peer| line */
            char peerip[64], peeruuid[64], peername[64], peerpub[128];
            int peerport;
            memset(peerip, 0, sizeof(peerip));
            memset(peeruuid, 0, sizeof(peeruuid));
            memset(peername, 0, sizeof(peername));
            memset(peerpub, 0, sizeof(peerpub));
            /* IP:PORT:UUID:NAME[:PUBKEY_B64] — pubkey enables v3 peer auth */
            sscanf(p, "%63[^:]:%d:%63[^:]:%63[^:]:%127s",
                   peerip, &peerport, peeruuid, peername, peerpub);
            if (peerpub[0])
                APP("peer|%s|%d|%s|%s|%s\n", peerip, peerport, peeruuid, peername, peerpub);
            else
                APP("peer|%s|%d|%s|%s\n", peerip, peerport, peeruuid, peername);
        }
    }

    APP("key|%s\n", priv_b64);
    APP("pub|%s\n", pub_b64);

    memset(priv_b64, 0, strlen(priv_b64)); free(priv_b64);
    free(pub_b64);

    if (write_config(outfile, cfgpass, buf) != 0) {
        fprintf(stderr, "Failed to write %s\n", outfile);
        return 1;
    }

    printf("Written: %s  port=%d  uuid=%s\n", outfile, port, uuid);
    return 0;
}
