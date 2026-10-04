/*
 * keygen — Curve25519 keypair generator for ircbot / irchub users and bots.
 *
 * SHARED FILE: kept byte-identical as irchub/keygen.c and
 * ircbot/utils/keygen.c, together with bcrypt_pbkdf.c / bcrypt_pbkdf.h.
 * Change all copies together (the test harness cmp's them).  Self-contained
 * on purpose — OpenSSL (-lcrypto) only, no hub.h / bot.h — so either tree can
 * build it:
 *
 *     gcc -O2 -Wall -Wextra -std=c11 -o keygen keygen.c bcrypt_pbkdf.c -lcrypto
 *
 * Usage:  keygen [-d <dir>] [--no-passphrase | --passphrase-file <f>] [name]
 *         keygen --passwd <YYYYMMDDHHMMSS_name.private.b64>
 *                [--old-passphrase-file <f>] [--no-passphrase | --passphrase-file <f>]
 *         keygen --ssh-fingerprint <public.b64 | hub_public.b64>
 *
 * A new key writes, in <dir> (default: the current directory; created 0700
 * if missing; never overwriting anything):
 *   YYYYMMDDHHMMSS_<name>.private.b64   0600  the IRC private key
 *   YYYYMMDDHHMMSS_<name>.public.b64    0644  base64(ed25519_pub || x25519_pub)
 *   YYYYMMDDHHMMSS_<name>_ed25519       0600  the Ed25519 half as an OpenSSH key
 *   YYYYMMDDHHMMSS_<name>_ed25519.pub   0644
 * and prints the public key, its fingerprint (first 8 bytes of SHA-256(pub),
 * "ab12:cd34:ef56:7890") and a ~/.ssh/config block — never the private key.
 *
 * Passphrase (optional, one for both private files), asked twice on
 * /dev/tty with echo off; empty = none.  Without a terminal, or with
 * --no-passphrase, the keys are written unencrypted with a warning.
 * --passphrase-file reads it from the first line of a 0600 file (scripts,
 * the testnet).  With one:
 *   .private.b64 = "irckey-v2 scrypt <log2N> <r> <p> <salt> <nonce> <ct>":
 *       AES-256-GCM(scrypt(pass, salt, N, r, p) -> 32 bytes) over the 64-byte
 *       ed25519_priv || x25519_priv, AAD = the line before " <ct>".
 *   _ed25519 = openssh-key-v1, aes256-ctr + bcrypt KDF (16 rounds), which
 *       ssh / ssh-add / PuTTYgen open directly.
 * Without one, .private.b64 is the old single line base64(priv), 88 chars.
 *
 * --passwd adds, changes or removes the passphrase of an existing key (the
 * old one is asked first) and rewrites the _ed25519 pair next to it with the
 * same passphrase.  The public key does not change.  Files are replaced via a
 * temporary file + rename, so a crash never leaves half a key.
 * --ssh-fingerprint prints the SHA256 fingerprint SSH shows for a key's
 * Ed25519 half — check a hub's host key against it on first connect.  See
 * irchub/docs/console.md §9 and irchub/docs/passwordless.md.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700 /* realpath */
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "bcrypt_pbkdf.h"

#define KEYGEN_VERSION "2"
#define NAME_MAX_LEN 32
#define DIR_MAX_LEN 1024
#define PATH_CAP (DIR_MAX_LEN + 128)

/* Passphrases: UTF-8 bytes as typed, no normalisation. */
#define PASS_MIN 8
#define PASS_MAX 1024

/* irckey-v2: written with these; readers accept only the ranges below, which
 * cap a hostile file at 128 * r * N = 256 MB and a few seconds of work. */
#define IRCKEY_TAG "irckey-v2"
#define IRCKEY_LOG2N 17
#define IRCKEY_R 8
#define IRCKEY_P 1
#define IRCKEY_LOG2N_MIN 14
#define IRCKEY_LOG2N_MAX 18
#define IRCKEY_R_MAX 8
#define IRCKEY_P_MAX 4
#define IRCKEY_SALT 16
#define IRCKEY_NONCE 12
#define IRCKEY_TAGLEN 16
#define IRCKEY_LINE_MAX 512

/* openssh-key-v1 with a passphrase: ssh-keygen's defaults. */
#define SSH_BCRYPT_ROUNDS 16
#define SSH_SALT 16

/* Keep the private key out of core dumps and away from same-uid ptrace. */
static void harden(void) {
  struct rlimit rl = {0, 0};
  (void)setrlimit(RLIMIT_CORE, &rl);
#if defined(__linux__) && defined(PR_SET_DUMPABLE)
  (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
}

/* ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$ — safe as a filename component. */
static bool valid_name(const char *s) {
  size_t n = strlen(s);
  if (n == 0 || n > NAME_MAX_LEN) return false;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_' ||
              (i > 0 && (c == '.' || c == '-'));
    if (!ok) return false;
  }
  return true;
}

static bool b64(const unsigned char *in, int n, char *out, size_t cap) {
  /* 64 bytes -> 88 chars + NUL */
  if (cap < (size_t)(4 * ((n + 2) / 3) + 1)) return false;
  return EVP_EncodeBlock((unsigned char *)out, in, n) == 4 * ((n + 2) / 3);
}

/* Strict padded base64 of exactly n bytes; false otherwise. */
static bool unb64_n(const char *in, unsigned char *out, size_t n) {
  size_t want = 4 * ((n + 2) / 3), pad = (3 - n % 3) % 3;
  unsigned char tmp[128];
  if (want + 3 > sizeof(tmp) || strlen(in) != want) return false;
  for (size_t i = 0; i < pad; i++)
    if (in[want - 1 - i] != '=') return false;
  if (want > pad && in[want - 1 - pad] == '=') return false;
  if (EVP_DecodeBlock(tmp, (const unsigned char *)in, (int)want) != (int)(want / 4 * 3)) {
    OPENSSL_cleanse(tmp, sizeof(tmp));
    return false;
  }
  memcpy(out, tmp, n);
  OPENSSL_cleanse(tmp, sizeof(tmp));
  return true;
}

static bool unb64_64(const char *in, unsigned char out[64]) {
  return unb64_n(in, out, 64);
}

static bool gen_combined(unsigned char priv[64], unsigned char pub[64]) {
  EVP_PKEY_CTX *ec = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
  EVP_PKEY_CTX *xc = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
  EVP_PKEY *ep = NULL, *xp = NULL;
  size_t l = 32;
  bool ok =
      ec && EVP_PKEY_keygen_init(ec) > 0 && EVP_PKEY_keygen(ec, &ep) > 0 &&
      EVP_PKEY_get_raw_private_key(ep, priv, &l) > 0 && l == 32 &&
      (l = 32, EVP_PKEY_get_raw_public_key(ep, pub, &l) > 0) && l == 32 &&
      xc && EVP_PKEY_keygen_init(xc) > 0 && EVP_PKEY_keygen(xc, &xp) > 0 &&
      (l = 32, EVP_PKEY_get_raw_private_key(xp, priv + 32, &l) > 0) && l == 32 &&
      (l = 32, EVP_PKEY_get_raw_public_key(xp, pub + 32, &l) > 0) && l == 32;
  EVP_PKEY_free(ep);
  EVP_PKEY_free(xp);
  EVP_PKEY_CTX_free(ec);
  EVP_PKEY_CTX_free(xc);
  if (!ok) {
    OPENSSL_cleanse(priv, 64);
    memset(pub, 0, 64);
  }
  return ok;
}

/* The combined public key of a combined private key. */
static bool derive_pub(const unsigned char priv[64], unsigned char pub[64]) {
  EVP_PKEY *ep = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, priv, 32);
  EVP_PKEY *xp = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv + 32, 32);
  size_t l = 32;
  bool ok = ep && xp && EVP_PKEY_get_raw_public_key(ep, pub, &l) > 0 && l == 32 &&
            (l = 32, EVP_PKEY_get_raw_public_key(xp, pub + 32, &l) > 0) && l == 32;
  EVP_PKEY_free(ep);
  EVP_PKEY_free(xp);
  return ok;
}

/* First line of a key file, trailing CR/LF removed, into out (cap bytes). */
static bool read_key_line(const char *path, char *out, size_t cap) {
  FILE *f = fopen(path, "r");
  if (!f) {
    fprintf(stderr, "keygen: cannot open %s: %s\n", path, strerror(errno));
    return false;
  }
  bool ok = fgets(out, (int)cap, f) != NULL;
  fclose(f);
  if (!ok) {
    fprintf(stderr, "keygen: %s is empty\n", path);
    return false;
  }
  out[strcspn(out, "\r\n")] = '\0';
  return true;
}

/* ---- passphrases ------------------------------------------------------ */

/* write(2) whose result is deliberately ignored (prompts, newlines). */
static void put_fd(int fd, const char *s, size_t n) {
  ssize_t r = write(fd, s, n);
  (void)r;
}

static int tty_fd = -1;
static struct termios tty_saved;
static volatile sig_atomic_t tty_echo_off = 0;

static void tty_restore(void) {
  if (tty_echo_off) {
    (void)tcsetattr(tty_fd, TCSAFLUSH, &tty_saved);
    tty_echo_off = 0;
  }
}

/* A signal during a prompt must not leave the terminal without echo. */
static void on_signal(int sig) {
  if (tty_echo_off) (void)tcsetattr(tty_fd, TCSAFLUSH, &tty_saved);
  put_fd(STDERR_FILENO, "\n", 1);
  _exit(128 + sig);
}

static bool tty_open(void) {
  if (tty_fd >= 0) return true;
  tty_fd = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (tty_fd < 0) return false;
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = on_signal;
  sigemptyset(&sa.sa_mask);
  (void)sigaction(SIGINT, &sa, NULL);
  (void)sigaction(SIGTERM, &sa, NULL);
  (void)sigaction(SIGHUP, &sa, NULL);
  (void)sigaction(SIGQUIT, &sa, NULL);
  return true;
}

/* One line from the terminal with echo off.  Returns its length, or -1
 * (no tty, EOF, read error, longer than PASS_MAX). */
static int tty_read_secret(const char *prompt, char *buf, size_t cap) {
  if (!tty_open()) return -1;
  if (tcgetattr(tty_fd, &tty_saved) != 0) return -1;
  struct termios t = tty_saved;
  t.c_lflag &= ~(tcflag_t)(ECHO | ECHONL);
  t.c_lflag |= ICANON;
  tty_echo_off = 1;
  if (tcsetattr(tty_fd, TCSAFLUSH, &t) != 0) {
    tty_echo_off = 0;
    return -1;
  }
  put_fd(tty_fd, prompt, strlen(prompt));
  size_t n = 0;
  bool too_long = false, got_nl = false;
  for (;;) {
    char c;
    ssize_t r = read(tty_fd, &c, 1);
    if (r < 0 && errno == EINTR) continue;
    if (r <= 0) break;
    if (c == '\n') {
      got_nl = true;
      break;
    }
    if (n + 1 < cap && n < PASS_MAX)
      buf[n++] = c;
    else
      too_long = true;
  }
  tty_restore();
  put_fd(tty_fd, "\n", 1);
  if (n > 0 && buf[n - 1] == '\r') n--;
  buf[n] = '\0';
  if (!got_nl || too_long) {
    OPENSSL_cleanse(buf, cap);
    if (too_long) fprintf(stderr, "keygen: passphrase longer than %d bytes\n", PASS_MAX);
    return -1;
  }
  return (int)n;
}

/* A passphrase from the first line of a file that only its owner can read.
 * Returns its length (0 = empty line), or -1. */
static int file_read_secret(const char *path, char *buf, size_t cap) {
  int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
  struct stat st;
  if (fd < 0 || fstat(fd, &st) != 0) {
    fprintf(stderr, "keygen: cannot open %s: %s\n", path, strerror(errno));
    if (fd >= 0) close(fd);
    return -1;
  }
  if (!S_ISREG(st.st_mode) || (st.st_mode & 0077)) {
    fprintf(stderr, "keygen: %s must be a regular file with mode 0600\n", path);
    close(fd);
    return -1;
  }
  size_t n = 0;
  bool too_long = false;
  for (;;) {
    char c;
    ssize_t r = read(fd, &c, 1);
    if (r < 0 && errno == EINTR) continue;
    if (r <= 0 || c == '\n') break;
    if (n + 1 < cap && n < PASS_MAX)
      buf[n++] = c;
    else
      too_long = true;
  }
  close(fd);
  if (n > 0 && buf[n - 1] == '\r') n--;
  buf[n] = '\0';
  if (too_long) {
    OPENSSL_cleanse(buf, cap);
    fprintf(stderr, "keygen: passphrase in %s is longer than %d bytes\n", path, PASS_MAX);
    return -1;
  }
  return (int)n;
}

typedef struct {
  bool none;          /* --no-passphrase */
  const char *file;   /* --passphrase-file */
} pass_src_t;

/* The new passphrase for a key.  Returns its length, 0 for none, -1 to
 * abort.  buf must hold PASS_MAX + 1 bytes. */
static int ask_new_passphrase(const pass_src_t *src, char *buf, size_t cap) {
  int n;
  if (src->none) return 0;
  if (src->file) {
    n = file_read_secret(src->file, buf, cap);
    if (n > 0 && n < PASS_MIN) {
      fprintf(stderr, "keygen: passphrase must be at least %d bytes\n", PASS_MIN);
      OPENSSL_cleanse(buf, cap);
      return -1;
    }
    return n;
  }
  if (!tty_open()) {
    fprintf(stderr, "keygen: warning: no terminal to ask for a passphrase — "
                    "writing the private keys WITHOUT one\n");
    return 0;
  }
  char again[PASS_MAX + 1];
  (void)mlock(again, sizeof(again));
  for (int tries = 0; tries < 3; tries++) {
    n = tty_read_secret("Passphrase for the private keys (empty for none): ", buf, cap);
    if (n < 0) break;
    if (n == 0) {
      fprintf(stderr, "keygen: warning: no passphrase — anyone who copies the "
                      "private key files can use them\n");
      break;
    }
    if (n < PASS_MIN) {
      fprintf(stderr, "keygen: passphrase must be at least %d bytes\n", PASS_MIN);
      OPENSSL_cleanse(buf, cap);
      n = -1;
      continue;
    }
    int m = tty_read_secret("Same passphrase again: ", again, sizeof(again));
    if (m == n && CRYPTO_memcmp(buf, again, (size_t)n) == 0) break;
    fprintf(stderr, "keygen: the passphrases do not match\n");
    OPENSSL_cleanse(buf, cap);
    n = -1;
  }
  OPENSSL_cleanse(again, sizeof(again));
  (void)munlock(again, sizeof(again));
  return n;
}

/* ---- irckey-v2 -------------------------------------------------------- */

static bool irckey_kdf(const char *pass, size_t plen, const unsigned char *salt,
                       unsigned log2n, unsigned r, unsigned p, unsigned char key[32]) {
  uint64_t n = (uint64_t)1 << log2n;
  uint64_t maxmem = 128ULL * r * n + (1ULL << 20) + 128ULL * r * p;
  return EVP_PBE_scrypt(pass, plen, salt, IRCKEY_SALT, n, r, p, maxmem, key, 32) == 1;
}

/* AES-256-GCM seal (enc) or open (!enc) of 64 bytes with aad. */
static bool gcm64(bool enc, const unsigned char key[32], const unsigned char *nonce,
                  const char *aad, const unsigned char *in, unsigned char *out,
                  unsigned char tag[IRCKEY_TAGLEN]) {
  EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
  int l = 0, fl = 0;
  bool ok = c && EVP_CipherInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL, enc) == 1 &&
            EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, IRCKEY_NONCE, NULL) == 1 &&
            EVP_CipherInit_ex(c, NULL, NULL, key, nonce, enc) == 1 &&
            EVP_CipherUpdate(c, NULL, &l, (const unsigned char *)aad, (int)strlen(aad)) == 1 &&
            EVP_CipherUpdate(c, out, &l, in, 64) == 1 && l == 64;
  if (ok && !enc) ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, IRCKEY_TAGLEN, tag) == 1;
  if (ok) ok = EVP_CipherFinal_ex(c, out + 64, &fl) == 1 && fl == 0;
  if (ok && enc) ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, IRCKEY_TAGLEN, tag) == 1;
  EVP_CIPHER_CTX_free(c);
  if (!ok) OPENSSL_cleanse(out, 64);
  return ok;
}

/* The .private.b64 line for priv: irckey-v2 with a passphrase, else the
 * plain 88-char base64. */
static bool irckey_line(const unsigned char priv[64], const char *pass, size_t plen,
                        char *out, size_t cap) {
  if (plen == 0) return b64(priv, 64, out, cap);
  unsigned char salt[IRCKEY_SALT], nonce[IRCKEY_NONCE], key[32] = {0},
                ct[64 + IRCKEY_TAGLEN];
  char salt64[32], nonce64[24], ct64[112];
  bool ok = false;
  (void)mlock(key, sizeof(key));
  if (RAND_bytes(salt, sizeof(salt)) != 1 || RAND_bytes(nonce, sizeof(nonce)) != 1 ||
      !b64(salt, sizeof(salt), salt64, sizeof(salt64)) ||
      !b64(nonce, sizeof(nonce), nonce64, sizeof(nonce64)))
    goto out;
  int hl = snprintf(out, cap, "%s scrypt %d %d %d %s %s", IRCKEY_TAG, IRCKEY_LOG2N,
                    IRCKEY_R, IRCKEY_P, salt64, nonce64);
  if (hl < 0 || (size_t)hl + 1 + sizeof(ct64) > cap) goto out;
  if (!irckey_kdf(pass, plen, salt, IRCKEY_LOG2N, IRCKEY_R, IRCKEY_P, key) ||
      !gcm64(true, key, nonce, out, priv, ct, ct + 64) ||
      !b64(ct, sizeof(ct), ct64, sizeof(ct64)))
    goto out;
  snprintf(out + hl, cap - (size_t)hl, " %s", ct64);
  ok = true;
out:
  OPENSSL_cleanse(key, sizeof(key));
  (void)munlock(key, sizeof(key));
  if (!ok) {
    OPENSSL_cleanse(out, cap);
    fprintf(stderr, "keygen: could not encrypt the private key\n");
  }
  return ok;
}

/* Parsed "irckey-v2 scrypt log2N r p salt nonce ct" (bounds checked). */
typedef struct {
  unsigned log2n, r, p;
  unsigned char salt[IRCKEY_SALT], nonce[IRCKEY_NONCE], ct[64 + IRCKEY_TAGLEN];
  char aad[IRCKEY_LINE_MAX];
} irckey_t;

static bool small_uint(const char *s, unsigned lo, unsigned hi, unsigned *v) {
  if (!*s || strlen(s) > 3) return false;
  unsigned x = 0;
  for (; *s; s++) {
    if (*s < '0' || *s > '9') return false;
    x = x * 10 + (unsigned)(*s - '0');
  }
  if (x < lo || x > hi) return false;
  *v = x;
  return true;
}

static bool irckey_parse(const char *line, irckey_t *k) {
  char buf[IRCKEY_LINE_MAX], *f[8], *save = NULL;
  int nf = 0;
  if (strlen(line) >= sizeof(buf)) return false;
  memcpy(buf, line, strlen(line) + 1);
  for (char *t = strtok_r(buf, " ", &save); t; t = strtok_r(NULL, " ", &save)) {
    if (nf == 8) return false;
    f[nf++] = t;
  }
  /* single spaces only, so the AAD is exactly what the writer produced */
  bool ok = nf == 8 && strcmp(f[0], IRCKEY_TAG) == 0 && strcmp(f[1], "scrypt") == 0 &&
            strstr(line, "  ") == NULL && line[strlen(line) - 1] != ' ' &&
            small_uint(f[2], IRCKEY_LOG2N_MIN, IRCKEY_LOG2N_MAX, &k->log2n) &&
            small_uint(f[3], 1, IRCKEY_R_MAX, &k->r) &&
            small_uint(f[4], 1, IRCKEY_P_MAX, &k->p) &&
            unb64_n(f[5], k->salt, IRCKEY_SALT) &&
            unb64_n(f[6], k->nonce, IRCKEY_NONCE) &&
            unb64_n(f[7], k->ct, sizeof(k->ct));
  if (ok) {
    size_t al = (size_t)(f[7] - buf) - 1; /* up to, not including, " <ct>" */
    memcpy(k->aad, line, al);
    k->aad[al] = '\0';
  }
  OPENSSL_cleanse(buf, sizeof(buf));
  return ok;
}

static bool is_irckey(const char *line) {
  return strncmp(line, IRCKEY_TAG " ", sizeof(IRCKEY_TAG)) == 0;
}

/* Reads a .private.b64 (either format) into priv.  An encrypted key asks for
 * its passphrase (from old_file, else the terminal; 3 tries).  *was_enc says
 * which format it was. */
static bool load_private(const char *path, const char *old_file,
                         unsigned char priv[64], bool *was_enc) {
  char line[IRCKEY_LINE_MAX + 2], pass[PASS_MAX + 1];
  unsigned char key[32];
  irckey_t k;
  bool ok = false;
  (void)mlock(line, sizeof(line));
  (void)mlock(pass, sizeof(pass));
  (void)mlock(key, sizeof(key));
  struct stat st;
  if (stat(path, &st) == 0 && (st.st_mode & 0077))
    fprintf(stderr, "keygen: warning: %s is readable by others — chmod 600 it\n", path);
  if (!read_key_line(path, line, sizeof(line))) goto out;
  *was_enc = is_irckey(line);
  if (!*was_enc) {
    if (!unb64_64(line, priv)) {
      fprintf(stderr, "keygen: %s does not hold a private key\n", path);
      goto out;
    }
    ok = true;
    goto out;
  }
  if (!irckey_parse(line, &k)) {
    fprintf(stderr, "keygen: %s: unreadable or out-of-range irckey-v2 line\n", path);
    goto out;
  }
  for (int tries = 0; tries < (old_file ? 1 : 3) && !ok; tries++) {
    int n = old_file ? file_read_secret(old_file, pass, sizeof(pass))
                     : tty_read_secret("Current passphrase: ", pass, sizeof(pass));
    if (n < 0) {
      if (!old_file) fprintf(stderr, "keygen: the key is encrypted and there is no "
                                     "terminal to ask for its passphrase\n");
      break;
    }
    ok = irckey_kdf(pass, (size_t)n, k.salt, k.log2n, k.r, k.p, key) &&
         gcm64(false, key, k.nonce, k.aad, k.ct, priv, k.ct + 64);
    OPENSSL_cleanse(pass, sizeof(pass));
    if (!ok) fprintf(stderr, "keygen: wrong passphrase (or a damaged key file)\n");
  }
out:
  OPENSSL_cleanse(line, sizeof(line));
  OPENSSL_cleanse(pass, sizeof(pass));
  OPENSSL_cleanse(key, sizeof(key));
  OPENSSL_cleanse(&k, sizeof(k));
  (void)munlock(line, sizeof(line));
  (void)munlock(pass, sizeof(pass));
  (void)munlock(key, sizeof(key));
  return ok;
}

/* ---- OpenSSH ---------------------------------------------------------- */

/* The ssh-ed25519 key blob: string "ssh-ed25519" || string pub(32). */
static size_t ssh_blob(const unsigned char pub[32], unsigned char out[51]) {
  static const unsigned char head[19] = {0, 0, 0, 11, 's', 's', 'h', '-', 'e', 'd',
                                         '2', '5', '5', '1', '9', 0, 0, 0, 32};
  memcpy(out, head, sizeof(head));
  memcpy(out + sizeof(head), pub, 32);
  return 51;
}

/* "SHA256:<base64, no padding>" — what OpenSSH prints for the key. */
static void ssh_fingerprint(const unsigned char pub[32], char out[64]) {
  unsigned char blob[51], h[32];
  unsigned int hl = 0;
  char b[48];
  snprintf(out, 64, "SHA256:?");
  if (EVP_Digest(blob, ssh_blob(pub, blob), h, &hl, EVP_sha256(), NULL) != 1 ||
      hl != 32 || EVP_EncodeBlock((unsigned char *)b, h, 32) != 44)
    return;
  b[43] = '\0'; /* drop the one '=' */
  snprintf(out, 64, "SHA256:%s", b);
}

static int cmd_ssh_fingerprint(const char *path) {
  char line[256];
  unsigned char pub[64];
  if (!read_key_line(path, line, sizeof(line))) return 1;
  if (strstr(path, ".private.") || is_irckey(line)) {
    fprintf(stderr, "keygen: %s is a PRIVATE key; give the .public.b64\n", path);
    return 1;
  }
  if (!unb64_64(line, pub)) {
    fprintf(stderr, "keygen: %s does not hold an 88-char public key\n", path);
    return 1;
  }
  char fp[64];
  ssh_fingerprint(pub, fp);
  printf("%s ssh-ed25519\n", fp);
  return 0;
}

static void put32(unsigned char *p, size_t *o, uint32_t v) {
  p[(*o)++] = (unsigned char)(v >> 24);
  p[(*o)++] = (unsigned char)(v >> 16);
  p[(*o)++] = (unsigned char)(v >> 8);
  p[(*o)++] = (unsigned char)v;
}

static void putstr(unsigned char *p, size_t *o, const void *d, size_t n) {
  put32(p, o, (uint32_t)n);
  memcpy(p + *o, d, n);
  *o += n;
}

/* AES-256-CTR in place with the first 48 bytes of kiv (key || iv). */
static bool aes256ctr(const unsigned char kiv[48], unsigned char *buf, size_t n) {
  EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
  int l = 0, fl = 0;
  bool ok = c && EVP_EncryptInit_ex(c, EVP_aes_256_ctr(), NULL, kiv, kiv + 32) == 1 &&
            EVP_EncryptUpdate(c, buf, &l, buf, (int)n) == 1 && (size_t)l == n &&
            EVP_EncryptFinal_ex(c, buf + l, &fl) == 1 && fl == 0;
  EVP_CIPHER_CTX_free(c);
  return ok;
}

/* An "openssh-key-v1" private key: encrypted (aes256-ctr, bcrypt KDF) when
 * plen > 0.  pem (cap >= 1024) gets the text without the final newline
 * (write_file adds it). */
static bool openssh_pem(const unsigned char seed[32], const unsigned char pub[32],
                        const char *comment, const char *pass, size_t plen,
                        char *pem, size_t cap) {
  unsigned char raw[512] = {0}, sec[320] = {0}, blob[51], salt[SSH_SALT], kiv[48] = {0},
                kdfopt[64];
  size_t o = 0, so = 0, ko = 0, cl = strlen(comment), block = plen ? 16 : 8;
  unsigned char check[4];
  bool ok = false;
  char b[700];
  (void)mlock(sec, sizeof(sec));
  (void)mlock(raw, sizeof(raw));
  (void)mlock(kiv, sizeof(kiv));
  if (cl > 64 || cap < 1024 || RAND_bytes(check, 4) != 1) goto out;
  memcpy(raw, "openssh-key-v1", 15); /* incl. NUL */
  o = 15;
  if (plen) {
    if (RAND_bytes(salt, sizeof(salt)) != 1) goto out;
    putstr(kdfopt, &ko, salt, sizeof(salt));
    put32(kdfopt, &ko, SSH_BCRYPT_ROUNDS);
    putstr(raw, &o, "aes256-ctr", 10);
    putstr(raw, &o, "bcrypt", 6);
    putstr(raw, &o, kdfopt, ko);
  } else {
    putstr(raw, &o, "none", 4);
    putstr(raw, &o, "none", 4);
    putstr(raw, &o, "", 0);
  }
  put32(raw, &o, 1);
  putstr(raw, &o, blob, ssh_blob(pub, blob));
  memcpy(sec, check, 4);
  memcpy(sec + 4, check, 4);
  so = 8;
  putstr(sec, &so, "ssh-ed25519", 11);
  putstr(sec, &so, pub, 32);
  put32(sec, &so, 64);
  memcpy(sec + so, seed, 32);
  memcpy(sec + so + 32, pub, 32);
  so += 64;
  putstr(sec, &so, comment, cl);
  for (unsigned char pad = 1; so % block != 0; pad++) sec[so++] = pad;
  if (plen && (bcrypt_pbkdf(pass, plen, salt, sizeof(salt), kiv, sizeof(kiv),
                            SSH_BCRYPT_ROUNDS) != 0 ||
               !aes256ctr(kiv, sec, so)))
    goto out;
  putstr(raw, &o, sec, so);

  int bl = EVP_EncodeBlock((unsigned char *)b, raw, (int)o);
  if (bl <= 0 || (size_t)bl + (size_t)bl / 70 + 80 > cap) goto out;
  size_t p = (size_t)snprintf(pem, cap, "-----BEGIN OPENSSH PRIVATE KEY-----\n");
  for (int i = 0; i < bl; i += 70) {
    int n = bl - i < 70 ? bl - i : 70;
    memcpy(pem + p, b + i, (size_t)n);
    p += (size_t)n;
    pem[p++] = '\n';
  }
  snprintf(pem + p, cap - p, "-----END OPENSSH PRIVATE KEY-----");
  ok = true;
out:
  OPENSSL_cleanse(sec, sizeof(sec));
  OPENSSL_cleanse(raw, sizeof(raw));
  OPENSSL_cleanse(kiv, sizeof(kiv));
  OPENSSL_cleanse(b, sizeof(b));
  (void)munlock(sec, sizeof(sec));
  (void)munlock(raw, sizeof(raw));
  (void)munlock(kiv, sizeof(kiv));
  return ok;
}

/* "ssh-ed25519 <blob> <comment>" */
static bool openssh_pub(const unsigned char pub[32], const char *comment, char *out,
                        size_t cap) {
  unsigned char blob[51];
  char blob64[80];
  if (EVP_EncodeBlock((unsigned char *)blob64, blob, (int)ssh_blob(pub, blob)) != 68)
    return false;
  int n = snprintf(out, cap, "ssh-ed25519 %s %s", blob64, comment);
  return n > 0 && (size_t)n < cap;
}

/* ---- files ------------------------------------------------------------ */

/* Write text + "\n" to path with `mode`.  replace = false: create it
 * exclusively (never replaces a file, never follows a symlink).  replace =
 * true: write a temporary file next to it and rename it over path. */
static bool write_file(const char *path, mode_t mode, const char *text, bool replace) {
  char tmp[PATH_CAP + 32];
  const char *target = path;
  int fd;
  if (replace) {
    int n = snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path);
    if (n < 0 || (size_t)n >= sizeof(tmp)) return false;
    fd = mkstemp(tmp);
    target = tmp;
  } else {
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode);
  }
  if (fd < 0) {
    fprintf(stderr, "keygen: cannot create %s: %s\n", target, strerror(errno));
    return false;
  }
  (void)fchmod(fd, mode); /* independent of the caller's umask */
  size_t n = strlen(text);
  bool ok = write(fd, text, n) == (ssize_t)n && write(fd, "\n", 1) == 1 &&
            fsync(fd) == 0;
  if (close(fd) != 0) ok = false;
  if (ok && replace && rename(tmp, path) != 0) ok = false;
  if (!ok) {
    fprintf(stderr, "keygen: writing %s failed: %s\n", path, strerror(errno));
    unlink(target);
  }
  return ok;
}

/* <dir> exists as a directory, or is created 0700 (one level). */
static bool ensure_dir(const char *dir) {
  struct stat st;
  if (stat(dir, &st) == 0) {
    if (S_ISDIR(st.st_mode)) return true;
    fprintf(stderr, "keygen: %s is not a directory\n", dir);
    return false;
  }
  if (errno != ENOENT || mkdir(dir, 0700) != 0) {
    fprintf(stderr, "keygen: cannot create directory %s: %s\n", dir, strerror(errno));
    return false;
  }
  return true;
}

/* The ssh/ssh-add lines keygen prints after writing an SSH key. */
static void print_ssh_help(const char *key_path, const char *name, bool enc) {
  char abs[PATH_MAX];
  const char *p = realpath(key_path, abs) ? abs : key_path;
  printf("SSH console (any hub where '%s' is an admin) — add to ~/.ssh/config:\n", name);
  printf("  Host irchub-<hub>\n");
  printf("      HostName <hub host>\n");
  printf("      Port <hubport>\n");
  printf("      User %s\n", name);
  printf("      IdentityFile %s\n", p);
  printf("      IdentitiesOnly yes\n");
  printf("then: ssh irchub-<hub>\n");
  if (enc) printf("Unlock it for an hour at a time with: ssh-add -t 1h %s\n", p);
  printf("PuTTY: load %s in PuTTYgen and save it as a .ppk.\n", p);
}

static void print_fp(const unsigned char pub[64]) {
  unsigned char h[32];
  unsigned int hl = 0;
  char fp[20] = "????:????:????:????";
  if (EVP_Digest(pub, 64, h, &hl, EVP_sha256(), NULL) == 1 && hl == 32)
    snprintf(fp, sizeof(fp), "%02x%02x:%02x%02x:%02x%02x:%02x%02x", h[0], h[1],
             h[2], h[3], h[4], h[5], h[6], h[7]);
  printf("  fingerprint: %s\n", fp);
}

/* Secrets of one run, in one mlock'd block. */
typedef struct {
  unsigned char priv[64];
  char pass[PASS_MAX + 1];
  char priv_line[IRCKEY_LINE_MAX];
  char pem[1024];
} secrets_t;

static secrets_t *secrets_new(void) {
  secrets_t *s = calloc(1, sizeof(*s));
  if (s) (void)mlock(s, sizeof(*s));
  return s;
}

static void secrets_free(secrets_t *s) {
  if (!s) return;
  OPENSSL_cleanse(s, sizeof(*s));
  (void)munlock(s, sizeof(*s));
  free(s);
}

/* keygen --passwd <stamp_name.private.b64> */
static int cmd_passwd(const char *path, const char *old_file, const pass_src_t *src) {
  const char *base = strrchr(path, '/');
  base = base ? base + 1 : path;
  const char *suf = strstr(base, ".private.b64");
  if (!suf || suf[12] != '\0' || suf == base) {
    fprintf(stderr, "keygen: expected a <YYYYMMDDHHMMSS>_<name>.private.b64 file\n");
    return 1;
  }
  char stem[PATH_CAP], name[NAME_MAX_LEN + 1];
  int sl = snprintf(stem, sizeof(stem), "%.*s", (int)(suf - path), path);
  if (sl < 0 || (size_t)sl >= sizeof(stem) - 16) {
    fprintf(stderr, "keygen: path too long\n");
    return 1;
  }
  /* the name: the stem after the timestamp */
  const char *sb = stem + (base - path), *us = strchr(sb, '_');
  const char *nm = us && valid_name(us + 1) ? us + 1 : sb;
  if (!valid_name(nm)) {
    fprintf(stderr, "keygen: cannot read a name from %s\n", base);
    return 1;
  }
  snprintf(name, sizeof(name), "%s", nm);

  secrets_t *s = secrets_new();
  unsigned char pub[64];
  char key_path[PATH_CAP + 16], kpub_path[PATH_CAP + 16], pub_line[256];
  bool was_enc = false;
  int rc = 1;
  if (!s) goto out;
  if (!load_private(path, old_file, s->priv, &was_enc)) goto out;
  if (!derive_pub(s->priv, pub)) {
    fprintf(stderr, "keygen: %s does not hold a valid key\n", path);
    goto out;
  }
  if (!src->none && !src->file && !tty_open()) {
    fprintf(stderr, "keygen: --passwd needs a terminal (or --passphrase-file / "
                    "--no-passphrase)\n");
    goto out;
  }
  int n = ask_new_passphrase(src, s->pass, sizeof(s->pass));
  if (n < 0) goto out;
  snprintf(key_path, sizeof(key_path), "%s_ed25519", stem);
  snprintf(kpub_path, sizeof(kpub_path), "%s_ed25519.pub", stem);
  if (!irckey_line(s->priv, s->pass, (size_t)n, s->priv_line, sizeof(s->priv_line)) ||
      !openssh_pem(s->priv, pub, name, s->pass, (size_t)n, s->pem, sizeof(s->pem)) ||
      !openssh_pub(pub, name, pub_line, sizeof(pub_line))) {
    fprintf(stderr, "keygen: could not build the keys\n");
    goto out;
  }
  /* SSH pair first: if it fails, the IRC key is still the old one. */
  if (!write_file(key_path, 0600, s->pem, true) ||
      !write_file(kpub_path, 0644, pub_line, true) ||
      !write_file(path, 0600, s->priv_line, true))
    goto out;
  printf("%s for '%s':\n", n ? (was_enc ? "Passphrase changed" : "Passphrase added")
                             : "Passphrase removed", name);
  printf("  irc key:  %s  (%s)\n", path, n ? "encrypted" : "NOT encrypted");
  printf("  ssh key:  %s  (%s)\n", key_path, n ? "encrypted" : "NOT encrypted");
  printf("  ssh pub:  %s\n", kpub_path);
  print_fp(pub);
  printf("The public key is unchanged; nothing on the hubs or bots needs updating.\n");
  printf("Load the new file in your IRC client script (or /botlock + /botunlock).\n\n");
  print_ssh_help(key_path, name, n > 0);
  rc = 0;
out:
  secrets_free(s);
  return rc;
}

static void usage(FILE *f) {
  fprintf(f,
          "Usage: keygen [-d <dir>] [--no-passphrase | --passphrase-file <f>] [name]\n"
          "       keygen --passwd <YYYYMMDDHHMMSS_name.private.b64>\n"
          "              [--old-passphrase-file <f>] [--no-passphrase | --passphrase-file <f>]\n"
          "       keygen --ssh-fingerprint <public.b64 | hub_public.b64>\n"
          "Generates a Curve25519 (Ed25519 + X25519) keypair in <dir> (default: here):\n"
          "  YYYYMMDDHHMMSS_<name>.private.b64  (0600, for the IRC client scripts)\n"
          "  YYYYMMDDHHMMSS_<name>.public.b64   (give this to an admin)\n"
          "  YYYYMMDDHHMMSS_<name>_ed25519      (0600, SSH key for the hub console)\n"
          "  YYYYMMDDHHMMSS_<name>_ed25519.pub\n"
          "It asks for an optional passphrase (empty for none) that protects both\n"
          "private files.  Without [name] it asks for one. Names: letters, digits,\n"
          "_ . - (max %d, not starting with . or -).\n"
          "--passwd adds/changes/removes the passphrase of an existing key and\n"
          "rewrites its _ed25519 pair; --passphrase-file reads a passphrase from\n"
          "the first line of a 0600 file; --ssh-fingerprint prints the SHA256\n"
          "fingerprint ssh shows.\n",
          NAME_MAX_LEN);
}

int main(int argc, char *argv[]) {
  harden();

  const char *dir = NULL, *passwd = NULL, *sshfp = NULL, *old_file = NULL, *arg = NULL;
  pass_src_t src = {false, NULL};
  for (int i = 1; i < argc; i++) {
    const char *a = argv[i];
    bool has_next = i + 1 < argc;
    if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
      usage(stdout);
      return 0;
    } else if (strcmp(a, "-d") == 0 && has_next && !dir) {
      dir = argv[++i];
    } else if (strcmp(a, "--passwd") == 0 && has_next && !passwd) {
      passwd = argv[++i];
    } else if (strcmp(a, "--ssh-fingerprint") == 0 && has_next && !sshfp) {
      sshfp = argv[++i];
    } else if (strcmp(a, "--passphrase-file") == 0 && has_next && !src.file) {
      src.file = argv[++i];
    } else if (strcmp(a, "--old-passphrase-file") == 0 && has_next && !old_file) {
      old_file = argv[++i];
    } else if (strcmp(a, "--no-passphrase") == 0) {
      src.none = true;
    } else if (a[0] != '-' && !arg) {
      arg = a;
    } else {
      usage(stderr);
      return 1;
    }
  }
  if ((src.none && src.file) || (sshfp && (passwd || dir || arg || src.none || src.file ||
                                           old_file)) ||
      (passwd && (dir || arg)) || (old_file && !passwd)) {
    usage(stderr);
    return 1;
  }
  if (sshfp) return cmd_ssh_fingerprint(sshfp);
  if (passwd) return cmd_passwd(passwd, old_file, &src);

  char name[128] = {0};
  if (arg) {
    snprintf(name, sizeof(name), "%s", arg);
  } else {
    printf("Key name (e.g. your nick): ");
    fflush(stdout);
    if (!fgets(name, sizeof(name), stdin)) {
      fprintf(stderr, "keygen: no name given\n");
      return 1;
    }
    name[strcspn(name, "\r\n")] = '\0';
  }
  if (!valid_name(name)) {
    fprintf(stderr, "keygen: invalid name '%s' — use letters, digits, _ . - "
                    "(max %d, not starting with . or -)\n", name, NAME_MAX_LEN);
    return 1;
  }
  if (dir && (strlen(dir) == 0 || strlen(dir) > DIR_MAX_LEN)) {
    fprintf(stderr, "keygen: -d: empty or longer than %d bytes\n", DIR_MAX_LEN);
    return 1;
  }
  if (dir && !ensure_dir(dir)) return 1;

  char stamp[32];
  time_t now = time(NULL);
  struct tm tmv;
  if (!localtime_r(&now, &tmv) ||
      strftime(stamp, sizeof(stamp), "%Y%m%d%H%M%S", &tmv) == 0) {
    fprintf(stderr, "keygen: cannot format the timestamp\n");
    return 1;
  }
  /* valid_name caps the name and DIR_MAX_LEN the directory, so PATH_CAP
   * always fits; a short write is still fatal. */
  char priv_path[PATH_CAP], pub_path[PATH_CAP], key_path[PATH_CAP], kpub_path[PATH_CAP];
  const char *d = dir ? dir : "", *sep = dir ? "/" : "";
  int l1 = snprintf(priv_path, sizeof(priv_path), "%s%s%s_%s.private.b64", d, sep, stamp, name);
  int l2 = snprintf(pub_path, sizeof(pub_path), "%s%s%s_%s.public.b64", d, sep, stamp, name);
  int l3 = snprintf(key_path, sizeof(key_path), "%s%s%s_%s_ed25519", d, sep, stamp, name);
  int l4 = snprintf(kpub_path, sizeof(kpub_path), "%s%s%s_%s_ed25519.pub", d, sep, stamp, name);
  if (l1 < 0 || (size_t)l1 >= sizeof(priv_path) || l2 < 0 || (size_t)l2 >= sizeof(pub_path) ||
      l3 < 0 || (size_t)l3 >= sizeof(key_path) || l4 < 0 || (size_t)l4 >= sizeof(kpub_path)) {
    fprintf(stderr, "keygen: file name too long\n");
    return 1;
  }

  secrets_t *s = secrets_new();
  unsigned char pub[64];
  char pub_b64[89], ssh_pub_line[256];
  int wrote = 0, rc = 1;
  const char *paths[4] = {priv_path, pub_path, key_path, kpub_path};
  if (!s) {
    fprintf(stderr, "keygen: out of memory\n");
    return 1;
  }
  int n = ask_new_passphrase(&src, s->pass, sizeof(s->pass));
  if (n < 0) goto out;
  if (!gen_combined(s->priv, pub) || !b64(pub, 64, pub_b64, sizeof(pub_b64)) ||
      !irckey_line(s->priv, s->pass, (size_t)n, s->priv_line, sizeof(s->priv_line)) ||
      !openssh_pem(s->priv, pub, name, s->pass, (size_t)n, s->pem, sizeof(s->pem)) ||
      !openssh_pub(pub, name, ssh_pub_line, sizeof(ssh_pub_line))) {
    fprintf(stderr, "keygen: key generation failed\n");
    goto out;
  }
  if (!write_file(priv_path, 0600, s->priv_line, false)) goto out;
  wrote++;
  if (!write_file(pub_path, 0644, pub_b64, false)) goto out;
  wrote++;
  if (!write_file(key_path, 0600, s->pem, false)) goto out;
  wrote++;
  if (!write_file(kpub_path, 0644, ssh_pub_line, false)) goto out;
  wrote++;

  printf("Generated Curve25519 keypair (keygen v%s) for '%s':\n", KEYGEN_VERSION, name);
  printf("  private: %s  (0600, %s)\n", priv_path,
         n ? "passphrase-protected" : "NOT passphrase-protected");
  printf("  public:  %s\n", pub_path);
  printf("  ssh key: %s  (0600, %s)\n", key_path,
         n ? "passphrase-protected" : "NOT passphrase-protected");
  printf("  ssh pub: %s\n", kpub_path);
  printf("  public key:  %s\n", pub_b64);
  print_fp(pub);
  printf("\nNext:\n");
  printf("  - Give the PUBLIC key to an admin: hub console 'admin add' / 'oper add'\n");
  printf("    / 'userkey', or IRC '+admin|+oper <name> <pubkey> <mask>'.\n");
  printf("  - Point your IRC client script (ircbot/utils) at %s\n", priv_path);
  if (!n) printf("  - Add a passphrase later with: keygen --passwd %s\n", priv_path);
  printf("\n");
  print_ssh_help(key_path, name, n > 0);
  rc = 0;

out:
  if (rc != 0)
    for (int i = 0; i < wrote; i++) unlink(paths[i]); /* never leave half a set */
  secrets_free(s);
  return rc;
}
