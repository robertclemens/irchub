/* sync_digest.c — hash-first hub anti-entropy (CMD_SYNC_DIGEST 0x94), 2.5.4.
 * See sync_digest.h; spec ircbot-testnet/proto/syncdigest/model.py. */
#include "sync_digest.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  const char *kind;
  size_t klen;
  char *norm;    /* heap: the normalised line, no '\n' */
  size_t nlen;
} sdg_line_t;

/* Bytes of a line's first field (the whole line without a '|'). */
static size_t sdg_klen(const char *l, size_t n) {
  const char *bar = memchr(l, '|', n);
  return bar ? (size_t)(bar - l) : n;
}

/* Copy line `l` (n bytes, no '\n') into a new heap string with field `blank`
 * emptied (-1: none); *olen its length. */
static char *sdg_norm(const char *l, size_t n, int blank, size_t *olen) {
  char *o = malloc(n + 1);
  if (!o) return NULL;
  size_t w = 0;
  int field = 0;
  for (size_t i = 0; i < n; i++) {
    if (l[i] == '|') {
      field++;
      o[w++] = '|';
      continue;
    }
    if (field != blank) o[w++] = l[i];
  }
  o[w] = '\0';
  *olen = w;
  return o;
}

static int sdg_kind_blank(const char *k, size_t kl) {
  if (kl == 1 && (k[0] == 'a' || k[0] == 'o')) return 5;
  if (kl == 1 && k[0] == 'm') return 4;
  return -1;
}

static int sdg_bytes_cmp(const char *a, size_t al, const char *b, size_t bl) {
  int c = memcmp(a, b, al < bl ? al : bl);
  if (c) return c;
  return al < bl ? -1 : al > bl ? 1 : 0;
}

static int sdg_line_cmp(const void *x, const void *y) {
  const sdg_line_t *a = x, *b = y;
  int c = sdg_bytes_cmp(a->kind, a->klen, b->kind, b->klen);
  return c ? c : sdg_bytes_cmp(a->norm, a->nlen, b->norm, b->nlen);
}

long sdg_digest(const char *packet, size_t len, char *out, size_t cap) {
  long rc = -1;
  size_t n = 0;
  for (size_t i = 0; i < len; i++)
    if (packet[i] == '\n') n++;
  n++; /* a last line without '\n' */
  sdg_line_t *ls = calloc(n, sizeof(*ls));
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ls || !ctx) goto out;
  size_t cnt = 0;
  for (size_t at = 0; at < len;) {
    const char *nl = memchr(packet + at, '\n', len - at);
    size_t l = nl ? (size_t)(nl - (packet + at)) : len - at;
    if (l > 0) {
      const char *line = packet + at;
      size_t kl = sdg_klen(line, l);
      if (kl > SDG_KIND_MAX) goto out;
      ls[cnt].norm = sdg_norm(line, l, sdg_kind_blank(line, kl), &ls[cnt].nlen);
      if (!ls[cnt].norm) goto out;
      ls[cnt].kind = ls[cnt].norm; /* the kind survives normalising: field 0 */
      ls[cnt].klen = kl;
      cnt++;
    }
    at += l + 1;
  }
  qsort(ls, cnt, sizeof(*ls), sdg_line_cmp);
  int w = snprintf(out, cap, "v|1\n");
  if (w < 0 || (size_t)w >= cap) goto out;
  size_t at = (size_t)w;
  int kinds = 0;
  for (size_t i = 0; i < cnt;) {
    size_t e = i;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto out;
    while (e < cnt && sdg_bytes_cmp(ls[e].kind, ls[e].klen, ls[i].kind, ls[i].klen) == 0) {
      if (EVP_DigestUpdate(ctx, ls[e].norm, ls[e].nlen) != 1 ||
          EVP_DigestUpdate(ctx, "\n", 1) != 1)
        goto out;
      e++;
    }
    unsigned char h[32];
    unsigned int hl = 0;
    if (EVP_DigestFinal_ex(ctx, h, &hl) != 1 || hl != 32) goto out;
    if (++kinds > SDG_KINDS_MAX) goto out;
    char hex[SDG_HEX + 1];
    for (int k = 0; k < 32; k++) snprintf(hex + 2 * k, 3, "%02x", h[k]);
    w = snprintf(out + at, cap - at, "s|%.*s|%zu|%s\n", (int)ls[i].klen, ls[i].kind, e - i, hex);
    if (w < 0 || (size_t)w >= cap - at) goto out;
    at += (size_t)w;
    i = e;
  }
  rc = (long)at;
out:
  if (ls)
    for (size_t i = 0; i < n; i++) free(ls[i].norm);
  free(ls);
  EVP_MD_CTX_free(ctx);
  return rc;
}

static bool sdg_hexok(const char *s, size_t n) {
  if (n != SDG_HEX) return false;
  for (size_t i = 0; i < n; i++)
    if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return false;
  return true;
}

/* A kind on the wire: 1..SDG_KIND_MAX bytes, no '|', ',', '\n' or NUL. */
static bool sdg_kindok(const char *s, size_t n) {
  if (n == 0 || n > SDG_KIND_MAX) return false;
  for (size_t i = 0; i < n; i++)
    if (s[i] == '|' || s[i] == ',' || s[i] == '\n' || s[i] == '\0') return false;
  return true;
}

int sdg_parse(const char *p, size_t len, sdg_entry_t *out, int max) {
  if (len < 4 || memcmp(p, "v|1\n", 4) != 0) return -1;
  int n = 0;
  for (size_t at = 4; at < len;) {
    const char *nl = memchr(p + at, '\n', len - at);
    if (!nl) return -1;
    size_t l = (size_t)(nl - (p + at));
    const char *s = p + at;
    at += l + 1;
    /* s|<kind>|<count>|<hex> */
    if (l < 2 || s[0] != 's' || s[1] != '|') return -1;
    const char *k = s + 2;
    const char *b1 = memchr(k, '|', l - 2);
    if (!b1) return -1;
    const char *c = b1 + 1;
    const char *b2 = memchr(c, '|', (size_t)(s + l - c));
    if (!b2) return -1;
    const char *h = b2 + 1;
    size_t kl = (size_t)(b1 - k), cl = (size_t)(b2 - c), hl = (size_t)(s + l - h);
    if (!sdg_kindok(k, kl) || cl == 0 || cl > 9 || !sdg_hexok(h, hl) || n >= max) return -1;
    long cnt = 0;
    for (size_t i = 0; i < cl; i++) {
      if (c[i] < '0' || c[i] > '9') return -1;
      cnt = cnt * 10 + (c[i] - '0');
    }
    memcpy(out[n].kind, k, kl);
    out[n].kind[kl] = '\0';
    if (n > 0 && strcmp(out[n - 1].kind, out[n].kind) >= 0) return -1; /* strictly ascending */
    out[n].count = cnt;
    memcpy(out[n].hex, h, SDG_HEX);
    out[n].hex[SDG_HEX] = '\0';
    n++;
  }
  return n;
}

int sdg_mismatch(const sdg_entry_t *a, int na, const sdg_entry_t *b, int nb,
                 char kinds[][SDG_KIND_MAX + 1], int max) {
  int i = 0, j = 0, n = 0;
  while (i < na || j < nb) {
    int c = i >= na ? 1 : j >= nb ? -1 : strcmp(a[i].kind, b[j].kind);
    const char *k;
    bool differ;
    if (c < 0) {
      k = a[i++].kind;
      differ = true;
    } else if (c > 0) {
      k = b[j++].kind;
      differ = true;
    } else {
      differ = a[i].count != b[j].count || strcmp(a[i].hex, b[j].hex) != 0;
      k = a[i].kind;
      i++;
      j++;
    }
    if (!differ) continue;
    if (n >= max) return -1;
    snprintf(kinds[n++], SDG_KIND_MAX + 1, "%s", k);
  }
  return n;
}

int sdg_parse_pull(const char *p, size_t len, char kinds[][SDG_KIND_MAX + 1], int max,
                   bool *all) {
  *all = false;
  if (len < 4 || memcmp(p, "r|", 2) != 0 || p[len - 1] != '\n') return -1;
  const char *s = p + 2;
  size_t l = len - 3;
  if (l == 1 && s[0] == '*') {
    *all = true;
    return 0;
  }
  int n = 0;
  for (size_t at = 0; at <= l;) {
    const char *c = memchr(s + at, ',', l - at);
    size_t kl = c ? (size_t)(c - (s + at)) : l - at;
    if (!sdg_kindok(s + at, kl) || n >= max) return -1;
    memcpy(kinds[n], s + at, kl);
    kinds[n][kl] = '\0';
    n++;
    if (!c) break;
    at += kl + 1;
  }
  return n;
}

long sdg_select(const char *packet, size_t len, char kinds[][SDG_KIND_MAX + 1], int nk,
                bool all, char *out, size_t cap) {
  if (cap == 0) return -1;
  size_t w = 0;
  for (size_t at = 0; at < len;) {
    const char *nl = memchr(packet + at, '\n', len - at);
    size_t l = nl ? (size_t)(nl - (packet + at)) : len - at;
    const char *line = packet + at;
    at += l + 1;
    if (l == 0) continue;
    size_t kl = sdg_klen(line, l);
    bool want = all;
    for (int i = 0; !want && i < nk; i++)
      want = strlen(kinds[i]) == kl && memcmp(kinds[i], line, kl) == 0;
    if (!want) continue;
    if (l + 2 > cap - w) return -1;
    memcpy(out + w, line, l);
    w += l;
    out[w++] = '\n';
  }
  out[w] = '\0';
  return (long)w;
}
