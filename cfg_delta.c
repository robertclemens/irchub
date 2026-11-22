/* cfg_delta.c — bot config text deltas (CMD_CONFIG_DELTA 0x91), 2.5.4.
 * Byte-identical in irchub and ircbot.  Spec and reference model:
 * ircbot-testnet/proto/cfgdelta/model.py — the Rust hub and bot mirror it in
 * cfg_delta.rs, and the testnet checks all of them against its vectors. */
#include "cfg_delta.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  const char *p;
  size_t len;     /* with its \n */
  uint64_t h;     /* FNV-1a 64 of the line: a cheap first comparison */
} cfgd_line_t;

static uint64_t cfgd_fnv(const char *p, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) {
    h ^= (unsigned char)p[i];
    h *= 0x100000001b3ULL;
  }
  return h;
}

/* Lines of t (each keeping its \n) into a new array; *n their count.  NULL
 * with *n 0 for an empty text; NULL with *n -1 for one not line framed or out
 * of memory. */
static cfgd_line_t *cfgd_split(const char *t, size_t len, long *n) {
  *n = 0;
  if (len == 0) return NULL;
  if (t[len - 1] != '\n') {
    *n = -1;
    return NULL;
  }
  /* At least one: the text ends in '\n' (gcc 8 cannot see it: -Walloc-zero). */
  long count = 0;
  for (size_t i = 0; i < len; i++)
    if (t[i] == '\n') count++;
  if (count < 1) {
    *n = -1;
    return NULL;
  }
  cfgd_line_t *ls = malloc((size_t)count * sizeof(*ls));
  if (!ls) {
    *n = -1;
    return NULL;
  }
  size_t at = 0;
  for (long k = 0; k < count; k++) {
    const char *nl = memchr(t + at, '\n', len - at);
    size_t l = (size_t)(nl - (t + at)) + 1;
    ls[k].p = t + at;
    ls[k].len = l;
    ls[k].h = cfgd_fnv(t + at, l);
    at += l;
  }
  *n = count;
  return ls;
}

static int cfgd_eq(const cfgd_line_t *a, const cfgd_line_t *b) {
  return a->h == b->h && a->len == b->len && memcmp(a->p, b->p, a->len) == 0;
}

/* Myers shortest edit script a[0..n) -> b[0..m) into ops ('K','D','I'), its
 * length in *olen.  Tie rule (model.py, both hubs): at diagonal k step down
 * (insert) when k == -d, or when k != d and V[k-1] < V[k+1]; else right
 * (delete).  0, or -1 past dmax edits / out of memory. */
static int cfgd_myers(const cfgd_line_t *a, long n, const cfgd_line_t *b, long m, int dmax,
                      char *ops, long *olen) {
  const long w = 2L * dmax + 3, off = dmax + 1;
  long *v = calloc((size_t)w, sizeof(long));
  long *trace = NULL;
  size_t tcap = 0;
  int rc = -1, dend = -1;
  long kend = 0;
  if (!v) return -1;
  for (int d = 0; d <= dmax && dend < 0; d++) {
    size_t need = ((size_t)d + 1) * (size_t)w;
    if (need > tcap) {
      size_t nc = tcap ? tcap * 2 : (size_t)w * 4;
      while (nc < need) nc *= 2;
      long *t2 = realloc(trace, nc * sizeof(long));
      if (!t2) goto out;
      trace = t2;
      tcap = nc;
    }
    memcpy(trace + (size_t)d * (size_t)w, v, (size_t)w * sizeof(long));
    for (long k = -d; k <= d; k += 2) {
      long x;
      if (k == -d || (k != d && v[off + k - 1] < v[off + k + 1]))
        x = v[off + k + 1];
      else
        x = v[off + k - 1] + 1;
      long y = x - k;
      while (x < n && y < m && cfgd_eq(&a[x], &b[y])) {
        x++;
        y++;
      }
      v[off + k] = x;
      if (x >= n && y >= m) {
        dend = d;
        kend = k;
        break;
      }
    }
  }
  if (dend < 0) goto out;
  (void)kend;
  /* Walk back: trace[d] is V as it stood before step d. */
  long x = n, y = m, o = 0;
  for (int dd = dend; dd >= 0; dd--) {
    const long *tv = trace + (size_t)dd * (size_t)w;
    long k = x - y, pk;
    if (k == -dd || (k != dd && tv[off + k - 1] < tv[off + k + 1]))
      pk = k + 1;
    else
      pk = k - 1;
    long px = tv[off + pk], py = px - pk;
    while (x > px && y > py) {
      ops[o++] = 'K';
      x--;
      y--;
    }
    if (dd > 0) {
      if (x == px) {
        ops[o++] = 'I';
        y--;
      } else {
        ops[o++] = 'D';
        x--;
      }
    }
    x = px;
    y = py;
  }
  for (long i = 0, j = o - 1; i < j; i++, j--) {
    char c = ops[i];
    ops[i] = ops[j];
    ops[j] = c;
  }
  *olen = o;
  rc = 0;
out:
  free(trace);
  free(v);
  return rc;
}

static int cfgd_put(char *out, size_t cap, size_t *at, const char *s, size_t n) {
  if (n > cap - *at) return -1;
  memcpy(out + *at, s, n);
  *at += n;
  return 0;
}

static int cfgd_putn(char *out, size_t cap, size_t *at, char op, long n) {
  char tmp[24];
  int l = snprintf(tmp, sizeof(tmp), "%c%ld\n", op, n);
  return (l > 0 && (size_t)l < sizeof(tmp)) ? cfgd_put(out, cap, at, tmp, (size_t)l) : -1;
}

long cfgd_diff(const char *base, size_t blen, const char *nw, size_t nlen,
               const char base_hex[CFGD_HASH_HEX], const char new_hex[CFGD_HASH_HEX],
               char *out, size_t cap) {
  long n = 0, m = 0, rc = -1;
  char *ops = NULL;
  cfgd_line_t *a = cfgd_split(base, blen, &n);
  cfgd_line_t *b = cfgd_split(nw, nlen, &m);
  if (n < 0 || m < 0) goto out;
  for (long j = 0; j < m; j++)
    if (b[j].len - 1 > CFG_DELTA_LINE_MAX || memchr(b[j].p, '\0', b[j].len)) goto out;
  /* Keep the common prefix and suffix as they are; Myers on the middle. */
  long p = 0, q = 0;
  while (p < n && p < m && cfgd_eq(&a[p], &b[p])) p++;
  while (q < n - p && q < m - p && cfgd_eq(&a[n - 1 - q], &b[m - 1 - q])) q++;
  ops = malloc((size_t)(n + m) + 1);
  if (!ops) goto out;
  long mid = 0;
  if (cfgd_myers(a + p, n - p - q, b + p, m - p - q, CFG_DELTA_MAX_EDITS, ops + p, &mid) != 0)
    goto out;
  memset(ops, 'K', (size_t)p);
  memset(ops + p + mid, 'K', (size_t)q);
  long total = p + mid + q;

  size_t at = 0;
  if (cfgd_put(out, cap, &at, base_hex, CFGD_HASH_HEX) || cfgd_put(out, cap, &at, "|", 1) ||
      cfgd_put(out, cap, &at, new_hex, CFGD_HASH_HEX) || cfgd_put(out, cap, &at, "\n", 1))
    goto out;
  long j = 0;
  for (long i = 0; i < total;) {
    if (ops[i] == 'K') {
      long e = i;
      while (e < total && ops[e] == 'K') e++;
      if (cfgd_putn(out, cap, &at, '=', e - i)) goto out;
      j += e - i;
      i = e;
      continue;
    }
    /* A hunk: every delete before every insert. */
    long e = i, dels = 0, ins = 0;
    while (e < total && ops[e] != 'K') {
      if (ops[e] == 'D') dels++;
      else ins++;
      e++;
    }
    if (dels && cfgd_putn(out, cap, &at, '-', dels)) goto out;
    for (long t = 0; t < ins; t++, j++)
      if (cfgd_put(out, cap, &at, "+", 1) || cfgd_put(out, cap, &at, b[j].p, b[j].len)) goto out;
    i = e;
  }
  if (j != m) goto out;
  if ((unsigned long long)at * 100ULL >= (unsigned long long)nlen * CFG_DELTA_MAX_PCT) goto out;
  rc = (long)at;
out:
  free(ops);
  free(a);
  free(b);
  return rc;
}

static int cfgd_is_hex(const char *s, size_t n) {
  for (size_t i = 0; i < n; i++)
    if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return 0;
  return 1;
}

int cfgd_header(const char *payload, size_t plen, char *base_hex, char *new_hex) {
  if (!payload || plen < CFGD_HEADER_LEN || payload[CFGD_HASH_HEX] != '|' ||
      payload[CFGD_HEADER_LEN - 1] != '\n' || !cfgd_is_hex(payload, CFGD_HASH_HEX) ||
      !cfgd_is_hex(payload + CFGD_HASH_HEX + 1, CFGD_HASH_HEX))
    return -1;
  memcpy(base_hex, payload, CFGD_HASH_HEX);
  memcpy(new_hex, payload + CFGD_HASH_HEX + 1, CFGD_HASH_HEX);
  return 0;
}

/* A count: decimal, 1..cap, no sign, no leading zero, at most 10 digits. */
static long cfgd_count(const char *s, size_t n, long cap) {
  if (n == 0 || n > 10 || (n > 1 && s[0] == '0')) return -1;
  unsigned long long v = 0;
  for (size_t i = 0; i < n; i++) {
    if (s[i] < '0' || s[i] > '9') return -1;
    v = v * 10 + (unsigned)(s[i] - '0');
  }
  return (v >= 1 && v <= (unsigned long long)cap) ? (long)v : -1;
}

long cfgd_patch(const char *held, size_t hlen, const char *payload, size_t plen,
                char *out, size_t cap, const char **why) {
  static const char *unset = "?";
  const char *dummy;
  if (!why) why = &dummy;
  *why = unset;
  if (plen < CFGD_HEADER_LEN) {
    *why = "bad header";
    return -1;
  }
  if (hlen && held[hlen - 1] != '\n') {
    *why = "held text not line framed";
    return -1;
  }
  long total = 0;
  for (size_t i = 0; i < hlen; i++)
    if (held[i] == '\n') total++;
  long used = 0;
  size_t hat = 0, at = 0;
  size_t p = CFGD_HEADER_LEN;
  while (p < plen) {
    const char *e = memchr(payload + p, '\n', plen - p);
    if (!e) {
      *why = "unterminated op";
      return -1;
    }
    size_t olen = (size_t)(e - (payload + p));
    const char *op = payload + p;
    p += olen + 1;
    if (olen == 0) {
      *why = "empty op";
      return -1;
    }
    if (op[0] == '=' || op[0] == '-') {
      long cnt = cfgd_count(op + 1, olen - 1, total - used);
      if (cnt < 0) {
        *why = "bad count";
        return -1;
      }
      size_t from = hat;
      for (long k = 0; k < cnt; k++) {
        const char *nl = memchr(held + hat, '\n', hlen - hat);
        hat = (size_t)(nl - held) + 1;
      }
      if (op[0] == '=') {
        if (hat - from > cap - at) {
          *why = "too large";
          return -1;
        }
        memcpy(out + at, held + from, hat - from);
        at += hat - from;
      }
      used += cnt;
    } else if (op[0] == '+') {
      size_t l = olen - 1;
      if (l > CFG_DELTA_LINE_MAX) {
        *why = "line too long";
        return -1;
      }
      if (memchr(op + 1, '\0', l)) {
        *why = "bad byte";
        return -1;
      }
      if (l + 1 > cap - at) {
        *why = "too large";
        return -1;
      }
      memcpy(out + at, op + 1, l);
      at += l;
      out[at++] = '\n';
    } else {
      *why = "bad op";
      return -1;
    }
  }
  if (used != total) {
    *why = "base not consumed";
    return -1;
  }
  return (long)at;
}
