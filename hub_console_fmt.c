/* SSH admin console — the output renderer.  hub_console_fmt.h; the style
 * rules are docs/console.md §3.5.
 *
 * Runs on the console thread.  Every function here is a pure function of the
 * records, the context (width, glyphs, clock) and nothing else, so the Rust
 * console (src/console/fmt.rs) can reproduce it byte for byte: no locale, no
 * floating point, no time zone (UTC throughout). */
#include "hub_console_fmt.h"
#include <ctype.h>
#include <stdarg.h>
#include <strings.h>

/* ==========================================================================
 * Parsing (docs/console.md §3.1)
 * ========================================================================== */
static char *dupn(const char *s, size_t n) {
  char *p = malloc(n + 1);
  if (!p) return NULL;
  memcpy(p, s, n);
  p[n] = '\0';
  return p;
}

/* %25 %7C %0A %0D back to their bytes, then the sanitizer (§5). */
static char *unescape_clean(const char *s, size_t n) {
  char *u = malloc(n + 1);
  if (!u) return NULL;
  size_t o = 0;
  for (size_t i = 0; i < n; i++) {
    if (s[i] == '%' && i + 2 < n) {
      char a = s[i + 1], b = s[i + 2];
      char c = 0;
      if (a == '2' && b == '5') c = '%';
      else if (a == '7' && (b == 'C' || b == 'c')) c = '|';
      else if (a == '0' && (b == 'A' || b == 'a')) c = '\n';
      else if (a == '0' && (b == 'D' || b == 'd')) c = '\r';
      if (c) {
        u[o++] = c;
        i += 2;
        continue;
      }
    }
    u[o++] = s[i];
  }
  char *out = malloc(o + 1);
  if (!out) {
    free(u);
    return NULL;
  }
  console_sanitize(u, o, out, o + 1);
  free(u);
  return out;
}

static char *clean_dup(const char *s, size_t n) {
  char *out = malloc(n + 1);
  if (!out) return NULL;
  console_sanitize(s, n, out, n + 1);
  return out;
}

static void rec_add(crec_t *r, char *k, char *v) {
  char **nk = realloc(r->k, sizeof(char *) * (size_t)(r->n + 1));
  if (!nk) { free(k); free(v); return; }
  r->k = nk;
  char **nv = realloc(r->v, sizeof(char *) * (size_t)(r->n + 1));
  if (!nv) { free(k); free(v); return; }
  r->v = nv;
  r->k[r->n] = k;
  r->v[r->n] = v;
  r->n++;
}

/* One "type|k=v|k=v" line; `kv` false keeps the fields positional (the
 * tree rows), stored as keys "0", "1", …. */
static void parse_rec(const char *s, size_t n, crec_t *r, bool kv) {
  memset(r, 0, sizeof(*r));
  r->line = clean_dup(s, n);
  size_t i = 0, start = 0;
  int field = 0;
  for (;; i++) {
    if (i < n && s[i] != '|') continue;
    const char *f = s + start;
    size_t fl = i - start;
    if (field == 0) {
      r->type = clean_dup(f, fl);
    } else if (kv) {
      const char *eq = memchr(f, '=', fl);
      if (eq) rec_add(r, clean_dup(f, (size_t)(eq - f)), unescape_clean(eq + 1, fl - (size_t)(eq - f) - 1));
      else rec_add(r, clean_dup(f, fl), dupn("", 0));
    } else {
      char key[12];
      snprintf(key, sizeof(key), "%d", field - 1);
      rec_add(r, dupn(key, strlen(key)), clean_dup(f, fl));
    }
    field++;
    if (i >= n) break;
    start = i + 1;
  }
  if (!r->type) r->type = dupn("", 0);
}

void creply_parse(const char *text, size_t len, creply_t *out) {
  memset(out, 0, sizeof(*out));
  size_t end = len;
  while (end > 0 && (text[end - 1] == '\n' || text[end - 1] == '\r')) end--;
  bool first = true, rows = false;
  for (size_t i = 0; i < end;) {
    size_t j = i;
    while (j < end && text[j] != '\n') j++;
    size_t n = j - i;
    if (n > 0 && text[i + n - 1] == '\r') n--;
    if (first) {
      first = false;
      if ((n >= 3 && memcmp(text + i, "ok|", 3) == 0) ||
          (n >= 4 && memcmp(text + i, "err|", 4) == 0)) {
        parse_rec(text + i, n, &out->res, true);
        out->ok = out->res.type[0] == 'o';
        out->err = !out->ok;
        /* the code is the first field after the type: it was parsed as a
         * key without '=' */
        if (out->res.n > 0 && out->res.v[0][0] == '\0') {
          out->code = out->res.k[0];
          out->res.k[0] = dupn("", 0);
        }
        if (!out->code) out->code = dupn("", 0);
        rows = !strcmp(out->code, "network.tree");
        i = j + 1;
        continue;
      }
      out->code = dupn("", 0);
    }
    crec_t *nr = realloc(out->r, sizeof(crec_t) * (size_t)(out->n + 1));
    if (!nr) break;
    out->r = nr;
    parse_rec(text + i, n, &out->r[out->n], !rows);
    out->n++;
    i = j + 1;
  }
  if (!out->code) out->code = dupn("", 0);
  if (!out->res.type) out->res.type = dupn("", 0);
}

static void rec_free(crec_t *r) {
  for (int i = 0; i < r->n; i++) {
    free(r->k[i]);
    free(r->v[i]);
  }
  free(r->k);
  free(r->v);
  free(r->type);
  free(r->line);
  memset(r, 0, sizeof(*r));
}

void creply_free(creply_t *rep) {
  rec_free(&rep->res);
  for (int i = 0; i < rep->n; i++) rec_free(&rep->r[i]);
  free(rep->r);
  free(rep->code);
  memset(rep, 0, sizeof(*rep));
}

const char *rv(const crec_t *rec, const char *key) {
  for (int i = 0; rec && i < rec->n; i++)
    if (!strcmp(rec->k[i], key)) return rec->v[i];
  return NULL;
}

long long rvi(const crec_t *rec, const char *key, long long dflt) {
  const char *v = rv(rec, key);
  if (!v || !*v) return dflt;
  char *e = NULL;
  long long x = strtoll(v, &e, 10);
  return (e && *e == '\0') ? x : dflt;
}

bool rvb(const crec_t *rec, const char *key) { return rvi(rec, key, 0) != 0; }

/* A value that is present and not empty. */
const char *rvs(const crec_t *rec, const char *key) {
  const char *v = rv(rec, key);
  return v && *v ? v : NULL;
}

/* ==========================================================================
 * Output lines and the line builder
 * ========================================================================== */
void flines_add(flines_t *o, int role, const char *text) {
  if (o->n == o->cap) {
    int cap = o->cap ? o->cap * 2 : 32;
    fline_t *nv = realloc(o->v, sizeof(fline_t) * (size_t)cap);
    if (!nv) return;
    o->v = nv;
    o->cap = cap;
  }
  /* trailing blanks never reach the screen */
  size_t n = strlen(text);
  while (n > 0 && text[n - 1] == ' ') n--;
  char *t = dupn(text, n);
  if (!t) return;
  o->v[o->n].text = t;
  o->v[o->n].role = role;
  o->n++;
}

void flines_free(flines_t *o) {
  for (int i = 0; i < o->n; i++) free(o->v[i].text);
  free(o->v);
  memset(o, 0, sizeof(*o));
}

typedef struct {
  char  *p;
  size_t len, cap;
  int    w;      /* display cells */
} sb_t;

static void sb_addn(sb_t *b, const char *s, size_t n) {
  if (b->len + n + 1 > b->cap) {
    size_t cap = b->cap ? b->cap : 128;
    while (cap < b->len + n + 1) cap *= 2;
    char *np = realloc(b->p, cap);
    if (!np) return;
    b->p = np;
    b->cap = cap;
  }
  memcpy(b->p + b->len, s, n);
  b->len += n;
  b->p[b->len] = '\0';
  for (size_t i = 0; i < n;) {
    unsigned cp;
    int w;
    i += console_next_char(s + i, n - i, &cp, &w);
    b->w += w;
  }
}

/* NULL adds nothing (a record that lacks the key a card line shows). */
static void sb_add(sb_t *b, const char *s) {
  if (s) sb_addn(b, s, strlen(s));
}

static void sb_addf(sb_t *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void sb_addf(sb_t *b, const char *fmt, ...) {
  char tmp[512];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
  va_end(ap);
  if (n < 0) return;
  if ((size_t)n < sizeof(tmp)) {
    sb_addn(b, tmp, (size_t)n);
    return;
  }
  char *big = malloc((size_t)n + 1);
  if (!big) return;
  va_start(ap, fmt);
  vsnprintf(big, (size_t)n + 1, fmt, ap);
  va_end(ap);
  sb_addn(b, big, (size_t)n);
  free(big);
}

static void sb_pad(sb_t *b, int col) {
  while (b->w < col) sb_addn(b, " ", 1);
}

static void sb_rep(sb_t *b, const char *g, int n) {
  for (int i = 0; i < n; i++) sb_add(b, g);
}

static void sb_reset(sb_t *b) {
  b->len = 0;
  b->w = 0;
  if (b->p) b->p[0] = '\0';
}

static void sb_emit(sb_t *b, flines_t *out, int role) {
  flines_add(out, role, b->p ? b->p : "");
  sb_reset(b);
}

static void sb_free(sb_t *b) {
  free(b->p);
  memset(b, 0, sizeof(*b));
}

/* ==========================================================================
 * Glyphs and value formats
 * ========================================================================== */
static const char *const GLYPH_U[G_COUNT] = {
  "─", "●", "○", "◐", "✓", "✗", "▲", "•", "…", "·", "→", "├", "└", "│", "—",
  "×", "█", "░", "▾", "?"};
static const char *const GLYPH_A[G_COUNT] = {
  "-", "*", "o", "~", "+", "x", "!", "-", "~", "|", "->", "|", "`", "|", "-",
  "x", "#", ".", "v", "?"};

const char *fmt_glyph(const fmt_ctx_t *ctx, int g) {
  if (g < 0 || g >= G_COUNT) return "?";
  return ctx->ascii ? GLYPH_A[g] : GLYPH_U[g];
}
#define GL(g) fmt_glyph(ctx, (g))

/* The ASCII stand-in for one character at s (display ascii): a glyph of
 * GLYPH_U becomes its GLYPH_A ("←" "<-"); any other non-ASCII character
 * becomes one '?' per cell, a zero-width one nothing.  *len gets the bytes
 * of s it covers; NULL return = s[0] is ASCII, keep it. */
const char *fmt_ascii_char(const char *s, size_t n, size_t *len) {
  static const char *const Q[3] = {"", "?", "??"};
  unsigned cp;
  int w;
  *len = console_next_char(s, n, &cp, &w);
  if ((unsigned char)s[0] < 0x80) return NULL;
  for (int g = 0; g < G_COUNT; g++)
    if (strlen(GLYPH_U[g]) == *len && !memcmp(GLYPH_U[g], s, *len)) return GLYPH_A[g];
  if (*len == 3 && !memcmp(s, "←", 3)) return "<-";
  return Q[w < 0 ? 0 : w > 2 ? 2 : w];
}

/* A whole line through fmt_ascii_char; malloc'd, NULL on OOM. */
char *fmt_ascii(const char *s) {
  size_t n = strlen(s), cap = n * 2 + 1, o = 0;
  char *out = malloc(cap);
  if (!out) return NULL;
  for (size_t i = 0; i < n;) {
    size_t l;
    const char *r = fmt_ascii_char(s + i, n - i, &l);
    if (!r) {
      out[o++] = s[i];
    } else {
      size_t rl = strlen(r);           /* ≤ 2 bytes for ≥ 2 bytes in: fits */
      memcpy(out + o, r, rl);
      o += rl;
    }
    i += l ? l : 1;
  }
  out[o] = '\0';
  return out;
}

/* Days since 1970-01-01 to a civil date (proleptic Gregorian). */
static void civil(long long days, int *y, int *m, int *d) {
  long long z = days + 719468;
  long long era = (z >= 0 ? z : z - 146096) / 146097;
  long long doe = z - era * 146097;
  long long yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  long long yy = yoe + era * 400;
  long long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  long long mp = (5 * doy + 2) / 153;
  *d = (int)(doy - (153 * mp + 2) / 5 + 1);
  *m = (int)(mp < 10 ? mp + 3 : mp - 9);
  *y = (int)(yy + (*m <= 2));
}

static long long floordiv(long long a, long long b) {
  long long q = a / b;
  return (a % b != 0 && ((a < 0) != (b < 0))) ? q - 1 : q;
}

static const char *const MONTH[12] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

/* 14:02:11Z today, Oct 02 14:02Z this year, 2025-12-30 before; never for 0. */
void fmt_when(long long ts, long long now, char *out, size_t cap) {
  if (ts <= 0) {
    snprintf(out, cap, "never");
    return;
  }
  long long day = floordiv(ts, 86400), sec = ts - day * 86400;
  long long nday = floordiv(now, 86400);
  int y, m, d, ny, nm, nd;
  civil(day, &y, &m, &d);
  civil(nday, &ny, &nm, &nd);
  int hh = (int)(sec / 3600), mm = (int)(sec / 60 % 60), ss = (int)(sec % 60);
  if (day == nday)
    snprintf(out, cap, "%02d:%02d:%02dZ", hh, mm, ss);
  else if (y == ny)
    snprintf(out, cap, "%s %02d %02d:%02dZ", MONTH[m - 1], d, hh, mm);
  else
    snprintf(out, cap, "%04d-%02d-%02d", y, m, d);
}

/* 42s, 7m, 3h 12m, 5d 03h */
void fmt_span(long long s, char *out, size_t cap) {
  if (s < 0) s = 0;
  if (s < 60) snprintf(out, cap, "%llds", s);
  else if (s < 3600) snprintf(out, cap, "%lldm", s / 60);
  else if (s < 86400) snprintf(out, cap, "%lldh %02lldm", s / 3600, s / 60 % 60);
  else snprintf(out, cap, "%lldd %02lldh", s / 86400, s / 3600 % 24);
}

/* 3d 04h 12m — an uptime with one more unit */
static void fmt_dur3(long long s, char *out, size_t cap) {
  if (s < 0) s = 0;
  if (s < 60) snprintf(out, cap, "%llds", s);
  else if (s < 3600) snprintf(out, cap, "%lldm %02llds", s / 60, s % 60);
  else if (s < 86400) snprintf(out, cap, "%lldh %02lldm", s / 3600, s / 60 % 60);
  else snprintf(out, cap, "%lldd %02lldh %02lldm", s / 86400, s / 3600 % 24, s / 60 % 60);
}

/* 512 B, 86.2 KiB, 12.0 MiB, 1.31 GiB */
void fmt_bytes(unsigned long long n, char *out, size_t cap) {
  static const char *const U[] = {"KiB", "MiB", "GiB", "TiB"};
  if (n < 1024) {
    snprintf(out, cap, "%llu B", n);
    return;
  }
  int u = 0;
  unsigned long long d = 1024;
  while (u < 3 && n >= d * 1024) {
    d *= 1024;
    u++;
  }
  if (u >= 2) {
    unsigned long long v = n / d * 100 + ((n % d) * 100 + d / 2) / d;
    snprintf(out, cap, "%llu.%02llu %s", v / 100, v % 100, U[u]);
  } else {
    unsigned long long v = n / d * 10 + ((n % d) * 10 + d / 2) / d;
    snprintf(out, cap, "%llu.%llu %s", v / 10, v % 10, U[u]);
  }
}

/* 1,402,881 */
void fmt_count(unsigned long long n, char *out, size_t cap) {
  char d[32];
  int l = snprintf(d, sizeof(d), "%llu", n);
  size_t o = 0;
  for (int i = 0; i < l && o + 2 < cap; i++) {
    if (i > 0 && (l - i) % 3 == 0) out[o++] = ',';
    out[o++] = d[i];
  }
  out[o] = '\0';
}

static const char *const LEVEL_NAME[] = {"none", "error", "warning", "info", "debug"};
static const char *level_name(long long l) {
  return l >= 0 && l <= 4 ? LEVEL_NAME[l] : "?";
}

/* "1 hub link" / "3 hub links" */
static void plural(char *out, size_t cap, long long n, const char *one, const char *many) {
  snprintf(out, cap, "%lld %s", n, n == 1 ? one : many);
}

/* Case-insensitive ASCII order, then bytes. */
static int ci_cmp(const char *a, const char *b) {
  for (;; a++, b++) {
    int ca = tolower((unsigned char)*a), cb = tolower((unsigned char)*b);
    if (ca != cb || !ca) return ca - cb;
  }
}

/* ==========================================================================
 * Blocks: title rule, result, note, card line (§3.5 building blocks)
 * ========================================================================== */
void fmt_title(const fmt_ctx_t *ctx, flines_t *out, const char *title,
               const char *right) {
  sb_t b = {0};
  int W = ctx->width;
  int tw = console_str_width(title);
  int rw = right && *right ? console_str_width(right) : 0;
  sb_add(&b, " ");
  sb_add(&b, title);
  sb_add(&b, " ");
  int fill = W - (tw + 2) - (rw ? rw + 1 : 0);
  if (fill >= 3) {
    sb_rep(&b, GL(G_RULE), fill);
    if (rw) {
      sb_add(&b, " ");
      sb_add(&b, right);
    }
    sb_emit(&b, out, RL_TITLE);
  } else {
    sb_rep(&b, GL(G_RULE), W - (tw + 2) >= 3 ? W - (tw + 2) : 3);
    sb_emit(&b, out, RL_TITLE);
    if (rw) {
      sb_add(&b, "  ");
      sb_add(&b, right);
      sb_emit(&b, out, RL_DIM);
    }
  }
  sb_free(&b);
}

static void rule_line(const fmt_ctx_t *ctx, flines_t *out) {
  sb_t b = {0};
  sb_add(&b, " ");
  sb_rep(&b, GL(G_RULE), ctx->width - 1 > 3 ? ctx->width - 1 : 3);
  sb_emit(&b, out, RL_RULE);
  sb_free(&b);
}

static void line(flines_t *out, int role, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void line(flines_t *out, int role, const char *fmt, ...) {
  char tmp[1024];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
  va_end(ap);
  if (n < 0) return;
  if ((size_t)n < sizeof(tmp)) {
    flines_add(out, role, tmp);
    return;
  }
  char *big = malloc((size_t)n + 1);
  if (!big) return;
  va_start(ap, fmt);
  vsnprintf(big, (size_t)n + 1, fmt, ap);
  va_end(ap);
  flines_add(out, role, big);
  free(big);
}

/* " ✓ What   subject" */
void fmt_ok(const fmt_ctx_t *ctx, const char *what, const char *subject, flines_t *out) {
  if (subject && *subject) line(out, RL_OK, " %s %s   %s", GL(G_OK), what, subject);
  else line(out, RL_OK, " %s %s", GL(G_OK), what);
}

void fmt_error(const fmt_ctx_t *ctx, const char *msg, const char *hint, flines_t *out) {
  line(out, RL_ERR, " %s %s", GL(G_ERR), msg && *msg ? msg : "failed");
  if (hint && *hint) line(out, RL_DIM, "   hint  %s", hint);
}

static void effect(const fmt_ctx_t *ctx, flines_t *out, const char *text) {
  line(out, RL_NORMAL, "   %s %s", GL(G_BULLET), text);
}

static void warn(const fmt_ctx_t *ctx, flines_t *out, const char *text) {
  line(out, RL_WARN, "   %s %s", GL(G_WARN), text);
}

static void hint(flines_t *out, const char *text) { line(out, RL_DIM, "   hint  %s", text); }

/* "  label   value", labels padded to label_w */
void fmt_card_line(const fmt_ctx_t *ctx, flines_t *out, int label_w, const char *label,
                   const char *value, int role) {
  (void)ctx;
  sb_t b = {0};
  sb_add(&b, "  ");
  sb_add(&b, label);
  sb_pad(&b, 2 + label_w + 2);
  sb_add(&b, value);
  sb_emit(&b, out, role);
  sb_free(&b);
}

/* A result's own card lines: "   key         value" */
static void res_kv(flines_t *out, const char *label, const char *value) {
  sb_t b = {0};
  sb_add(&b, "   ");
  sb_add(&b, label);
  sb_pad(&b, 15);
  sb_add(&b, value);
  sb_emit(&b, out, RL_NORMAL);
  sb_free(&b);
}

static void empty_note(flines_t *out, const char *text, const char *hint_text) {
  line(out, RL_DIM, "  (%s)", text);
  if (hint_text) hint(out, hint_text);
}

/* Keys a renderer already showed; any other key of the record is shown
 * after them as "key  value" (rule 11: a newer hub never hides data). */
static void unknown_keys(const fmt_ctx_t *ctx, flines_t *out, const crec_t *r,
                         const char *const *known, int label_w) {
  for (int i = 0; i < r->n; i++) {
    bool k = !r->k[i][0];
    for (int j = 0; known[j] && !k; j++) k = !strcmp(known[j], r->k[i]);
    if (!k) fmt_card_line(ctx, out, label_w, r->k[i], r->v[i][0] ? r->v[i] : GL(G_DASH),
                          RL_NORMAL);
  }
}

/* ==========================================================================
 * Tables: wide → stacked → cards (§1.4; every layout has every field)
 * ========================================================================== */
#define TBL_MAX_COLS 16

typedef struct {
  const char *head;
  char        align;   /* 'L' or 'R' */
  int         line;    /* 1 or 2: where it goes when the table is stacked */
} col_t;

typedef struct {
  const col_t *cols;
  int          nc;
  char       **cells;  /* nr * nc */
  int         *roles;
  char       **right;  /* cards: the text on a row's title rule */
  int          nr, cap;
  int          indent;
  int          gap_after_badge;
  int          badge;  /* column holding a status glyph, -1 = none */
  int          title;  /* column that names the object (cards) */
  int          l2_at;  /* stacked: line 2 starts under this column */
} tbl_t;

static void tbl_init(tbl_t *t, const col_t *cols, int nc, int badge, int title, int l2_at) {
  memset(t, 0, sizeof(*t));
  t->cols = cols;
  t->nc = nc;
  t->indent = 2;
  t->badge = badge;
  t->title = title;
  t->l2_at = l2_at;
}

/* Append a row; cells are copied (NULL or "" become the dash). */
static void tbl_row(const fmt_ctx_t *ctx, tbl_t *t, int role, const char *right,
                    const char *const *cells) {
  if (t->nr == t->cap) {
    int cap = t->cap ? t->cap * 2 : 16;
    char **nc = realloc(t->cells, sizeof(char *) * (size_t)(cap * t->nc));
    if (!nc) return;
    t->cells = nc;
    int *nr = realloc(t->roles, sizeof(int) * (size_t)cap);
    if (!nr) return;
    t->roles = nr;
    char **rt = realloc(t->right, sizeof(char *) * (size_t)cap);
    if (!rt) return;
    t->right = rt;
    t->cap = cap;
  }
  for (int c = 0; c < t->nc; c++) {
    const char *s = cells[c] && *cells[c] ? cells[c] : GL(G_DASH);
    t->cells[t->nr * t->nc + c] = dupn(s, strlen(s));
  }
  t->roles[t->nr] = role;
  t->right[t->nr] = right ? dupn(right, strlen(right)) : NULL;
  t->nr++;
}

static void tbl_free(tbl_t *t) {
  for (int i = 0; i < t->nr * t->nc; i++) free(t->cells[i]);
  for (int i = 0; i < t->nr; i++) free(t->right[i]);
  free(t->cells);
  free(t->roles);
  free(t->right);
  memset(t, 0, sizeof(*t));
}

static int col_gap(const tbl_t *t, int prev) {
  return prev == t->badge ? 1 : 2;
}

/* One line of the given columns (mask: line 1 or 2, 0 = all). */
static int tbl_line_width(const tbl_t *t, const int *w, int which, int x0) {
  int x = x0, prev = -1;
  for (int c = 0; c < t->nc; c++) {
    if (which && t->cols[c].line != which) continue;
    if (prev >= 0) x += col_gap(t, prev);
    x += w[c];
    prev = c;
  }
  return x;
}

static void tbl_put(const tbl_t *t, sb_t *b, const int *w, int which, int x0,
                    const char *const *cells) {
  int prev = -1;
  sb_pad(b, x0);
  for (int c = 0; c < t->nc; c++) {
    if (which && t->cols[c].line != which) continue;
    if (prev >= 0) sb_rep(b, " ", col_gap(t, prev));
    int start = b->w;
    const char *s = cells[c];
    if (t->cols[c].align == 'R') {
      sb_pad(b, start + w[c] - console_str_width(s));
      sb_add(b, s);
    } else {
      sb_add(b, s);
      sb_pad(b, start + w[c]);
    }
    prev = c;
  }
}

/* x of column `col` in a line-1 layout */
static int tbl_x_of(const tbl_t *t, const int *w, int col) {
  int x = t->indent, prev = -1;
  for (int c = 0; c < t->nc; c++) {
    if (t->cols[c].line != 1) continue;
    if (prev >= 0) x += col_gap(t, prev);
    if (c == col) return x;
    x += w[c];
    prev = c;
  }
  return t->indent;
}

static void tbl_render(const fmt_ctx_t *ctx, flines_t *out, const tbl_t *t) {
  int W = ctx->width;
  int *w = calloc((size_t)t->nc, sizeof(int));
  const char **heads = calloc((size_t)t->nc, sizeof(char *));
  if (!w || !heads) {
    free(w);
    free(heads);
    return;
  }
  for (int c = 0; c < t->nc; c++) {
    heads[c] = t->cols[c].head;
    w[c] = console_str_width(t->cols[c].head);
    for (int r = 0; r < t->nr; r++) {
      int cw = console_str_width(t->cells[r * t->nc + c]);
      if (cw > w[c]) w[c] = cw;
    }
  }
  sb_t b = {0};
  int wide = tbl_line_width(t, w, 0, t->indent);
  int l2x = tbl_x_of(t, w, t->l2_at);
  int st1 = tbl_line_width(t, w, 1, t->indent), st2 = tbl_line_width(t, w, 2, l2x);
  bool has2 = false;
  for (int c = 0; c < t->nc; c++) has2 |= t->cols[c].line == 2;
  if (wide <= W || (!has2 && W >= CONSOLE_WIDTH_MIN)) {
    tbl_put(t, &b, w, 0, t->indent, heads);
    sb_emit(&b, out, RL_HEAD);
    for (int r = 0; r < t->nr; r++) {
      tbl_put(t, &b, w, 0, t->indent, (const char *const *)&t->cells[r * t->nc]);
      sb_emit(&b, out, t->roles[r]);
    }
  } else if (W >= CONSOLE_WIDTH_MIN && st1 <= W && st2 <= W) {
    tbl_put(t, &b, w, 1, t->indent, heads);
    sb_emit(&b, out, RL_HEAD);
    tbl_put(t, &b, w, 2, l2x, heads);
    sb_emit(&b, out, RL_HEAD);
    for (int r = 0; r < t->nr; r++) {
      tbl_put(t, &b, w, 1, t->indent, (const char *const *)&t->cells[r * t->nc]);
      sb_emit(&b, out, t->roles[r]);
      tbl_put(t, &b, w, 2, l2x, (const char *const *)&t->cells[r * t->nc]);
      sb_emit(&b, out, t->roles[r] == RL_NORMAL ? RL_NORMAL : t->roles[r]);
    }
  } else {
    /* cards: one block per row, every column a "label value" line */
    int lw = 0;
    char low[TBL_MAX_COLS][40];
    for (int c = 0; c < t->nc && c < TBL_MAX_COLS; c++) {
      size_t i = 0;
      for (; t->cols[c].head[i] && i < sizeof(low[c]) - 1; i++)
        low[c][i] = (char)tolower((unsigned char)t->cols[c].head[i]);
      low[c][i] = '\0';
      if (c != t->badge && c != t->title && console_str_width(low[c]) > lw)
        lw = console_str_width(low[c]);
    }
    for (int r = 0; r < t->nr; r++) {
      char **cells = &t->cells[r * t->nc];
      sb_reset(&b);
      if (t->badge >= 0) {
        sb_add(&b, cells[t->badge]);
        sb_add(&b, " ");
      }
      sb_add(&b, cells[t->title]);
      fmt_title(ctx, out, b.p, t->right[r]);
      sb_reset(&b);
      for (int c = 0; c < t->nc; c++) {
        if (c == t->badge || c == t->title) continue;
        fmt_card_line(ctx, out, lw, low[c], cells[c], t->roles[r] == RL_DIM ? RL_DIM : RL_NORMAL);
      }
    }
  }
  sb_free(&b);
  free(w);
  free(heads);
}

/* ==========================================================================
 * Shared value phrases
 * ========================================================================== */
static void peers_phrase(char *out, size_t cap, long long peers) {
  if (peers <= 0) snprintf(out, cap, "no other hub is linked now; they catch up on their next sync");
  else snprintf(out, cap, "synced to %lld other hub%s", peers, peers == 1 ? "" : "s");
}

static void sync_push_phrase(char *out, size_t cap, long long peers, long long bots) {
  char p[96];
  if (peers <= 0) snprintf(p, sizeof(p), "no other hub linked");
  else snprintf(p, sizeof(p), "synced to %lld other hub%s", peers, peers == 1 ? "" : "s");
  snprintf(out, cap, "%s; pushed to %lld bot%s", p, bots, bots == 1 ? "" : "s");
}

/* "Oct 03 22:10Z · 15h" */
static void when_ago(const fmt_ctx_t *ctx, long long ts, char *out, size_t cap) {
  char w[32], s[32];
  if (ts <= 0) {
    snprintf(out, cap, "never");
    return;
  }
  fmt_when(ts, ctx->now, w, sizeof(w));
  fmt_span(ctx->now - ts, s, sizeof(s));
  if (snprintf(out, cap, "%s %s %s", w, GL(G_DOT), s) < 0) out[0] = '\0';
}

static void span_since(const fmt_ctx_t *ctx, long long ts, char *out, size_t cap) {
  if (ts <= 0) snprintf(out, cap, "%s", GL(G_DASH));
  else fmt_span(ctx->now - ts, out, cap);
}

static void flags_phrase(const char *f, char *out, size_t cap) {
  snprintf(out, cap, "%s", f && *f ? f : "none");
}

/* ==========================================================================
 * Bots
 * ========================================================================== */
typedef struct {
  const crec_t *r;
  int on;
  const char *name;
  const char *uuid;
  int idx;
} sortrow_t;

/* online first, then name (any case), then uuid, then arrival */
static bool row_before(const sortrow_t *a, const sortrow_t *b) {
  if (a->on != b->on) return a->on > b->on;
  int c = ci_cmp(a->name, b->name);
  if (c) return c < 0;
  c = strcmp(a->name, b->name);
  if (c) return c < 0;
  c = strcmp(a->uuid, b->uuid);
  if (c) return c < 0;
  return a->idx < b->idx;
}

static void sort_rows(sortrow_t *v, int n) {
  for (int i = 1; i < n; i++) {
    sortrow_t x = v[i];
    int j = i - 1;
    while (j >= 0 && row_before(&x, &v[j])) {
      v[j + 1] = v[j];
      j--;
    }
    v[j + 1] = x;
  }
}

/* Records of one type, sorted; caller frees. */
static sortrow_t *collect(const creply_t *rep, const char *type, const char *name_key,
                          const char *on_key, int *n) {
  sortrow_t *v = calloc((size_t)rep->n + 1, sizeof(sortrow_t));
  *n = 0;
  if (!v) return NULL;
  for (int i = 0; i < rep->n; i++) {
    const crec_t *r = &rep->r[i];
    if (strcmp(r->type, type)) continue;
    sortrow_t *s = &v[(*n)++];
    s->r = r;
    s->on = on_key && rvb(r, on_key) ? 1 : 0;
    s->name = rv(r, name_key) ? rv(r, name_key) : "";
    s->uuid = rv(r, "uuid") ? rv(r, "uuid") : "";
    s->idx = i;
  }
  sort_rows(v, *n);
  return v;
}

static void bot_last_seen(const fmt_ctx_t *ctx, const crec_t *r, char *out, size_t cap) {
  if (rvb(r, "online")) snprintf(out, cap, "now");
  else when_ago(ctx, rvi(r, "seen", 0), out, cap);
}

static void render_bot_list(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  long long total = rvi(&rep->res, "total", 0), online = rvi(&rep->res, "online", 0);
  char right[96];
  snprintf(right, sizeof(right), "%lld registered %s %lld online %s %lld offline", total,
           GL(G_DOT), online, GL(G_DOT), total - online);
  fmt_title(ctx, out, "Bots", right);
  int n = 0;
  sortrow_t *v = collect(rep, "bot", "nick", "online", &n);
  if (!n) {
    empty_note(out, "no bots registered", "bot add <nick> <uuid> <key>");
    free(v);
    return;
  }
  static const col_t cols[] = {
    {"", 'L', 1}, {"NICK", 'L', 1}, {"UUID", 'L', 1}, {"VERSION", 'L', 1},
    {"CODE", 'L', 1}, {"UPTIME", 'L', 1}, {"SERVER", 'L', 2}, {"HUB", 'L', 2},
    {"ADDRESS", 'L', 2}, {"SINCE", 'L', 2}, {"KEY", 'L', 2}, {"AUTH", 'L', 2},
    {"LAST SEEN", 'L', 1}};
  tbl_t t;
  tbl_init(&t, cols, 13, 0, 1, 1);
  int here = 0, via = 0;
  /* version and code-base breakdowns, in first-seen order then sorted */
  char vers[64][24];
  int vcnt[64], nv = 0, cc = 0, crs = 0;
  for (int i = 0; i < n; i++) {
    const crec_t *r = v[i].r;
    bool on = rvb(r, "online");
    char up[24], since[24], seen[64];
    span_since(ctx, on ? rvi(r, "started", 0) : 0, up, sizeof(up));
    span_since(ctx, on ? rvi(r, "since", 0) : 0, since, sizeof(since));
    bot_last_seen(ctx, r, seen, sizeof(seen));
    const char *cells[13] = {
      on ? GL(G_ON) : GL(G_OFF), rv(r, "nick"), rv(r, "uuid"), rv(r, "ver"), rv(r, "base"),
      up, rv(r, "server"), rv(r, "hub_name"), rv(r, "ip"), since,
      rvs(r, "fp") ? rv(r, "fp") : "(no key)", rvb(r, "auth") ? "yes" : "no", seen};
    tbl_row(ctx, &t, on ? RL_NORMAL : RL_DIM, on ? "online" : "offline", cells);
    if (on) {
      const char *hub = rv(r, "hub");
      if (hub && !strcmp(hub, "local")) here++;
      else via++;
      const char *ver = rvs(r, "ver");
      if (ver) {
        int k = 0;
        while (k < nv && strcmp(vers[k], ver)) k++;
        if (k == nv && nv < 64) {
          snprintf(vers[nv], sizeof(vers[0]), "%.*s", console_uprec(ver, 23), ver);
          vcnt[nv++] = 0;
        }
        if (k < nv) vcnt[k]++;
      }
      const char *base = rvs(r, "base");
      if (base && !strcmp(base, "c")) cc++;
      if (base && !strcmp(base, "rs")) crs++;
    }
  }
  tbl_render(ctx, out, &t);
  tbl_free(&t);
  rule_line(ctx, out);
  /* most common version first, then the higher string */
  for (int i = 1; i < nv; i++)
    for (int j = i; j > 0 && (vcnt[j] > vcnt[j - 1] ||
                              (vcnt[j] == vcnt[j - 1] && strcmp(vers[j], vers[j - 1]) > 0)); j--) {
      char tv[24];
      memcpy(tv, vers[j], sizeof(tv));
      memcpy(vers[j], vers[j - 1], sizeof(tv));
      memcpy(vers[j - 1], tv, sizeof(tv));
      int tc = vcnt[j];
      vcnt[j] = vcnt[j - 1];
      vcnt[j - 1] = tc;
    }
  sb_t b = {0};
  sb_addf(&b, "  online %lld %s offline %lld %s on this hub %d %s via other hubs %d", online,
          GL(G_DOT), total - online, GL(G_DOT), here, GL(G_DOT), via);
  for (int i = 0; i < nv; i++) sb_addf(&b, " %s %s %s%d", GL(G_DOT), vers[i], GL(G_TIMES), vcnt[i]);
  if (cc) sb_addf(&b, " %s c %d", GL(G_DOT), cc);
  if (crs) sb_addf(&b, " %s rs %d", GL(G_DOT), crs);
  sb_emit(&b, out, RL_DIM);
  sb_free(&b);
  hint(out, "bot show <uuid|nick> for one bot in detail");
  free(v);
}

static void render_bot_show(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const crec_t *r = NULL, *u = NULL;
  for (int i = 0; i < rep->n; i++) {
    if (!r && !strcmp(rep->r[i].type, "bot")) r = &rep->r[i];
    if (!u && !strcmp(rep->r[i].type, "upg")) u = &rep->r[i];
  }
  if (!r) return;
  bool on = rvb(r, "online");
  char title[128], right[48], v[512], a[64], b[64];
  snprintf(title, sizeof(title), "Bot %s", rvs(r, "nick") ? rv(r, "nick") : rv(r, "uuid"));
  snprintf(right, sizeof(right), "%s %s", on ? GL(G_ON) : GL(G_OFF), on ? "online" : "offline");
  fmt_title(ctx, out, title, right);
  const int L = 12;
  fmt_card_line(ctx, out, L, "uuid", rv(r, "uuid"), RL_NORMAL);
  if (on) {
    sb_t s = {0};
    sb_add(&s, rvs(r, "ver") ? rv(r, "ver") : "unknown version");
    if (rvs(r, "base")) sb_addf(&s, " %s code %s", GL(G_DOT), rv(r, "base"));
    long long st = rvi(r, "started", 0);
    if (st > 0) {
      fmt_dur3(ctx->now - st, a, sizeof(a));
      fmt_when(st, ctx->now, b, sizeof(b));
      sb_addf(&s, " %s up %s (started %s)", GL(G_DOT), a, b);
    }
    fmt_card_line(ctx, out, L, "version", s.p, RL_NORMAL);
    sb_free(&s);
    fmt_card_line(ctx, out, L, "irc server", rvs(r, "server") ? rv(r, "server") : GL(G_DASH),
                  RL_NORMAL);
    sb_reset(&s);
    bool local = rv(r, "hub") && !strcmp(rv(r, "hub"), "local");
    sb_addf(&s, "%s%s", rvs(r, "hub_name") ? rv(r, "hub_name") : GL(G_DASH),
            local ? " (this hub)" : "");
    long long since = rvi(r, "since", 0);
    if (since > 0) {
      fmt_when(since, ctx->now, a, sizeof(a));
      fmt_span(ctx->now - since, b, sizeof(b));
      sb_addf(&s, " %s connected %s %s %s", GL(G_DOT), a, GL(G_DOT), b);
    }
    if (rvs(r, "ip")) sb_addf(&s, " %s from %s", GL(G_DOT), rv(r, "ip"));
    fmt_card_line(ctx, out, L, "hub", s.p, RL_NORMAL);
    sb_free(&s);
  } else {
    fmt_card_line(ctx, out, L, "hub", "not connected to any hub", RL_DIM);
  }
  fmt_card_line(ctx, out, L, "key", rvs(r, "fp") ? rv(r, "fp") : "(no key)", RL_NORMAL);
  bot_last_seen(ctx, r, v, sizeof(v));
  fmt_card_line(ctx, out, L, "last seen", v, RL_NORMAL);
  if (rvb(r, "auth") && rvi(r, "auth_ts", 0) > 0) {
    fmt_when(rvi(r, "auth_ts", 0), ctx->now, a, sizeof(a));
    snprintf(v, sizeof(v), "yes %s %s", GL(G_DOT), a);
  } else if (rvb(r, "auth")) {
    snprintf(v, sizeof(v), "yes");
  } else {
    snprintf(v, sizeof(v), "no");
  }
  fmt_card_line(ctx, out, L, "authorized", v, RL_NORMAL);
  if (u) {
    fmt_when(rvi(u, "started", 0), ctx->now, a, sizeof(a));
    snprintf(v, sizeof(v), "run %s: %s %s %s %s (started %s)", rv(u, "id") ? rv(u, "id") : "?",
             rv(u, "state") ? rv(u, "state") : "?", rvs(u, "from") ? rv(u, "from") : "?",
             GL(G_ARROW), rvs(u, "to") ? rv(u, "to") : "?", a);
    fmt_card_line(ctx, out, L, "upgrade", v, RL_NORMAL);
  }
  static const char *const known[] = {"uuid", "nick", "online", "ver", "base", "started",
                                      "server", "hub", "hub_uuid", "hub_name", "ip", "since",
                                      "fp", "seen", "auth", "auth_ts", NULL};
  unknown_keys(ctx, out, r, known, L);
  if (rvs(r, "hub_uuid")) fmt_card_line(ctx, out, L, "hub uuid", rv(r, "hub_uuid"), RL_DIM);
}

static void render_bot_summary(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  char right[48];
  snprintf(right, sizeof(right), "%lld registered", rvi(&rep->res, "total", 0));
  fmt_title(ctx, out, "Bots", right);
  int n = 0;
  sortrow_t *v = collect(rep, "bot", "nick", NULL, &n);
  if (!n) {
    empty_note(out, "no bots registered", "bot add <nick> <uuid> <key>");
    free(v);
    return;
  }
  int nw = 4;
  for (int i = 0; i < n; i++) {
    int w = console_str_width(v[i].name[0] ? v[i].name : GL(G_DASH));
    if (w > nw) nw = w;
  }
  int entry = 2 + nw + 2 + 36;
  int per = ctx->width >= 2 * entry + 3 ? 2 : 1;
  int rows = (n + per - 1) / per;
  sb_t b = {0};
  for (int row = 0; row < rows; row++) {
    for (int c = 0; c < per; c++) {
      int i = c * rows + row;
      if (i >= n) break;
      sb_pad(&b, c * (entry + 3));
      sb_add(&b, "  ");
      int x = b.w;
      sb_add(&b, v[i].name[0] ? v[i].name : GL(G_DASH));
      sb_pad(&b, x + nw + 2);
      sb_add(&b, v[i].uuid);
    }
    sb_emit(&b, out, RL_NORMAL);
  }
  sb_free(&b);
  free(v);
}

static void render_bot_revoked(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  char right[48];
  snprintf(right, sizeof(right), "%lld of %lld", rvi(&rep->res, "count", 0),
           rvi(&rep->res, "max", 0));
  fmt_title(ctx, out, "Revoked bots", right);
  static const col_t cols[] = {{"NICK", 'L', 1}, {"UUID", 'L', 1}, {"DELETED", 'L', 1},
                               {"WIPED", 'L', 1}};
  tbl_t t;
  tbl_init(&t, cols, 4, -1, 1, 1);
  for (int i = 0; i < rep->n; i++) {
    const crec_t *r = &rep->r[i];
    if (strcmp(r->type, "revoked")) continue;
    char del[48], wiped[48];
    fmt_when(rvi(r, "deleted", 0), ctx->now, del, sizeof(del));
    if (rvi(r, "wiped", 0) > 0) fmt_when(rvi(r, "wiped", 0), ctx->now, wiped, sizeof(wiped));
    else snprintf(wiped, sizeof(wiped), "%s", GL(G_DASH));
    const char *cells[4] = {rvs(r, "nick") ? rv(r, "nick") : GL(G_DASH), rv(r, "uuid"), del,
                            wiped};
    tbl_row(ctx, &t, RL_NORMAL, NULL, cells);
  }
  if (!t.nr) {
    empty_note(out, "no deleted bots", NULL);
    tbl_free(&t);
    return;
  }
  tbl_render(ctx, out, &t);
  tbl_free(&t);
  rule_line(ctx, out);
  line(out, RL_DIM, "  one that ever connects to any hub is told to wipe its config and exit");
}

/* ==========================================================================
 * Peers and the mesh
 * ========================================================================== */
static void addr_of(const crec_t *r, char *out, size_t cap) {
  snprintf(out, cap, "%s:%lld", rv(r, "ip") ? rv(r, "ip") : "?", rvi(r, "port", 0));
}

static const char *peer_name(const crec_t *r) {
  if (rvs(r, "name")) return rv(r, "name");
  if (rvs(r, "ip")) return rv(r, "ip");
  return rvs(r, "uuid") ? rv(r, "uuid") : "?";
}

static void peer_link(const fmt_ctx_t *ctx, const crec_t *r, char *out, size_t cap) {
  long long since = rvi(r, "since", 0);
  char s[32], w[32];
  if (rvb(r, "up")) {
    span_since(ctx, since, s, sizeof(s));
    snprintf(out, cap, "%s up %s", GL(G_ON), s);
  } else if (since > 0) {
    fmt_when(since, ctx->now, w, sizeof(w));
    fmt_span(ctx->now - since, s, sizeof(s));
    snprintf(out, cap, "%s down since %s %s %s", GL(G_ERR), w, GL(G_DOT), s);
  } else {
    snprintf(out, cap, "%s down", GL(G_ERR));
  }
}

/* hub del's preview (peer.refs): the hub, the hubs that link to it, the bots
 * whose hub list holds it, and what to run where.  hub_console_ui.c asks the
 * question after it. */
static void render_peer_refs(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const crec_t *t = NULL;
  for (int i = 0; i < rep->n && !t; i++)
    if (!strcmp(rep->r[i].type, "peer")) t = &rep->r[i];
  if (!t) return;
  const char *tn = peer_name(t);
  char title[160], v[160];
  snprintf(title, sizeof(title), "Hub %s", tn);
  snprintf(v, sizeof(v), "%s link %s", GL(rvb(t, "up") ? G_ON : G_ERR), rvb(t, "up") ? "up" : "down");
  fmt_title(ctx, out, title, v);
  const int L = 8;
  fmt_card_line(ctx, out, L, "uuid", rvs(t, "uuid") ? rv(t, "uuid") : GL(G_DASH), RL_NORMAL);
  addr_of(t, v, sizeof(v));
  fmt_card_line(ctx, out, L, "address", v, RL_NORMAL);
  fmt_card_line(ctx, out, L, "key", rvs(t, "fp") ? rv(t, "fp") : "(no key)", RL_NORMAL);

  int hrefs = 0, hunrep = 0, brefs = 0, bunrep = 0;
  for (int i = 0; i < rep->n; i++) {
    const char *ty = rep->r[i].type;
    if (!strcmp(ty, "hubref") && !rvb(&rep->r[i], "self")) hrefs++;
    else if (!strcmp(ty, "hubunrep")) hunrep++;
    else if (!strcmp(ty, "botref")) brefs++;
    else if (!strcmp(ty, "botunrep")) bunrep++;
  }
  line(out, RL_NORMAL, "%s", "");
  if (!hrefs && !hunrep && !brefs && !bunrep) {
    line(out, RL_NORMAL, "  No other hub links to %s and no bot lists it.", tn);
    return;
  }

  /* hubs */
  snprintf(title, sizeof(title), "Hubs that link to %s", tn);
  snprintf(v, sizeof(v), "%d of %lld hubs", hrefs + 1, rvi(&rep->res, "hubs", 0));
  if (hunrep) {
    size_t o = strlen(v);
    snprintf(v + o, sizeof(v) - o, " %s %d not reported", GL(G_DOT), hunrep);
  }
  fmt_title(ctx, out, title, v);
  static const col_t hcols[] = {{"HUB", 'L', 1}, {"LINK", 'L', 1}, {"TO DO", 'L', 2}};
  tbl_t ht;
  tbl_init(&ht, hcols, 3, -1, 0, 2);
  for (int i = 0; i < rep->n; i++) {
    const crec_t *r = &rep->r[i];
    if (strcmp(r->type, "hubref")) continue;
    bool up = rvs(r, "state") && !strcmp(rv(r, "state"), "up");
    char lk[32], todo[256];
    snprintf(lk, sizeof(lk), "%s %s", GL(up ? G_ON : G_ERR), up ? "up" : "down");
    if (rvb(r, "self"))
      snprintf(todo, sizeof(todo), "this hub: unlinked when you answer y");
    else
      snprintf(todo, sizeof(todo), "hub del %s on %s%s", tn, rv(r, "name") ? rv(r, "name") : "?",
               up ? "" : " (link configured, down now)");
    const char *cells[3] = {rv(r, "name"), lk, todo};
    tbl_row(ctx, &ht, up ? RL_NORMAL : RL_WARN, NULL, cells);
  }
  tbl_render(ctx, out, &ht);
  tbl_free(&ht);
  if (hunrep) {
    sb_t s = {0};
    for (int i = 0; i < rep->n; i++)
      if (!strcmp(rep->r[i].type, "hubunrep"))
        sb_addf(&s, "%s%s", s.len ? ", " : "", rv(&rep->r[i], "name") ? rv(&rep->r[i], "name") : "?");
    line(out, RL_DIM, "  not reported: %s (their links never reached this hub)", s.p);
    sb_free(&s);
  }

  /* bots */
  line(out, RL_NORMAL, "%s", "");
  snprintf(title, sizeof(title), "Bots that list %s", tn);
  snprintf(v, sizeof(v), "%d of %lld bots", brefs, rvi(&rep->res, "bots", 0));
  if (bunrep) {
    size_t o = strlen(v);
    snprintf(v + o, sizeof(v) - o, " %s %d not reported", GL(G_DOT), bunrep);
  }
  fmt_title(ctx, out, title, v);
  static const col_t bcols[] = {{"BOT", 'L', 1}, {"NOW", 'L', 1}, {"ITS OTHER HUBS", 'L', 2},
                                {"TO DO", 'L', 2}};
  tbl_t bt;
  tbl_init(&bt, bcols, 4, -1, 0, 2);
  bool unknown = false;
  for (int i = 0; i < rep->n; i++) {
    const crec_t *r = &rep->r[i];
    if (strcmp(r->type, "botref")) continue;
    char now[96], todo[160], sp[32];
    if (rvs(r, "on")) {
      snprintf(now, sizeof(now), "%s on %s", GL(G_ON), rv(r, "on_name") ? rv(r, "on_name") : "?");
    } else if (rvi(r, "seen", 0) > 0) {
      fmt_span(ctx->now - rvi(r, "seen", 0), sp, sizeof(sp));
      snprintf(now, sizeof(now), "%s offline %s", GL(G_OFF), sp);
    } else {
      snprintf(now, sizeof(now), "%s offline", GL(G_OFF));
    }
    sb_t o = {0};
    const char *ol = rv(r, "others");
    if (!ol) ol = "";
    for (const char *p = ol; *p;) {
      const char *e = strchr(p, ',');
      size_t n = e ? (size_t)(e - p) : strlen(p);
      if (*p == '?') {
        sb_addf(&o, "%s%.*s (?)", o.len ? " " : "", (int)(n - 1), p + 1);
        unknown = true;
      } else {
        sb_addf(&o, "%s%.*s", o.len ? " " : "", (int)n, p);
      }
      p = e ? e + 1 : p + n;
    }
    bool stranded = !ol[0];
    if (stranded)
      snprintf(todo, sizeof(todo), "%s add another hub first (+hub)", GL(G_ERR));
    else
      snprintf(todo, sizeof(todo), "-hub %s", rvs(r, "addr") ? rv(r, "addr") : "<its address for it>");
    const char *cells[4] = {rvs(r, "nick") ? rv(r, "nick") : rv(r, "uuid"), now,
                            stranded ? "none" : o.p, todo};
    tbl_row(ctx, &bt, stranded ? RL_WARN : RL_NORMAL, NULL, cells);
    sb_free(&o);
  }
  if (bt.nr) tbl_render(ctx, out, &bt);
  else line(out, RL_NORMAL, "  (no bot lists it)");
  tbl_free(&bt);
  if (bunrep) {
    sb_t s = {0};
    for (int i = 0; i < rep->n; i++) {
      const crec_t *r = &rep->r[i];
      if (strcmp(r->type, "botunrep")) continue;
      sb_addf(&s, "%s%s", s.len ? ", " : "",
              rvs(r, "nick") ? rv(r, "nick") : rv(r, "uuid") ? rv(r, "uuid") : "?");
    }
    line(out, RL_DIM, "  not reported: %s (no hub list from them: an older build, or not "
         "connected since)", s.p);
    sb_free(&s);
  }
  for (int i = 0; i < rep->n; i++) {
    const crec_t *r = &rep->r[i];
    if (strcmp(r->type, "botref")) continue;
    const char *nk = rvs(r, "nick") ? rv(r, "nick") : rv(r, "uuid") ? rv(r, "uuid") : "?";
    if (!rvs(r, "others")) {
      line(out, RL_WARN, "  %s %s lists no other hub: without %s it cannot connect at all.",
           GL(G_WARN), nk, tn);
    } else if (rvs(r, "on_uuid") && rvs(t, "uuid") && !strcmp(rv(r, "on_uuid"), rv(t, "uuid"))) {
      const char *ol = rv(r, "others");
      if (!ol) ol = "";
      sb_t o = {0};
      int cnt = 0, k = 0;
      for (const char *p = ol; *p; p++) cnt += *p == ',';
      cnt++;
      for (const char *p = ol; *p;) {
        const char *e = strchr(p, ',');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        k++;
        const char *sep = k == 1 ? "" : k == cnt ? " or " : ", ";
        if (*p == '?') sb_addf(&o, "%s%.*s", sep, (int)(n - 1), p + 1);
        else sb_addf(&o, "%s%.*s", sep, (int)n, p);
        p = e ? e + 1 : p + n;
      }
      line(out, RL_WARN, "  %s %s is on %s now: after its -hub it moves to %s.", GL(G_WARN), nk, tn,
           o.p);
      sb_free(&o);
    }
  }
  if (unknown) line(out, RL_DIM, "  (?) a hub this hub has no key for, shown by the address the bot uses");
}

/* A hub's short name for a matrix column: the first 5 characters. */
/* A mesh column head: the first `head` and the last `tail` characters of
 * `name`, or all of it when it has no more than head + tail. */
static void mesh_head(const char *name, int head, int tail, char *out, size_t cap) {
  size_t n = strlen(name), o = 0;
  int nc = 0;
  for (size_t i = 0; i < n; nc++) {
    unsigned cp;
    int w;
    i += console_next_char(name + i, n - i, &cp, &w);
  }
  if (nc <= head + tail) head = nc;
  int c = 0;
  for (size_t i = 0; i < n; c++) {
    unsigned cp;
    int w;
    size_t l = console_next_char(name + i, n - i, &cp, &w);
    if ((c < head || c >= nc - tail) && o + l < cap) {
      memcpy(out + o, name + i, l);
      o += l;
    }
    i += l;
  }
  out[o] = '\0';
}

typedef struct {
  const char *uuid, *name;
  char shrt[32];
} mnode_t;

static int mesh_find(const mnode_t *nodes, int n, const char *uuid) {
  for (int i = 0; i < n; i++)
    if (uuid && !strcmp(nodes[i].uuid, uuid)) return i;
  return -1;
}

static void render_mesh(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  mnode_t nodes[64];
  int nn = 0;
  for (int i = 0; i < rep->n && nn < 64; i++) {
    const crec_t *r = &rep->r[i];
    if (strcmp(r->type, "self") && strcmp(r->type, "peer") && strcmp(r->type, "hub")) continue;
    if (!rvs(r, "uuid") || mesh_find(nodes, nn, rv(r, "uuid")) >= 0) continue;
    nodes[nn].uuid = rv(r, "uuid");
    nodes[nn].name = peer_name(r);
    nn++;
  }
  /* hubs only a link names */
  for (int i = 0; i < rep->n && nn < 64; i++) {
    const crec_t *r = &rep->r[i];
    if (strcmp(r->type, "link") || !rvs(r, "b") || mesh_find(nodes, nn, rv(r, "b")) >= 0) continue;
    nodes[nn].uuid = rv(r, "b");
    nodes[nn].name = rvs(r, "b_name") ? rv(r, "b_name") : rv(r, "b");
    nn++;
  }
  if (nn < 2) return;
  /* Column heads: the first 5 characters of each name ("hub-" dropped: it
   * says nothing).  Names whose heads clash get their start plus their end,
   * with the shortest end that tells that group apart ("tnhub1".."tnhub5"
   * -> "tnhu1".."tnhu5"); if no end does, the group is numbered in list
   * order. */
  const char *nm[64];
  char base[64][32];
  bool clash[64];
  bool any = false;
  for (int i = 0; i < nn; i++) {
    nm[i] = nodes[i].name;
    if (!strncasecmp(nm[i], "hub-", 4) && nm[i][4]) nm[i] += 4;
    mesh_head(nm[i], 5, 0, base[i], sizeof(base[i]));
  }
  for (int i = 0; i < nn; i++) {
    clash[i] = false;
    for (int j = 0; j < nn; j++) clash[i] |= j != i && !strcmp(base[i], base[j]);
    any |= clash[i];
    memcpy(nodes[i].shrt, base[i], sizeof(nodes[i].shrt));
  }
  if (any) {
    char cand[64][32];
    bool done[64] = {false};
    for (int i = 0; i < nn; i++) {
      if (!clash[i] || done[i]) continue;
      /* the group of names whose heads are base[i] */
      bool grp[64];
      for (int j = 0; j < nn; j++) grp[j] = clash[j] && !strcmp(base[j], base[i]);
      int k;
      for (k = 1; k <= 4; k++) {
        for (int j = 0; j < nn; j++)
          if (grp[j]) mesh_head(nm[j], 5 - k, k, cand[j], sizeof(cand[j]));
        bool ok = true;
        for (int j = 0; j < nn && ok; j++) {
          if (!grp[j]) continue;
          for (int m = 0; m < nn && ok; m++) {
            if (m == j) continue;
            if (grp[m]) ok = strcmp(cand[j], cand[m]) != 0;
            else if (!clash[m]) ok = strcmp(cand[j], base[m]) != 0;
          }
        }
        if (ok) break;
      }
      int ord = 0;
      for (int j = 0; j < nn; j++) {
        if (!grp[j]) continue;
        done[j] = true;
        ord++;
        if (k <= 4) {
          memcpy(nodes[j].shrt, cand[j], sizeof(nodes[j].shrt));
          continue;
        }
        char h[20]; /* at most 4 characters of 4 bytes */
        mesh_head(base[j], ord < 10 ? 4 : 3, 0, h, sizeof(h));
        snprintf(nodes[j].shrt, sizeof(nodes[j].shrt), "%s%d", h, ord);
      }
    }
  }
  /* cell[a][b]: 0 unknown, 1 up, 2 down */
  int cell[64][64];
  memset(cell, 0, sizeof(cell));
  for (int i = 0; i < rep->n; i++) {
    const crec_t *r = &rep->r[i];
    if (strcmp(r->type, "link")) continue;
    int a = mesh_find(nodes, nn, rv(r, "a")), b = mesh_find(nodes, nn, rv(r, "b"));
    if (a < 0 || b < 0) continue;
    cell[a][b] = rv(r, "state") && !strcmp(rv(r, "state"), "up") ? 1 : 2;
  }
  fmt_title(ctx, out, "Mesh links", "as gossiped");
  int nw = 0;
  for (int i = 0; i < nn; i++)
    if (console_str_width(nodes[i].name) > nw) nw = console_str_width(nodes[i].name);
  /* Whole names head the columns when they fit (each glyph centred under
   * its name); the short heads only when the terminal is too narrow. */
  int fw = nw + 2 > 6 ? nw + 2 : 6;
  bool full = 3 + nw + 2 + fw * nn <= ctx->width;
  int cw = full ? fw : 6;
  sb_t b = {0};
  if (3 + nw + 2 + cw * nn <= ctx->width) {
    sb_pad(&b, 3 + nw + 2);
    for (int i = 0; i < nn; i++) {
      int x = b.w;
      sb_add(&b, full ? nodes[i].name : nodes[i].shrt);
      sb_pad(&b, x + cw);
    }
    sb_emit(&b, out, RL_HEAD);
    for (int a = 0; a < nn; a++) {
      sb_add(&b, "   ");
      sb_add(&b, nodes[a].name);
      sb_pad(&b, 3 + nw + 2);
      for (int c = 0; c < nn; c++) {
        int x = b.w;
        int w = console_str_width(nodes[c].name);
        sb_pad(&b, x + (full && w > 0 ? (w - 1) / 2 : 2));
        sb_add(&b, a == c ? GL(G_DOT) : cell[a][c] == 1 ? GL(G_ON)
                   : cell[a][c] == 2 ? GL(G_ERR) : GL(G_UNKNOWN));
        sb_pad(&b, x + cw);
      }
      sb_emit(&b, out, RL_NORMAL);
    }
    line(out, RL_DIM, "  %s link up   %s link down   %s not reported   %s self", GL(G_ON),
         GL(G_ERR), GL(G_UNKNOWN), GL(G_DOT));
  } else {
    for (int a = 0; a < nn; a++) {
      sb_add(&b, "   ");
      sb_add(&b, nodes[a].name);
      sb_pad(&b, 3 + nw + 2);
      bool listed = false;
      for (int pass = 1; pass <= 2; pass++) {
        bool first = true;
        for (int c = 0; c < nn; c++) {
          if (c == a || cell[a][c] != pass) continue;
          sb_addf(&b, "%s%s", first ? (pass == 1 ? "up: " : (listed ? "  down: " : "down: ")) : " ",
                  nodes[c].shrt);
          first = false;
          listed = true;
        }
      }
      if (!listed) sb_add(&b, "(not reported)");
      sb_emit(&b, out, RL_NORMAL);
    }
  }
  sb_free(&b);
}

static void render_peer_list(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  long long conf = rvi(&rep->res, "configured", 0), up = rvi(&rep->res, "up", 0);
  char right[96];
  snprintf(right, sizeof(right), "%lld configured %s %lld up %s %lld down", conf, GL(G_DOT), up,
           GL(G_DOT), conf - up);
  fmt_title(ctx, out, "Linked hubs", right);
  static const col_t cols[] = {
    {"#", 'R', 1}, {"NAME", 'L', 1}, {"ADDRESS", 'L', 1}, {"UUID", 'L', 2}, {"CODE", 'L', 2},
    {"VERSION", 'L', 2}, {"UPTIME", 'L', 2}, {"BOTS", 'R', 1}, {"LINK", 'L', 1},
    {"KEY", 'L', 1}, {"FROM", 'L', 2}};
  tbl_t t;
  tbl_init(&t, cols, 11, -1, 1, 1);
  const crec_t *self = NULL;
  for (int i = 0; i < rep->n; i++) {
    const crec_t *r = &rep->r[i];
    if (!strcmp(r->type, "self")) self = r;
    if (strcmp(r->type, "peer")) continue;
    char nn[16], addr[96], bots[16], link[96], upt[32];
    snprintf(nn, sizeof(nn), "%lld", rvi(r, "n", 0));
    addr_of(r, addr, sizeof(addr));
    if (rv(r, "bots")) snprintf(bots, sizeof(bots), "%lld", rvi(r, "bots", 0));
    else bots[0] = '\0';
    peer_link(ctx, r, link, sizeof(link));
    span_since(ctx, rvi(r, "started", 0), upt, sizeof(upt));
    const char *from = rvs(r, "remote_ip") && rvs(r, "ip") && strcmp(rv(r, "remote_ip"), rv(r, "ip"))
                           ? rv(r, "remote_ip") : NULL;
    const char *cells[11] = {nn, rvs(r, "name"), addr, rv(r, "uuid"), rv(r, "base"),
                             rv(r, "ver"), upt, bots, link, rv(r, "fp"), from};
    tbl_row(ctx, &t, rvb(r, "up") ? RL_NORMAL : RL_WARN, rvb(r, "up") ? "up" : "down", cells);
  }
  if (!t.nr) {
    empty_note(out, "no other hubs linked: this hub runs alone",
               "hub add <ip> <port> <uuid> <name|-> <key>");
  } else {
    tbl_render(ctx, out, &t);
  }
  tbl_free(&t);
  if (self) {
    line(out, RL_DIM, "  this hub: %s  %s  %s %s  %lld bots  port %lld", peer_name(self),
         rvs(self, "uuid") ? rv(self, "uuid") : GL(G_DASH), rvs(self, "base") ? rv(self, "base") : "?",
         rvs(self, "ver") ? rv(self, "ver") : "?", rvi(self, "bots", 0), rvi(self, "port", 0));
  }
  if (!conf) return;
  flines_add(out, RL_NORMAL, "");
  render_mesh(ctx, rep, out);
  /* health */
  int issues = 0;
  for (int i = 0; i < rep->n; i++) issues += !strcmp(rep->r[i].type, "issue");
  flines_add(out, RL_NORMAL, "");
  if (!issues) {
    char h[96];
    snprintf(h, sizeof(h), "%s healthy %s every configured link is up, no unknown hubs",
             GL(G_ON), GL(G_DASH));
    fmt_title(ctx, out, "Health", h);
    return;
  }
  char h[48];
  snprintf(h, sizeof(h), "%s %d issue%s", GL(G_WARN), issues, issues == 1 ? "" : "s");
  fmt_title(ctx, out, "Health", h);
  for (int i = 0; i < rep->n; i++) {
    const crec_t *r = &rep->r[i];
    if (strcmp(r->type, "issue")) continue;
    const char *kind = rv(r, "kind") ? rv(r, "kind") : "";
    if (!strcmp(kind, "peer_down")) {
      long long since = rvi(r, "since", 0);
      if (since > 0) {
        char w[32];
        fmt_when(since, ctx->now, w, sizeof(w));
        line(out, RL_WARN, "  %s %s is down %s no link from this hub since %s", GL(G_WARN),
             peer_name(r), GL(G_DASH), w);
      } else {
        line(out, RL_WARN, "  %s %s is down %s no link from this hub since it started", GL(G_WARN),
             peer_name(r), GL(G_DASH));
      }
    } else if (!strcmp(kind, "unknown_hub")) {
      line(out, RL_WARN, "  %s %s links to %s, which this hub has not configured", GL(G_WARN),
           rvs(r, "via_name") ? rv(r, "via_name") : rv(r, "via") ? rv(r, "via") : "?",
           rvs(r, "name") ? rv(r, "name") : rv(r, "uuid") ? rv(r, "uuid") : "?");
    } else {
      line(out, RL_WARN, "  %s %s", GL(G_WARN), r->line);
    }
  }
}

static void render_peer_show(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const crec_t *r = NULL;
  for (int i = 0; i < rep->n && !r; i++)
    if (!strcmp(rep->r[i].type, "peer")) r = &rep->r[i];
  if (!r) return;
  char title[96], link[96], v[512], a[48], b[48];
  snprintf(title, sizeof(title), "Hub %s", peer_name(r));
  peer_link(ctx, r, link, sizeof(link));
  fmt_title(ctx, out, title, link);
  const int L = 12;
  snprintf(v, sizeof(v), "%lld", rvi(r, "n", 0));
  fmt_card_line(ctx, out, L, "#", v, RL_NORMAL);
  fmt_card_line(ctx, out, L, "uuid", rvs(r, "uuid") ? rv(r, "uuid") : GL(G_DASH), RL_NORMAL);
  addr_of(r, a, sizeof(a));
  if (rvs(r, "remote_ip"))
    snprintf(v, sizeof(v), "%s (configured) %s seen from %s", a, GL(G_DOT), rv(r, "remote_ip"));
  else
    snprintf(v, sizeof(v), "%s (configured)", a);
  fmt_card_line(ctx, out, L, "address", v, RL_NORMAL);
  sb_t s = {0};
  sb_add(&s, rvs(r, "ver") ? rv(r, "ver") : "unknown version");
  if (rvs(r, "base")) sb_addf(&s, " %s code %s", GL(G_DOT), rv(r, "base"));
  if (rvi(r, "started", 0) > 0) {
    fmt_dur3(ctx->now - rvi(r, "started", 0), a, sizeof(a));
    sb_addf(&s, " %s up %s", GL(G_DOT), a);
  }
  fmt_card_line(ctx, out, L, "version", s.p, RL_NORMAL);
  sb_reset(&s);
  fmt_card_line(ctx, out, L, "key", rvs(r, "fp") ? rv(r, "fp") : "(no key)", RL_NORMAL);
  long long since = rvi(r, "since", 0);
  if (rvb(r, "up")) {
    fmt_when(since, ctx->now, a, sizeof(a));
    fmt_span(ctx->now - since, b, sizeof(b));
    sb_addf(&s, "up since %s %s %s", a, GL(G_DOT), b);
  } else if (since > 0) {
    fmt_when(since, ctx->now, a, sizeof(a));
    sb_addf(&s, "down since %s", a);
  } else {
    sb_add(&s, "down");
  }
  if (rvi(r, "gossip", 0) > 0) {
    fmt_span(ctx->now - rvi(r, "gossip", 0), a, sizeof(a));
    sb_addf(&s, " %s last gossip %s ago", GL(G_DOT), a);
  }
  fmt_card_line(ctx, out, L, "link", s.p, rvb(r, "up") ? RL_NORMAL : RL_WARN);
  sb_reset(&s);
  if (rv(r, "bots")) {
    sb_addf(&s, "%lld", rvi(r, "bots", 0));
    const char *bots_list = rvs(r, "bots_list");
    if (bots_list) {
      sb_add(&s, " (");
      for (const char *p = bots_list; *p; p++) sb_add(&s, *p == ',' ? ", " : (char[2]){*p, 0});
      sb_add(&s, ")");
    }
    fmt_card_line(ctx, out, L, "bots", s.p, RL_NORMAL);
    sb_reset(&s);
  }
  for (int i = 0; i < rep->n; i++) {
    const crec_t *l = &rep->r[i];
    if (strcmp(l->type, "link")) continue;
    if (s.len) sb_addf(&s, " %s ", GL(G_DOT));
    bool lu = rv(l, "state") && !strcmp(rv(l, "state"), "up");
    sb_addf(&s, "%s %s", rvs(l, "b_name") ? rv(l, "b_name") : rv(l, "b") ? rv(l, "b") : "?",
            lu ? GL(G_ON) : GL(G_ERR));
  }
  fmt_card_line(ctx, out, L, "its links", s.len ? s.p : "(not reported)", RL_NORMAL);
  sb_free(&s);
  static const char *const known[] = {"n", "uuid", "name", "ip", "port", "remote_ip", "up",
                                      "since", "base", "ver", "started", "bots", "fp",
                                      "bots_list", "gossip", NULL};
  unknown_keys(ctx, out, r, known, L);
}

/* ==========================================================================
 * This hub
 * ========================================================================== */
static void render_hub_show(const fmt_ctx_t *ctx, const crec_t *h, flines_t *out) {
  char title[96], right[64], v[512], a[48], b[48];
  snprintf(title, sizeof(title), "Hub %s", rv(h, "name") ? rv(h, "name") : "?");
  fmt_dur3(ctx->now - rvi(h, "started", ctx->now), a, sizeof(a));
  snprintf(right, sizeof(right), "%s up %s", GL(G_ON), a);
  fmt_title(ctx, out, title, right);
  const int L = 12;
  fmt_card_line(ctx, out, L, "uuid", rvs(h, "uuid") ? rv(h, "uuid") : GL(G_DASH), RL_NORMAL);
  fmt_when(rvi(h, "started", 0), ctx->now, a, sizeof(a));
  snprintf(v, sizeof(v), "%s %s code %s %s started %s", rv(h, "ver") ? rv(h, "ver") : "?",
           GL(G_DOT), rv(h, "base") ? rv(h, "base") : "?", GL(G_DOT), a);
  fmt_card_line(ctx, out, L, "version", v, RL_NORMAL);
  if (rvs(h, "pending_bind_ip") || rvs(h, "pending_port"))
    snprintf(v, sizeof(v), "%s:%lld %s %s:%lld after restart", rv(h, "bind_ip"),
             rvi(h, "port", 0), GL(G_ARROW),
             rvs(h, "pending_bind_ip") ? rv(h, "pending_bind_ip") : rv(h, "bind_ip"),
             rvi(h, "pending_port", rvi(h, "port", 0)));
  else
    snprintf(v, sizeof(v), "%s:%lld", rv(h, "bind_ip") ? rv(h, "bind_ip") : "?", rvi(h, "port", 0));
  fmt_card_line(ctx, out, L, "listening", v, RL_NORMAL);
  /* the 88-character key on one unbroken line (D10) */
  fmt_card_line(ctx, out, L, "public key", rvs(h, "key") ? rv(h, "key") : GL(G_DASH), RL_NORMAL);
  fmt_card_line(ctx, out, L, "key", rvs(h, "fp") ? rv(h, "fp") : GL(G_DASH), RL_NORMAL);
  snprintf(v, sizeof(v), "ssh-ed25519 %s", rvs(h, "ssh_fp") ? rv(h, "ssh_fp") : "?");
  fmt_card_line(ctx, out, L, "ssh host key", v, RL_NORMAL);
  snprintf(v, sizeof(v), "%lld / %lld up", rvi(h, "peers_up", 0), rvi(h, "peers", 0));
  fmt_card_line(ctx, out, L, "hubs", v, RL_NORMAL);
  snprintf(v, sizeof(v), "%lld here %s %lld / %lld on the network", rvi(h, "bots_here", 0),
           GL(G_DOT), rvi(h, "bots_online", 0), rvi(h, "bots", 0));
  fmt_card_line(ctx, out, L, "bots", v, RL_NORMAL);
  long long ap = rvi(h, "autopurge", 0);
  if (ap > 0) snprintf(v, sizeof(v), "tombstones older than %lld days, daily", ap);
  else snprintf(v, sizeof(v), "off (hub purge clears tombstones by hand)");
  fmt_card_line(ctx, out, L, "autopurge", v, RL_NORMAL);
  fmt_bytes((unsigned long long)rvi(h, "log_size", 0), b, sizeof(b));
  snprintf(v, sizeof(v), "file %s (limit %s) %s console %s", level_name(rvi(h, "log_file", 0)), b,
           GL(G_DOT), level_name(rvi(h, "log_console", 0)));
  fmt_card_line(ctx, out, L, "log", v, RL_NORMAL);
  snprintf(v, sizeof(v), "hubs: hub add %s <key>   %s   bots: +hub host:port <key>",
           GL(G_ELL), GL(G_DOT));
  fmt_card_line(ctx, out, L, "give to", v, RL_DIM);
  static const char *const known[] = {"name", "uuid", "ver", "base", "started", "bind_ip", "port",
                                      "pending_bind_ip", "pending_port", "key", "fp", "ssh_fp",
                                      "peers_up", "peers", "bots_here", "bots_online", "bots",
                                      "autopurge", "log_file", "log_console", "log_size", NULL};
  unknown_keys(ctx, out, h, known, L);
}

static void render_hub_settings(const fmt_ctx_t *ctx, const crec_t *h, flines_t *out) {
  fmt_title(ctx, out, "Hub settings", "hub set <setting> <value>");
  static const col_t cols[] = {{"SETTING", 'L', 1}, {"CURRENT", 'L', 1}, {"MEANING", 'L', 2}};
  tbl_t t;
  tbl_init(&t, cols, 3, -1, 0, 1);
  char port[16], ap[32];
  snprintf(port, sizeof(port), "%lld", rvi(h, "pending_port", rvi(h, "port", 0)));
  long long d = rvi(h, "autopurge", 0);
  if (d > 0) snprintf(ap, sizeof(ap), "%lld days", d);
  else snprintf(ap, sizeof(ap), "off");
  const char *rows[5][3] = {
    {"name", rv(h, "name"), "this hub's name (A-Z a-z 0-9 . _ -, 1-63)"},
    {"bindip", rvs(h, "pending_bind_ip") ? rv(h, "pending_bind_ip") : rv(h, "bind_ip"),
     "address to listen on (restart)"},
    {"port", port, "port to listen on (restart)"},
    {"pubkey", rv(h, "fp"), "re-store the public key (must match the private key)"},
    {"autopurge", ap, "purge tombstones older than <days> daily (0 = off)"}};
  for (int i = 0; i < 5; i++) tbl_row(ctx, &t, RL_NORMAL, NULL, rows[i]);
  tbl_render(ctx, out, &t);
  tbl_free(&t);
}

/* hub set ssh / hub set conn: this hub's connection limits.  ok|hub.show with
 * group=ssh|conn and, per setting, <name>=<value> and <name>_def=<built-in>. */
static const struct {
  const char *group, *name, *meaning;
} LIMIT_ROWS[] = {
  {"ssh", "preauth", "SSH logins in progress, all addresses (1-64)"},
  {"ssh", "preauthip", "SSH logins in progress from one address (1 to preauth)"},
  {"ssh", "sessions", "open consoles (1-32)"},
  {"ssh", "grace", "seconds from connect to a running console (5-120)"},
  {"ssh", "authtries", "refused keys before a connection is dropped (1-6)"},
  {"ssh", "idle", "seconds without a keystroke before the console closes (60-86400)"},
  {"ssh", "authfail", "refused SSH logins per address, N:S, then blocked"},
  {"ssh", "connect", "new SSH connections per address, N:S, then blocked"},
  {"ssh", "block", "seconds blocked; doubles per repeat within 24 h, up to 24 h (30-86400)"},
  {"ssh", "cmdrate", "console commands per session, N:S; more are queued, not dropped"},
  {"conn", "perip", "connections at once from one address, bots, hubs and SSH (2-64)"},
  {"conn", "churn", "new connections per address, N:S[:B], then blocked B seconds"},
  {"conn", "authfail", "failed logins per address, N:S[:B], then blocked B seconds"},
};

static void render_limits(const fmt_ctx_t *ctx, const crec_t *h, flines_t *out) {
  const char *group = rv(h, "group") ? rv(h, "group") : "ssh";
  bool conn = !strcmp(group, "conn");
  static const col_t cols[] = {{"SETTING", 'L', 1}, {"VALUE", 'L', 1}, {"FROM", 'L', 1},
                               {"MEANING", 'L', 2}};
  tbl_t t;
  tbl_init(&t, cols, 4, -1, 0, 1);
  int changed = 0;
  for (size_t i = 0; i < sizeof(LIMIT_ROWS) / sizeof(LIMIT_ROWS[0]); i++) {
    if (strcmp(LIMIT_ROWS[i].group, group)) continue;
    char key[48];
    snprintf(key, sizeof(key), "%s_def", LIMIT_ROWS[i].name);
    const char *v = rv(h, LIMIT_ROWS[i].name) ? rv(h, LIMIT_ROWS[i].name) : GL(G_DASH);
    const char *d = rv(h, key) ? rv(h, key) : "";
    bool set = strcmp(v, d) != 0;
    if (set) changed++;
    const char *cells[4] = {LIMIT_ROWS[i].name, v, set ? "set here" : "built-in",
                            LIMIT_ROWS[i].meaning};
    tbl_row(ctx, &t, RL_NORMAL, NULL, cells);
  }
  char right[96];
  snprintf(right, sizeof(right), "this hub only %s %d changed", GL(G_DOT), changed);
  fmt_title(ctx, out, conn ? "Connection limits" : "SSH limits", right);
  tbl_render(ctx, out, &t);
  tbl_free(&t);
  rule_line(ctx, out);
  line(out, RL_DIM, "  a change applies to the next connection; logins in progress keep theirs");
  hint(out, conn ? "hub set conn <perip|churn|authfail> <value|default>"
                 : "hub set ssh <name> <value|default> · hub set conn shows the shared limits");
}

static void render_hub_set(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const crec_t *r = &rep->res;
  const char *setting = rv(r, "setting") ? rv(r, "setting") : "?";
  char what[160], subj[512], ph[160];
  const char *old = rvs(r, "old") ? rv(r, "old") : GL(G_DASH);
  const char *val = rvs(r, "value") ? rv(r, "value") : GL(G_DASH);
  if (rvs(r, "group")) {   /* hub set ssh|conn */
    snprintf(what, sizeof(what), "%s", !strcmp(rv(r, "group"), "conn") ? "Connection limits" : "SSH limits");
    snprintf(subj, sizeof(subj), "%s   %s %s %s", setting, old, GL(G_ARROW), val);
    fmt_ok(ctx, what, subj, out);
    if (!rvb(r, "written")) {
      effect(ctx, out, "no change: it already had that value");
    } else {
      snprintf(ph, sizeof(ph), "%s", rvb(r, "reset") ? "built-in value restored" : "saved on this hub");
      effect(ctx, out, ph);
      effect(ctx, out, "applies to the next connection; logins in progress keep theirs");
    }
    return;
  }
  snprintf(what, sizeof(what), "Hub %s",
           !strcmp(setting, "name") ? old : ctx->hubname && *ctx->hubname ? ctx->hubname : "hub");
  if (!strcmp(setting, "pubkey")) {
    snprintf(subj, sizeof(subj), "pubkey   re-stored %s (matches the private key)", val);
  } else if (!strcmp(setting, "autopurge")) {
    char o[32], n[32];
    long long ov = rvi(r, "old", 0), nv = rvi(r, "value", 0);
    if (ov > 0) snprintf(o, sizeof(o), "%lld days", ov);
    else snprintf(o, sizeof(o), "off");
    if (nv > 0) snprintf(n, sizeof(n), "%lld days", nv);
    else snprintf(n, sizeof(n), "off");
    if (nv > 0)
      snprintf(subj, sizeof(subj), "autopurge   %s %s %s   (tombstones older than %lld days, checked daily)",
               o, GL(G_ARROW), n, nv);
    else
      snprintf(subj, sizeof(subj), "autopurge   %s %s %s", o, GL(G_ARROW), n);
  } else {
    snprintf(subj, sizeof(subj), "%s   %s %s %s%s", setting, old, GL(G_ARROW), val,
             rvb(r, "restart") ? "   (restart needed)" : "");
  }
  fmt_ok(ctx, what, subj, out);
  if (!strcmp(setting, "name")) effect(ctx, out, "other hubs learn the new name with the next mesh gossip (now)");
  if (!strcmp(setting, "autopurge"))
    effect(ctx, out, "every hub uses it; the hub with the lowest uuid runs the purge");
  if (rvb(r, "restart")) {
    snprintf(ph, sizeof(ph), "takes effect when the hub restarts; it listens on %s:%s until then",
             rv(r, "listen_ip") ? rv(r, "listen_ip") : "?",
             rv(r, "listen_port") ? rv(r, "listen_port") : "?");
    effect(ctx, out, ph);
    if (!strcmp(setting, "port")) {
      snprintf(ph, sizeof(ph), "after the restart, admins connect with ssh -p %s; other hubs and bots must use :%s",
               val, val);
      effect(ctx, out, ph);
    }
  }
  if (rv(r, "peers") && strcmp(setting, "name")) {
    peers_phrase(ph, sizeof(ph), rvi(r, "peers", 0));
    effect(ctx, out, ph);
  }
}

static void render_hub_rekeyed(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const crec_t *r = &rep->res;
  char t[64], v[256];
  snprintf(t, sizeof(t), "%s Hub keypair replaced", GL(G_OK));
  fmt_title(ctx, out, t, rv(r, "name"));
  const int L = 12;
  fmt_card_line(ctx, out, L, "new key", rvs(r, "key") ? rv(r, "key") : "?", RL_NORMAL);
  snprintf(v, sizeof(v), "%s %s %s", rvs(r, "old_fp") ? rv(r, "old_fp") : GL(G_DASH), GL(G_ARROW),
           rvs(r, "fp") ? rv(r, "fp") : "?");
  fmt_card_line(ctx, out, L, "key", v, RL_NORMAL);
  snprintf(v, sizeof(v), "now %s  (admins: ssh-keygen -R '[host]:%lld')",
           rvs(r, "ssh_fp") ? rv(r, "ssh_fp") : "?", rvi(r, "port", 0));
  fmt_card_line(ctx, out, L, "ssh host key", v, RL_NORMAL);
  fmt_card_line(ctx, out, L, "saved to", rvs(r, "file") ? rv(r, "file") : "(not written)",
                rvs(r, "file") ? RL_NORMAL : RL_WARN);
  char p[48], b[48];
  plural(p, sizeof(p), rvi(r, "peers", 0), "hub link", "hub links");
  plural(b, sizeof(b), rvi(r, "bots", 0), "bot", "bots");
  snprintf(v, sizeof(v), "%s, %s", p, b);
  fmt_card_line(ctx, out, L, "dropped", v, RL_NORMAL);
  line(out, RL_HEAD, " Next steps");
  line(out, RL_NORMAL, "  1. on each other hub:  hub set %s key <new key>",
       rvs(r, "uuid") ? rv(r, "uuid") : "<this hub's uuid>");
  line(out, RL_NORMAL, "  2. on each bot here:   -hub %s:%lld  then  +hub %s:%lld <new key>",
       rv(r, "name") ? rv(r, "name") : "hub", rvi(r, "port", 0),
       rv(r, "name") ? rv(r, "name") : "hub", rvi(r, "port", 0));
}

static void render_tomb_purged(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const crec_t *r = &rep->res;
  long long count = rvi(r, "count", 0), days = rvi(r, "days", 0);
  char what[128], age[64];
  if (days > 0) snprintf(age, sizeof(age), "older than %lld days", days);
  else age[0] = '\0';
  if (count > 0) {
    snprintf(what, sizeof(what), "Purged %lld tombstone%s on this hub", count, count == 1 ? "" : "s");
    if (age[0]) {
      char a2[80];
      snprintf(a2, sizeof(a2), "(%s)", age);
      fmt_ok(ctx, what, a2, out);
    } else {
      fmt_ok(ctx, what, NULL, out);
    }
    static const col_t cols[] = {{"KIND", 'L', 1}, {"NAME / ID", 'L', 1}, {"DELETED", 'L', 1}};
    tbl_t t;
    tbl_init(&t, cols, 3, -1, 1, 1);
    t.indent = 3;
    for (int i = 0; i < rep->n; i++) {
      const crec_t *x = &rep->r[i];
      if (strcmp(x->type, "tomb")) continue;
      char nm[256], del[64];
      if (rvs(x, "name") && rvs(x, "id")) snprintf(nm, sizeof(nm), "%s  %s", rv(x, "name"), rv(x, "id"));
      else snprintf(nm, sizeof(nm), "%s", rvs(x, "name") ? rv(x, "name") : rvs(x, "id") ? rv(x, "id") : "");
      when_ago(ctx, rvi(x, "ts", 0), del, sizeof(del));
      const char *cells[3] = {rv(x, "kind"), nm, del};
      tbl_row(ctx, &t, RL_NORMAL, NULL, cells);
    }
    if (t.nr) tbl_render(ctx, out, &t);
    tbl_free(&t);
  } else {
    snprintf(what, sizeof(what), "No tombstones%s%s on this hub", age[0] ? " " : "", age);
    fmt_ok(ctx, what, NULL, out);
  }
  char p[96];
  long long peers = rvi(r, "peers", 0);
  if (peers > 0)
    snprintf(p, sizeof(p), "purge sent to %lld other hub%s (they purge on their own)", peers,
             peers == 1 ? "" : "s");
  else
    snprintf(p, sizeof(p), "no other hub is linked now to send the purge to");
  effect(ctx, out, p);
}

/* ==========================================================================
 * Statistics (view 5 renders the same)
 * ========================================================================== */
static const char *const OPNAME[256] = {
 [0x01] = "CMD_PING", [0x02] = "CMD_CONFIG_PUSH", [0x03] = "CMD_CONFIG_PULL",
 [0x04] = "CMD_CONFIG_DATA", [0x05] = "CMD_UPDATE_PUBKEY", [0x06] = "CMD_PEER_SYNC",
 [0x07] = "CMD_MESH_STATE", [0x08] = "CMD_SYNC_REQUEST", [0x09] = "CMD_INVITE_REQUEST",
 [0x10] = "CMD_ADMIN_AUTH", [0x11] = "CMD_ADMIN_LIST_FULL", [0x12] = "CMD_ADMIN_ADD",
 [0x13] = "CMD_ADMIN_DEL", [0x14] = "CMD_ADMIN_REGEN_KEYS", [0x15] = "CMD_ADMIN_LIST_SUMMARY",
 [0x16] = "CMD_ADMIN_GET_PENDING", [0x17] = "CMD_ADMIN_APPROVE", [0x18] = "CMD_ADMIN_ADD_PEER",
 [0x19] = "CMD_ADMIN_LIST_PEERS", [0x1A] = "CMD_ADMIN_DEL_PEER", [0x1B] = "CMD_ADMIN_GET_PUBKEY",
 [0x1C] = "CMD_ADMIN_SET_PRIVKEY", [0x1D] = "CMD_ADMIN_GET_PRIVKEY",
 [0x1E] = "CMD_ADMIN_SET_PUBKEY", [0x1F] = "CMD_ADMIN_SYNC_MESH", [0x20] = "CMD_ADMIN_REKEY_BOT",
 [0x21] = "CMD_ADMIN_DISCONNECT_BOT", [0x22] = "CMD_ADMIN_BOT_STATUS",
 [0x23] = "CMD_ADMIN_LIST_CHANNELS", [0x24] = "CMD_ADMIN_ADD_CHANNEL",
 [0x25] = "CMD_ADMIN_DEL_CHANNEL", [0x26] = "CMD_ADMIN_LIST_MASKS", [0x27] = "CMD_ADMIN_ADD_MASK",
 [0x28] = "CMD_OP_REQUEST", [0x29] = "CMD_OP_GRANT", [0x2A] = "CMD_OP_FAILED",
 [0x2B] = "CMD_ADMIN_DEL_MASK", [0x2C] = "CMD_ADMIN_LIST_OPERS", [0x2D] = "CMD_ADMIN_ADD_OPER",
 [0x2E] = "CMD_ADMIN_DEL_OPER", [0x2F] = "CMD_ADMIN_SET_ADMIN_PASS",
 [0x30] = "CMD_ADMIN_SET_BOT_PASS", [0x31] = "CMD_ADMIN_OP_USER", [0x32] = "CMD_ADMIN_CREATE_BOT",
 [0x33] = "CMD_OP_FORWARD_REQUEST", [0x34] = "CMD_OP_FORWARD_GRANT",
 [0x35] = "CMD_OP_FORWARD_FAILED", [0x36] = "CMD_ADMIN_PURGE_TOMBSTONES",
 [0x37] = "CMD_ADMIN_SET_BIND_IP", [0x38] = "CMD_ADMIN_LIST_ALLOWLIST",
 [0x39] = "CMD_ADMIN_ADD_ALLOWLIST", [0x3A] = "CMD_ADMIN_DEL_ALLOWLIST",
 [0x3B] = "CMD_ADMIN_LIST_DENYLIST", [0x3C] = "CMD_ADMIN_ADD_DENYLIST",
 [0x3D] = "CMD_ADMIN_DEL_DENYLIST", [0x3E] = "CMD_ADMIN_SET_HUB_NAME",
 [0x3F] = "CMD_ADMIN_SET_BIND_PORT", [0x40] = "CMD_BOT_KEY_UPDATE",
 [0x41] = "CMD_ADMIN_SET_PURGE_DAYS", [0x42] = "CMD_PEER_REKEY_BOT",
 [0x43] = "CMD_ADMIN_SET_LOG_LEVEL", [0x44] = "CMD_ADMIN_SET_LOG_SIZE", [0x45] = "CMD_BOT_DELTA",
 [0x46] = "CMD_ADMIN_ADD_ADMIN", [0x47] = "CMD_ADMIN_DEL_ADMIN",
 [0x48] = "CMD_ADMIN_ADD_OPER_RECORD", [0x49] = "CMD_ADMIN_DEL_OPER_RECORD",
 [0x4A] = "CMD_ADMIN_ADD_USERMASK", [0x4B] = "CMD_ADMIN_DEL_USERMASK",
 [0x4C] = "CMD_ADMIN_SET_USERPASS", [0x4D] = "CMD_ADMIN_MATCH", [0x4E] = "CMD_ADMIN_LIST_ADMINS",
 [0x4F] = "CMD_ADMIN_LIST_OPERS_V2", [0x50] = "CMD_BOT_RELAY", [0x51] = "CMD_BOT_MSG",
 [0x52] = "CMD_ADMIN_SET_PEER_PUBKEY", [0x53] = "CMD_ADMIN_SET_OPT_FLAGS",
 [0x54] = "CMD_ADMIN_GET_OPT_FLAGS", [0x55] = "CMD_ADMIN_SET_USERKEY", [0x56] = "CMD_BOT_PRESENCE",
 [0x57] = "CMD_BOT_ROSTER", [0x58] = "CMD_BOT_TREE", [0x59] = "CMD_CHAN_REQUEST",
 [0x5A] = "CMD_CHAN_ACTION", [0x5B] = "CMD_CHAN_REPLY", [0x5C] = "CMD_CHAN_FWD_REQUEST",
 [0x5D] = "CMD_CHAN_FWD_REPLY", [0x5E] = "CMD_UPGRADE_PREPARE", [0x5F] = "CMD_UPGRADE_READY",
 [0x60] = "CMD_UPGRADE_COMMIT", [0x61] = "CMD_UPGRADE_RESULT", [0x62] = "CMD_UPGRADE_ABORT",
 [0x63] = "CMD_ADMIN_UPGRADE_NET", [0x64] = "CMD_ADMIN_UPGRADE_STATUS",
 [0x65] = "CMD_BOT_RELAY_FWD", [0x66] = "CMD_UPGRADE_FORGET", [0x67] = "CMD_PEER_BCAST",
 [0x68] = "CMD_ADMIN_STATS", [0x69] = "CMD_ACTIVITY", [0x6A] = "CMD_ACTIVITY_QUERY",
 [0x6B] = "CMD_ACTIVITY_REPLY", [0x6C] = "CMD_CONSOLE", [0x6D] = "CMD_CHAN_PROBE",
 [0x6E] = "CMD_CHAN_PROBE_ACK", [0x6F] = "CMD_CHAN_DO", [0x70] = "CMD_CHAN_DONE",
 [0x71] = "CMD_CHAN_ELECT_FWD", [0x72] = "CMD_CHAN_ELECT_ACK", [0x73] = "CMD_CHAN_ELECT_DO",
 [0x74] = "CMD_CHAN_ELECT_DONE", [0x75] = "CMD_ADMIN_INVITE_USER",
 [0x76] = "CMD_ADMIN_CHAN_MODE", [0x77] = "CMD_ADMIN_CHAN_SET", [0x78] = "CMD_ADMIN_BAN",
 [0x79] = "CMD_ADMIN_NET_SET", [0x7A] = "CMD_ADMIN_SET_SSH", [0x7B] = "CMD_CHAN_EVENT", [0x7C] = "CMD_ADMIN_USER_ACCESS", [0x7D] = "CMD_USER_CHAN_REQUEST", [0x7E] = "CMD_USER_CHAN_RESULT", [0x7F] = "CMD_BOT_RETIRE", [0x80] = "CMD_BOT_RETIRE_ACK", [0x81] = "CMD_ADMIN_LIST_REVOKED", [0x82] = "CMD_ADMIN_PEER_REFS",
};

static unsigned long long rvu(const crec_t *r, const char *k) {
  const char *v = rv(r, k);
  return v ? strtoull(v, NULL, 10) : 0;
}

static void count_kv(sb_t *b, const char *label, unsigned long long n, int col) {
  char c[32];
  fmt_count(n, c, sizeof(c));
  sb_pad(b, col);
  sb_addf(b, "%s  %s", label, c);
}

/* The maintenance countdowns of a stats reply ("timer" records). */
static void render_timers(const fmt_ctx_t *ctx, const creply_t *rep, const crec_t *ld,
                          flines_t *out) {
  static const struct { const char *k, *label; } NAMES[] = {
      {"gossip", "mesh gossip"},      {"entropy", "anti-entropy sync"},
      {"scan", "client scan"},        {"ipclean", "ip limit cleanup"},
      {"peers", "hub reconnect"},     {"purge", "tombstone purge"}};
  static const col_t cols[] = {{"JOB", 'L', 1}, {"EVERY", 'R', 1}, {"NEXT RUN", 'R', 1}};
  tbl_t t;
  tbl_init(&t, cols, 3, -1, 1, 1);
  for (int i = 0; i < rep->n; i++) {
    const crec_t *r = &rep->r[i];
    if (strcmp(r->type, "timer")) continue;
    const char *k = rv(r, "name") ? rv(r, "name") : "?", *label = k;
    for (size_t j = 0; j < sizeof(NAMES) / sizeof(NAMES[0]); j++)
      if (!strcmp(NAMES[j].k, k)) label = NAMES[j].label;
    char every[48], in[48];
    fmt_dur3(rvi(r, "every", 0), every, sizeof(every));
    const char *iv = rv(r, "in");
    if (iv && !strcmp(iv, "off")) snprintf(in, sizeof(in), "off");
    else fmt_dur3(rvi(r, "in", 0), in, sizeof(in));
    const char *cells[3] = {label, every, in};
    tbl_row(ctx, &t, RL_NORMAL, NULL, cells);
  }
  if (!t.nr) {
    tbl_free(&t);
    return;
  }
  flines_add(out, RL_NORMAL, "");
  fmt_title(ctx, out, "Maintenance timers",
            ld ? (rvi(ld, "dirty", 0) ? "config unsaved" : "config saved") : NULL);
  tbl_render(ctx, out, &t);
  tbl_free(&t);
}

static void render_stats(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  char right[96], up[48];
  fmt_dur3(rvi(&rep->res, "up", 0), up, sizeof(up));
  snprintf(right, sizeof(right), "%s %s up %s", ctx->hubname && *ctx->hubname ? ctx->hubname : "hub",
           GL(G_DOT), up);
  fmt_title(ctx, out, "Hub statistics", right);
  const crec_t *cfg = NULL, *sy = NULL, *ld = NULL;
  for (int i = 0; i < rep->n; i++) {
    if (!strcmp(rep->r[i].type, "cfg")) cfg = &rep->r[i];
    if (!strcmp(rep->r[i].type, "sync")) sy = &rep->r[i];
    if (!strcmp(rep->r[i].type, "load")) ld = &rep->r[i];
  }
  sb_t b = {0};
  if (cfg) {
    line(out, RL_HEAD, " Config pushes to bots");
    count_kv(&b, "  sent", rvu(cfg, "sent"), 0);
    count_kv(&b, "skipped (unchanged)", rvu(cfg, "same"), 24);
    count_kv(&b, "lost", rvu(cfg, "lost"), 56);
    sb_emit(&b, out, RL_NORMAL);
  }
  if (sy) {
    line(out, RL_HEAD, " Sync frames from other hubs");
    count_kv(&b, "  frames", rvu(sy, "frames"), 0);
    count_kv(&b, "no-op", rvu(sy, "noop"), 24);
    count_kv(&b, "records", rvu(sy, "records"), 40);
    count_kv(&b, "applied", rvu(sy, "applied"), 60);
    sb_emit(&b, out, RL_NORMAL);
  }
  if (ld) {
    line(out, RL_HEAD, " Connections");
    count_kv(&b, "  total", rvu(ld, "clients"), 0);
    count_kv(&b, "bots", rvu(ld, "bots"), 24);
    count_kv(&b, "hubs", rvu(ld, "peers"), 40);
    count_kv(&b, "authing", rvu(ld, "authing"), 60);
    sb_emit(&b, out, RL_NORMAL);
  }
  sb_free(&b);
  render_timers(ctx, rep, ld, out);
  flines_add(out, RL_NORMAL, "");
  fmt_title(ctx, out, "Traffic by message", "sorted by bytes");
  int n = 0;
  int *ix = calloc((size_t)rep->n + 1, sizeof(int));
  if (!ix) return;
  for (int i = 0; i < rep->n; i++)
    if (!strcmp(rep->r[i].type, "op")) ix[n++] = i;
  /* most bytes first, then the opcode */
  for (int i = 1; i < n; i++) {
    int x = ix[i], j = i - 1;
    unsigned long long bx = rvu(&rep->r[x], "rx_b") + rvu(&rep->r[x], "tx_b");
    while (j >= 0) {
      unsigned long long bj = rvu(&rep->r[ix[j]], "rx_b") + rvu(&rep->r[ix[j]], "tx_b");
      const char *cx = rv(&rep->r[x], "code"), *cj = rv(&rep->r[ix[j]], "code");
      if (bx > bj || (bx == bj && cx && cj && strcmp(cx, cj) < 0)) {
        ix[j + 1] = ix[j];
        j--;
      } else {
        break;
      }
    }
    ix[j + 1] = x;
  }
  static const col_t cols[] = {{"OPCODE", 'L', 1}, {"NAME", 'L', 1}, {"IN FRAMES", 'R', 1},
                               {"IN BYTES", 'R', 1}, {"OUT FRAMES", 'R', 2}, {"OUT BYTES", 'R', 2}};
  tbl_t t;
  tbl_init(&t, cols, 6, -1, 1, 1);
  unsigned long long tot[4] = {0, 0, 0, 0};
  for (int k = 0; k < n; k++) {
    const crec_t *r = &rep->r[ix[k]];
    const char *code = rv(r, "code") ? rv(r, "code") : "?";
    unsigned long op = strtoul(code, NULL, 16);
    const char *name = op < 256 && OPNAME[op] ? OPNAME[op] : "?";
    unsigned long long v[4] = {rvu(r, "rx_f"), rvu(r, "rx_b"), rvu(r, "tx_f"), rvu(r, "tx_b")};
    char c[4][32];
    for (int q = 0; q < 4; q++) {
      tot[q] += v[q];
      if (q % 2) fmt_bytes(v[q], c[q], sizeof(c[q]));
      else fmt_count(v[q], c[q], sizeof(c[q]));
    }
    const char *cells[6] = {code, name, c[0], c[1], c[2], c[3]};
    tbl_row(ctx, &t, RL_NORMAL, NULL, cells);
  }
  if (n) {
    char c[4][32];
    for (int q = 0; q < 4; q++) {
      if (q % 2) fmt_bytes(tot[q], c[q], sizeof(c[q]));
      else fmt_count(tot[q], c[q], sizeof(c[q]));
    }
    const char *cells[6] = {"total", " ", c[0], c[1], c[2], c[3]};
    tbl_row(ctx, &t, RL_HEAD, NULL, cells);
    tbl_render(ctx, out, &t);
  } else {
    empty_note(out, "no traffic yet", NULL);
  }
  tbl_free(&t);
  free(ix);
}

/* ==========================================================================
 * Log
 * ========================================================================== */
static void render_log_show(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const crec_t *r = &rep->res;
  fmt_title(ctx, out, "Log", ctx->hubname);
  char v[256], a[32], b[32], c1[32], c2[32];
  const int L = 13;
  fmt_bytes((unsigned long long)rvi(r, "file_bytes", 0), a, sizeof(a));
  fmt_bytes((unsigned long long)rvi(r, "limit", 0), b, sizeof(b));
  snprintf(v, sizeof(v), "%-10s  %s %s %s of %s", level_name(rvi(r, "file_level", 0)),
           rv(r, "file") ? rv(r, "file") : "?", GL(G_DOT), a, b);
  fmt_card_line(ctx, out, L, "file", v, RL_NORMAL);
  fmt_count((unsigned long long)rvi(r, "ring_lines", 0), c1, sizeof(c1));
  fmt_count((unsigned long long)rvi(r, "ring_cap", 0), c2, sizeof(c2));
  if (rvi(r, "ring_oldest", 0) > 0) {
    fmt_when(rvi(r, "ring_oldest", 0), ctx->now, a, sizeof(a));
    snprintf(v, sizeof(v), "%-10s  %s of %s lines %s oldest %s",
             level_name(rvi(r, "console_level", 0)), c1, c2, GL(G_DOT), a);
  } else {
    snprintf(v, sizeof(v), "%-10s  %s of %s lines", level_name(rvi(r, "console_level", 0)), c1, c2);
  }
  fmt_card_line(ctx, out, L, "console ring", v, RL_NORMAL);
  if (ctx->session_log) fmt_card_line(ctx, out, L, "this session", ctx->session_log, RL_NORMAL);
}

static void render_log_set(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const crec_t *r = &rep->res;
  const char *setting = rv(r, "setting") ? rv(r, "setting") : "?";
  char subj[256], ph[256], a[32], b[32];
  if (!strcmp(setting, "size")) {
    fmt_bytes((unsigned long long)rvi(r, "old", 0), a, sizeof(a));
    fmt_bytes((unsigned long long)rvi(r, "value", 0), b, sizeof(b));
    long long asked = rvi(r, "asked", 0), val = rvi(r, "value", 0);
    if (asked != val) {
      char q[32];
      fmt_bytes((unsigned long long)asked, q, sizeof(q));
      snprintf(subj, sizeof(subj), "size   %s %s %s (the %s; %s was asked)", a, GL(G_ARROW), b,
               asked > val ? "maximum" : "minimum", q);
    } else {
      snprintf(subj, sizeof(subj), "size   %s %s %s", a, GL(G_ARROW), b);
    }
    fmt_ok(ctx, "Log", subj, out);
    if (rvi(r, "file_level", 1) == 0)
      warn(ctx, out, "the file level is none: nothing is written until log set file <level>");
    return;
  }
  snprintf(subj, sizeof(subj), "%s   %s %s %s", setting, level_name(rvi(r, "old", 0)),
           GL(G_ARROW), level_name(rvi(r, "value", 0)));
  fmt_ok(ctx, "Log", subj, out);
  if (!strcmp(setting, "file")) {
    if (rvi(r, "value", 0) == 0) {
      effect(ctx, out, "the log file is off");
    } else {
      fmt_bytes((unsigned long long)rvi(r, "limit", 0), b, sizeof(b));
      snprintf(ph, sizeof(ph), "writes %s and worse to %s, limit %s", level_name(rvi(r, "value", 0)),
               rv(r, "file") ? rv(r, "file") : "?", b);
      effect(ctx, out, ph);
    }
  } else {
    snprintf(ph, sizeof(ph), "the console ring keeps %s and worse; F2 / log on <level> filter further per session",
             level_name(rvi(r, "value", 0)));
    effect(ctx, out, ph);
  }
}

/* ==========================================================================
 * Access lists
 * ========================================================================== */
static bool ip4(const char *s, unsigned long *out) {
  unsigned long v = 0;
  int parts = 0;
  while (*s && parts < 4) {
    if (!isdigit((unsigned char)*s)) return false;
    unsigned long p = 0;
    int digits = 0;
    while (isdigit((unsigned char)*s) && digits < 4) {
      p = p * 10 + (unsigned long)(*s - '0');
      s++;
      digits++;
    }
    if (p > 255) return false;
    v = (v << 8) | p;
    parts++;
    if (*s == '.' && parts < 4) s++;
    else break;
  }
  if (parts != 4) return false;
  *out = v;
  return *s == '\0' || *s == '/';
}

static bool acl_covers(const char *pattern, const char *ip) {
  unsigned long net, a;
  if (!pattern || !ip || !ip4(pattern, &net) || !ip4(ip, &a)) return false;
  const char *sl = strchr(pattern, '/');
  long bits = sl ? strtol(sl + 1, NULL, 10) : 32;
  if (bits < 0 || bits > 32) return false;
  unsigned long mask = bits == 0 ? 0 : (0xFFFFFFFFul << (32 - bits)) & 0xFFFFFFFFul;
  return (a & mask) == (net & mask);
}

static void render_acl_list(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const crec_t *r = &rep->res;
  const char *self = rv(r, "self") ? rv(r, "self") : "?";
  char right[160];
  snprintf(right, sizeof(right), "allow %lld %s deny %lld %s you: %s %s %s", rvi(r, "allow", 0),
           GL(G_DOT), rvi(r, "deny", 0), GL(G_DOT), rv(r, "self_ip") ? rv(r, "self_ip") : "?",
           !strcmp(self, "denied") ? GL(G_ERR) : GL(G_ON), self);
  fmt_title(ctx, out, "Access lists", right);
  for (int pass = 0; pass < 2; pass++) {
    const char *list = pass == 0 ? "allow" : "deny";
    fmt_title(ctx, out, pass == 0 ? "Allow" : "Deny",
              pass == 0 ? "only these addresses may connect" : "these addresses are refused");
    static const col_t cols[] = {{"#", 'R', 1}, {"PATTERN", 'L', 1}, {"COVERS", 'L', 1},
                                 {"SCOPE", 'L', 1}, {"ADDED", 'L', 1}, {"", 'L', 1}};
    tbl_t t;
    tbl_init(&t, cols, 6, -1, 1, 1);
    for (int i = 0; i < rep->n; i++) {
      const crec_t *x = &rep->r[i];
      if (strcmp(x->type, "acl") || !rv(x, "list") || strcmp(rv(x, "list"), list)) continue;
      char nn[16], cov[48], c[32], added[64];
      snprintf(nn, sizeof(nn), "%lld", rvi(x, "n", 0));
      unsigned long long sz = strtoull(rv(x, "size") ? rv(x, "size") : "0", NULL, 10);
      fmt_count(sz, c, sizeof(c));
      snprintf(cov, sizeof(cov), "%s address%s", c, sz == 1 ? "" : "es");
      when_ago(ctx, rvi(x, "ts", 0), added, sizeof(added));
      char you[16];
      snprintf(you, sizeof(you), "%s you", ctx->ascii ? "<-" : "←");
      const char *cells[6] = {nn, rv(x, "pattern"), cov,
                              rv(x, "scope") ? rv(x, "scope") : "all", added,
                              acl_covers(rv(x, "pattern"), rv(r, "self_ip")) ? you : " "};
      tbl_row(ctx, &t, RL_NORMAL, NULL, cells);
    }
    if (t.nr) tbl_render(ctx, out, &t);
    else if (pass == 0) line(out, RL_DIM, "  (empty %s every address may connect, subject to the deny list)", GL(G_DASH));
    else line(out, RL_DIM, "  (empty)");
    tbl_free(&t);
  }
}

static void render_acl_change(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const crec_t *r = &rep->res;
  bool add = !strcmp(rep->code, "acl.added");
  const char *list = rv(r, "list") ? rv(r, "list") : "?";
  char what[32], subj[160], c[32];
  bool cscope = rv(r, "scope") && !strcmp(rv(r, "scope"), "console");
  snprintf(what, sizeof(what), "%s list%s", !strcmp(list, "allow") ? "Allow" : "Deny",
           cscope ? " (console)" : "");
  unsigned long long sz = strtoull(rv(r, "size") ? rv(r, "size") : "0", NULL, 10);
  fmt_count(sz, c, sizeof(c));
  snprintf(subj, sizeof(subj), "%s   %s  (%s address%s)", add ? "added" : "removed",
           rv(r, "pattern") ? rv(r, "pattern") : "?", c, sz == 1 ? "" : "es");
  fmt_ok(ctx, what, subj, out);
  effect(ctx, out, "local to this hub (the lists are not synced)");
  if (cscope) effect(ctx, out, "console scope: applies to SSH logins only, bots and other hubs are not affected");
  if (rvb(r, "first"))
    warn(ctx, out, cscope ? "the console allow list was empty: from now on only listed addresses can open the console"
                          : "the allow list was empty: from now on only listed addresses can connect");
  if (rvb(r, "empty"))
    warn(ctx, out, cscope ? "the console allow list is empty now: every address may open the console"
                          : "the allow list is empty now: every address may connect");
  long long closing = rvi(r, "closing", 0);
  if (closing > 0) {
    char p[96];
    snprintf(p, sizeof(p), "closing %lld connection%s it no longer permits", closing,
             closing == 1 ? "" : "s");
    effect(ctx, out, p);
  }
}

/* ==========================================================================
 * Options
 * ========================================================================== */
static const struct {
  char flag;
  const char *meaning;
} OPT_FLAGS[] = {
  {'h', "hub-only mutation: bots refuse config changes not coming from a hub"},
  {'F', "config frozen (an upgrade is running, or was left frozen)"},
};
#define NOPT ((int)(sizeof(OPT_FLAGS) / sizeof(OPT_FLAGS[0])))

static void render_option_list(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const char *flags = rv(&rep->res, "flags") ? rv(&rep->res, "flags") : "";
  char right[64], fp[40];
  flags_phrase(flags, fp, sizeof(fp));
  snprintf(right, sizeof(right), "flags: %s", fp);
  fmt_title(ctx, out, "Network options", right);
  static const col_t cols[] = {{"FLAG", 'L', 1}, {"STATE", 'L', 1}, {"MEANING", 'L', 2}};
  tbl_t t;
  tbl_init(&t, cols, 3, -1, 0, 1);
  for (int i = 0; i < NOPT; i++) {
    char f[2] = {OPT_FLAGS[i].flag, 0};
    bool on = strchr(flags, OPT_FLAGS[i].flag) != NULL;
    const char *cells[3] = {f, on ? "on" : "off", OPT_FLAGS[i].meaning};
    tbl_row(ctx, &t, on ? RL_NORMAL : RL_DIM, NULL, cells);
  }
  for (const char *p = flags; *p; p++) {
    bool known = false;
    for (int i = 0; i < NOPT; i++) known |= OPT_FLAGS[i].flag == *p;
    if (known) continue;
    char f[2] = {*p, 0};
    const char *cells[3] = {f, "on", "(unknown flag)"};
    tbl_row(ctx, &t, RL_WARN, NULL, cells);
  }
  tbl_render(ctx, out, &t);
  tbl_free(&t);
  line(out, RL_DIM, "  change with option set <flags>   %s   clear with option set -", GL(G_DOT));
}

static void render_option_set(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const crec_t *r = &rep->res;
  char o[40], n[40], subj[128], ph[128];
  flags_phrase(rv(r, "old"), o, sizeof(o));
  flags_phrase(rv(r, "value"), n, sizeof(n));
  snprintf(subj, sizeof(subj), "flags   %s %s %s", o, GL(G_ARROW), n);
  fmt_ok(ctx, "Network options", subj, out);
  sync_push_phrase(ph, sizeof(ph), rvi(r, "peers", 0), rvi(r, "bots", 0));
  effect(ctx, out, ph);
}

/* ==========================================================================
 * Users
 * ========================================================================== */
static void user_seen(const fmt_ctx_t *ctx, const crec_t *u, bool with_ip, char *out, size_t cap) {
  const char *name = rv(u, "name");
  if (name && ctx->admin && !strcasecmp(name, ctx->admin)) {
    if (with_ip && ctx->ip) snprintf(out, cap, "now (this session, from %s)", ctx->ip);
    else snprintf(out, cap, "now (this session)");
    return;
  }
  when_ago(ctx, rvi(u, "seen", 0), out, cap);
}

/* An admin's flags or an oper's channels for the user tables (plan U9). */
static void user_access(const fmt_ctx_t *ctx, const crec_t *u, char *out, size_t cap) {
  if (rv(u, "flags")) snprintf(out, cap, "%s%s", rvs(u, "flags") ? "+" : "",
                               rvs(u, "flags") ? rv(u, "flags") : "(none)");
  else if (rv(u, "chans")) snprintf(out, cap, "%s", rvs(u, "chans") ? rv(u, "chans") : "(none)");
  else snprintf(out, cap, "%s", GL(G_DASH));
}

/* "+chu" -> "channels, opers, upgrades"; "a" -> "full admin". */
static void flags_words(const char *flags, char *out, size_t cap) {
  static const struct { char f; const char *w; } W[] = {
    {'a', "full admin"}, {'b', "bots"}, {'c', "channels"}, {'h', "hub"}, {'o', "opers"},
    {'u', "upgrades"}};
  size_t o = 0;
  out[0] = '\0';
  for (const char *p = flags ? flags : ""; *p; p++)
    for (size_t i = 0; i < sizeof(W) / sizeof(W[0]); i++)
      if (W[i].f == *p && o + 1 < cap) {
        int w = snprintf(out + o, cap - o, "%s%s", o ? ", " : "", W[i].w);
        if (w > 0) o += (size_t)w < cap - o ? (size_t)w : cap - o - 1;
      }
  if (!out[0]) snprintf(out, cap, "no flags: views only");
}

static void render_user_list(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const crec_t *r = &rep->res;
  char title[48], right[96];
  if (rvs(r, "role")) snprintf(title, sizeof(title), "Users %s %s", GL(G_DOT), rv(r, "role"));
  else snprintf(title, sizeof(title), "Users");
  long long a = rvi(r, "admins", 0), o = rvi(r, "opers", 0), m = rvi(r, "masks", 0);
  snprintf(right, sizeof(right), "%lld admin%s %s %lld oper%s %s %lld mask%s", a, a == 1 ? "" : "s",
           GL(G_DOT), o, o == 1 ? "" : "s", GL(G_DOT), m, m == 1 ? "" : "s");
  fmt_title(ctx, out, title, right);
  static const col_t cols[] = {{"ROLE", 'L', 1}, {"NAME", 'L', 1}, {"ACCESS", 'L', 1},
                               {"KEY", 'L', 1}, {"LAST SEEN", 'L', 1}, {"MASKS", 'R', 1},
                               {"CONSOLES", 'R', 1}};
  tbl_t t;
  tbl_init(&t, cols, 7, -1, 1, 1);
  for (int i = 0; i < rep->n; i++) {
    const crec_t *u = &rep->r[i];
    if (strcmp(u->type, "user")) continue;
    char seen[96], masks[16], cons[16], acc[512];
    user_access(ctx, u, acc, sizeof(acc));
    user_seen(ctx, u, false, seen, sizeof(seen));
    snprintf(masks, sizeof(masks), "%lld", rvi(u, "masks", 0));
    if (rv(u, "sessions")) snprintf(cons, sizeof(cons), "%lld", rvi(u, "sessions", 0));
    else cons[0] = '\0';
    const char *cells[7] = {rv(u, "role"), rv(u, "name"), acc,
                            rvs(u, "fp") ? rv(u, "fp") : "(no key)", seen, masks, cons};
    tbl_row(ctx, &t, RL_NORMAL, rv(u, "role"), cells);
  }
  if (!t.nr) {
    empty_note(out, "no users", "user add admin <name> <key> <mask>");
    tbl_free(&t);
    return;
  }
  tbl_render(ctx, out, &t);
  tbl_free(&t);
  rule_line(ctx, out);
  line(out, RL_DIM, "  user show <name> for masks and their last use %s ACCESS: an admin's flags, an oper's channels",
       GL(G_DOT));
}

static void render_user_show(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  bool any = false;
  for (int i = 0; i < rep->n; i++) {
    const crec_t *u = &rep->r[i];
    if (strcmp(u->type, "user")) continue;
    if (any) flines_add(out, RL_NORMAL, "");
    any = true;
    char title[96], v[160];
    snprintf(title, sizeof(title), "User %s", rv(u, "name") ? rv(u, "name") : "?");
    fmt_title(ctx, out, title, rv(u, "role"));
    const int L = 10;
    if (rv(u, "flags")) {
      char fw[96];
      flags_words(rv(u, "flags"), fw, sizeof(fw));
      snprintf(v, sizeof(v), "%s%s  (%s)", rvs(u, "flags") ? "+" : "",
               rvs(u, "flags") ? rv(u, "flags") : "(none)", fw);
      fmt_card_line(ctx, out, L, "flags", v, rvs(u, "flags") ? RL_NORMAL : RL_WARN);
    } else if (rv(u, "chans")) {
      if (!rvs(u, "chans")) snprintf(v, sizeof(v), "(none: no channel access)");
      else if (!strcmp(rv(u, "chans"), "*")) snprintf(v, sizeof(v), "* (every channel)");
      else snprintf(v, sizeof(v), "%s", rv(u, "chans"));
      fmt_card_line(ctx, out, L, "channels", v, rvs(u, "chans") ? RL_NORMAL : RL_WARN);
    }
    fmt_card_line(ctx, out, L, "key", rvs(u, "fp") ? rv(u, "fp") : "(no key)", RL_NORMAL);
    user_seen(ctx, u, true, v, sizeof(v));
    fmt_card_line(ctx, out, L, "last seen", v, RL_NORMAL);
    if (rv(u, "sessions")) {
      long long s = rvi(u, "sessions", 0);
      snprintf(v, sizeof(v), "%lld open session%s", s, s == 1 ? "" : "s");
      fmt_card_line(ctx, out, L, "console", v, RL_NORMAL);
    }
    static const char *const known[] = {"name", "role", "fp", "seen", "masks", "sessions",
                                        "flags", "chans", NULL};
    unknown_keys(ctx, out, u, known, L);
    static const col_t cols[] = {{"MASK", 'L', 1}, {"LAST USED", 'L', 1}};
    tbl_t t;
    tbl_init(&t, cols, 2, -1, 0, 0);
    t.indent = 3;
    /* this user's mask| records follow its user| record */
    for (int k = i + 1; k < rep->n && strcmp(rep->r[k].type, "user"); k++) {
      const crec_t *m = &rep->r[k];
      if (strcmp(m->type, "mask")) continue;
      char used[64];
      when_ago(ctx, rvi(m, "used", 0), used, sizeof(used));
      const char *cells[2] = {rv(m, "mask"), used};
      tbl_row(ctx, &t, RL_NORMAL, NULL, cells);
    }
    if (t.nr) tbl_render(ctx, out, &t);
    else line(out, RL_DIM, "   (no masks: no bot recognises this user on IRC)");
    tbl_free(&t);
  }
  if (!any) empty_note(out, "no users", "user add admin <name> <key> <mask>");
}

static void render_user_change(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const crec_t *r = &rep->res;
  const char *code = rep->code;
  const char *name = rv(r, "name") ? rv(r, "name") : "?";
  char what[96], subj[256], ph[160];
  sync_push_phrase(ph, sizeof(ph), rvi(r, "peers", 0), rvi(r, "bots", 0));
  if (!strcmp(code, "user.added")) {
    snprintf(subj, sizeof(subj), "%s   %s", name, rv(r, "role") ? rv(r, "role") : "?");
    fmt_ok(ctx, "User added", subj, out);
    res_kv(out, "key", rvs(r, "fp") ? rv(r, "fp") : "?");
    res_kv(out, "mask", rvs(r, "mask") ? rv(r, "mask") : "?");
    if (rv(r, "flags")) {
      char fw[160];
      flags_words(rv(r, "flags"), fw, sizeof(fw));
      snprintf(subj, sizeof(subj), "+%s  (%s)", rv(r, "flags"), fw);
      res_kv(out, "flags", subj);
    }
    if (rvs(r, "chans")) res_kv(out, "channels", !strcmp(rv(r, "chans"), "*") ? "* (every channel)"
                                                                         : rv(r, "chans"));
    effect(ctx, out, ph);
    if (rv(r, "role") && !strcmp(rv(r, "role"), "admin")) {
      snprintf(subj, sizeof(subj), "%s logs in with: ssh -i <their>_ed25519 -p %lld %s@<this hub>", name,
               rvi(r, "port", 0), name);
    } else {
      snprintf(subj, sizeof(subj), "%s authenticates to bots from IRC with their key", name);
    }
    res_kv(out, "next", subj);
  } else if (!strcmp(code, "user.removed")) {
    long long m = rvi(r, "masks", 0);
    snprintf(subj, sizeof(subj), "%s   %s, with %lld mask%s", name, rv(r, "role") ? rv(r, "role") : "?",
             m, m == 1 ? "" : "s");
    fmt_ok(ctx, "User removed", subj, out);
    effect(ctx, out, ph);
    long long s = rvi(r, "sessions", 0);
    if (s > 0) {
      snprintf(subj, sizeof(subj), "%lld open console session%s of %s closed", s, s == 1 ? "" : "s", name);
      effect(ctx, out, subj);
    }
  } else if (!strcmp(code, "user.set")) {
    snprintf(what, sizeof(what), "User %s", name);
    snprintf(subj, sizeof(subj), "key   %s %s %s", rvs(r, "old") ? rv(r, "old") : "(none)", GL(G_ARROW),
             rvs(r, "value") ? rv(r, "value") : "?");
    fmt_ok(ctx, what, subj, out);
    effect(ctx, out, ph);
    if (rv(r, "role") && !strcmp(rv(r, "role"), "admin")) {
      long long s = rvi(r, "sessions", 0);
      snprintf(subj, sizeof(subj), "%lld open console session%s closed", s, s == 1 ? "" : "s");
      effect(ctx, out, subj);
    }
  } else if (!strcmp(code, "user.flags")) {
    snprintf(what, sizeof(what), "User %s", name);
    snprintf(subj, sizeof(subj), "flags   +%s %s +%s", rvs(r, "old") ? rv(r, "old") : "",
             GL(G_ARROW), rvs(r, "flags") ? rv(r, "flags") : "");
    fmt_ok(ctx, what, subj, out);
    char fw[160];
    flags_words(rv(r, "flags"), fw, sizeof(fw));
    snprintf(subj, sizeof(subj), "now: %s", fw);
    res_kv(out, "can", subj);
    if (!rvb(r, "written")) effect(ctx, out, "no change: they already had those flags");
    else effect(ctx, out, ph);
  } else if (!strcmp(code, "user.chan")) {
    snprintf(what, sizeof(what), "User %s", name);
    bool add = rv(r, "action") && !strcmp(rv(r, "action"), "add");
    const char *ch = rv(r, "chan") ? rv(r, "chan") : "?";
    if (!strcmp(ch, "*")) snprintf(subj, sizeof(subj), "%s", add ? "every channel (*)" : "every channel removed");
    else snprintf(subj, sizeof(subj), "channel %s   %s", add ? "added" : "removed", ch);
    fmt_ok(ctx, what, subj, out);
    res_kv(out, "channels", !rvs(r, "chans") ? "(none: no channel access)"
                            : !strcmp(rv(r, "chans"), "*") ? "* (every channel)" : rv(r, "chans"));
    if (!rvb(r, "written")) effect(ctx, out, "no change: they already had that");
    else effect(ctx, out, ph);
  } else {
    bool add = !strcmp(code, "user.mask_added");
    long long m = rvi(r, "masks", 0);
    snprintf(what, sizeof(what), "User %s", name);
    if (add) snprintf(subj, sizeof(subj), "mask added   %s   (%lld mask%s now)", rv(r, "mask") ? rv(r, "mask") : "?",
                      m, m == 1 ? "" : "s");
    else snprintf(subj, sizeof(subj), "mask removed   %s   (%lld left)", rv(r, "mask") ? rv(r, "mask") : "?", m);
    fmt_ok(ctx, what, subj, out);
    effect(ctx, out, ph);
    if (!add && m == 0) {
      snprintf(subj, sizeof(subj), "%s has no masks left: the console still works, but no bot will recognise them on IRC",
               name);
      warn(ctx, out, subj);
    }
  }
}

/* ==========================================================================
 * Channels (the CHAN_SETTINGS registry: a new setting is one row here)
 * ========================================================================== */
static const struct {
  const char *key, *head, *label;
} CHAN_SETTINGS[] = {
  {"key", "KEY", "key"},
  {"modes", "MODES", "modes"},
};
#define NCHANSET ((int)(sizeof(CHAN_SETTINGS) / sizeof(CHAN_SETTINGS[0])))

static void chan_value(const char *key, const char *v, char *out, size_t cap) {
  if (!strcmp(key, "modes") && v && *v) snprintf(out, cap, "+%s", v);
  else snprintf(out, cap, "%s", v ? v : "");
}

static void render_channel_list(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  long long count = rvi(&rep->res, "count", 0);
  char right[96];
  snprintf(right, sizeof(right), "%lld channel%s %s %lld bots online", count, count == 1 ? "" : "s",
           GL(G_DOT), rvi(&rep->res, "bots_online", 0));
  fmt_title(ctx, out, "Channels", right);
  /* CHANNEL, the registry's settings, ADDED / CHANGED, OTHER (unknown set.*) */
  col_t cols[2 + NCHANSET + 1];
  int nc = 0;
  cols[nc++] = (col_t){"CHANNEL", 'L', 1};
  for (int i = 0; i < NCHANSET; i++) cols[nc++] = (col_t){CHAN_SETTINGS[i].head, 'L', 2};
  cols[nc++] = (col_t){"ADDED / CHANGED", 'L', 1};
  bool other = false;
  for (int i = 0; i < rep->n; i++) {
    const crec_t *c = &rep->r[i];
    if (strcmp(c->type, "chan")) continue;
    for (int k = 0; k < c->n; k++) {
      bool known = !strcmp(c->k[k], "name") || !strcmp(c->k[k], "ts");
      for (int s = 0; s < NCHANSET && !known; s++) known = !strcmp(c->k[k], CHAN_SETTINGS[s].key);
      other |= !known;
    }
  }
  if (other) cols[nc++] = (col_t){"OTHER", 'L', 2};
  tbl_t t;
  tbl_init(&t, cols, nc, -1, 0, 0);
  int nr = 0;
  sortrow_t *v = collect(rep, "chan", "name", NULL, &nr);
  int keyed = 0;
  for (int i = 0; i < nr; i++) {
    const crec_t *c = v[i].r;
    char vals[NCHANSET][128], when[64];
    const char *cells[2 + NCHANSET + 1];
    int k = 0;
    cells[k++] = rv(c, "name");
    for (int s = 0; s < NCHANSET; s++) {
      chan_value(CHAN_SETTINGS[s].key, rv(c, CHAN_SETTINGS[s].key), vals[s], sizeof(vals[s]));
      cells[k++] = vals[s];
    }
    when_ago(ctx, rvi(c, "ts", 0), when, sizeof(when));
    cells[k++] = when;
    sb_t o = {0};
    if (other) {
      for (int q = 0; q < c->n; q++) {
        bool known = !strcmp(c->k[q], "name") || !strcmp(c->k[q], "ts");
        for (int s = 0; s < NCHANSET && !known; s++) known = !strcmp(c->k[q], CHAN_SETTINGS[s].key);
        if (!known) sb_addf(&o, "%s%s=%s", o.len ? " " : "", c->k[q], c->v[q]);
      }
      cells[k++] = o.p ? o.p : "";
    }
    if (rvs(c, "key")) keyed++;
    tbl_row(ctx, &t, RL_NORMAL, NULL, cells);
    sb_free(&o);
  }
  free(v);
  if (!t.nr) {
    empty_note(out, "no channels configured", "channel add <#chan> [key]");
    tbl_free(&t);
    return;
  }
  tbl_render(ctx, out, &t);
  tbl_free(&t);
  rule_line(ctx, out);
  line(out, RL_DIM, "  %d open %s %d with a key      channel show <#chan> for detail", nr - keyed,
       GL(G_DOT), keyed);
}

static const char *modes_source_phrase(const char *src);
static void overrides_phrase(const char *ov, char *out, size_t cap);
static bool settings_card(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out, int L);

static void render_channel_show(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const crec_t *c = NULL;
  for (int i = 0; i < rep->n && !c; i++)
    if (!strcmp(rep->r[i].type, "chan")) c = &rep->r[i];
  if (!c) return;
  char title[96], v[160];
  snprintf(title, sizeof(title), "Channel %s", rv(c, "name") ? rv(c, "name") : "?");
  fmt_title(ctx, out, title, "managed");
  const int L = 12;
  if (rvs(&rep->res, "want")) {
    /* 2.4.5: the key, the stored modes (and where they come from), the live
     * modes a bot last reported, the channel's own settings, its bans */
    const crec_t *res = &rep->res;
    fmt_card_line(ctx, out, L, "key", rvs(c, "key") ? rv(c, "key") : GL(G_DASH), RL_NORMAL);
    snprintf(v, sizeof(v), "%s   (%s)", rv(res, "want"), modes_source_phrase(rv(res, "want_src")));
    fmt_card_line(ctx, out, L, "modes", v, RL_NORMAL);
    if (rvs(c, "modes")) snprintf(v, sizeof(v), "+%s   (i and k as last reported by a bot)", rv(c, "modes"));
    else snprintf(v, sizeof(v), "not reported");
    fmt_card_line(ctx, out, L, "live modes", v, RL_NORMAL);
    if (!settings_card(ctx, rep, out, L)) {
      char ov[512];
      overrides_phrase(rv(res, "overrides"), ov, sizeof(ov));
      fmt_card_line(ctx, out, L, "settings", ov[0] ? ov : "all default", RL_NORMAL);
    }
    snprintf(v, sizeof(v), "%lld", rvi(res, "bans", 0));
    fmt_card_line(ctx, out, L, "bans", v, RL_NORMAL);
  } else {
    for (int s = 0; s < NCHANSET; s++) {
      chan_value(CHAN_SETTINGS[s].key, rv(c, CHAN_SETTINGS[s].key), v, sizeof(v));
      fmt_card_line(ctx, out, L, CHAN_SETTINGS[s].label, v[0] ? v : GL(G_DASH), RL_NORMAL);
    }
  }
  when_ago(ctx, rvi(c, "ts", 0), v, sizeof(v));
  fmt_card_line(ctx, out, L, "changed", v, RL_NORMAL);
  static const char *const known[] = {"name", "ts", "key", "modes", NULL};
  unknown_keys(ctx, out, c, known, L);
  line(out, RL_DIM, "  bot presence per channel: not reported yet");
  if (rvs(&rep->res, "want"))
    hint(out, "channel mode <#chan> · channel set <#chan> · ban list <#chan>");
}

static void render_channel_change(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const crec_t *r = &rep->res;
  const char *code = rep->code, *name = rv(r, "name") ? rv(r, "name") : "?";
  char subj[256], ph[160];
  long long bots = rvi(r, "bots", 0), peers = rvi(r, "peers", 0);
  char pp[96];
  if (peers > 0) snprintf(pp, sizeof(pp), "synced to %lld other hub%s", peers, peers == 1 ? "" : "s");
  else snprintf(pp, sizeof(pp), "no other hub linked");
  if (!strcmp(code, "channel.added")) {
    if (rvb(r, "existed")) {
      snprintf(subj, sizeof(subj), "%s   key %s %s %s", name, rvs(r, "old_key") ? rv(r, "old_key") : "(none)",
               GL(G_ARROW), rvs(r, "key") ? rv(r, "key") : "(none)");
      fmt_ok(ctx, "Channel updated", subj, out);
    } else {
      if (rvs(r, "key")) snprintf(subj, sizeof(subj), "%s   key %s", name, rv(r, "key"));
      else snprintf(subj, sizeof(subj), "%s", name);
      fmt_ok(ctx, "Channel added", subj, out);
    }
    snprintf(ph, sizeof(ph), "pushed to %lld bot%s (they join now); %s", bots, bots == 1 ? "" : "s", pp);
    effect(ctx, out, ph);
    if (rvs(r, "modes")) {
      snprintf(ph, sizeof(ph), "recorded modes +%s kept", rv(r, "modes"));
      effect(ctx, out, ph);
    }
  } else if (!strcmp(code, "channel.removed")) {
    fmt_ok(ctx, "Channel removed", name, out);
    if (!rvb(r, "existed")) warn(ctx, out, "it was not a managed channel here; the removal still syncs");
    snprintf(ph, sizeof(ph), "%lld bot%s told to part; %s", bots, bots == 1 ? "" : "s", pp);
    effect(ctx, out, ph);
    long long d = rvi(r, "purge_days", 0);
    if (d > 0) snprintf(ph, sizeof(ph), "tombstone kept %lld days (hub set autopurge)", d);
    else snprintf(ph, sizeof(ph), "the tombstone stays until hub purge (autopurge is off)");
    effect(ctx, out, ph);
  } else {
    bool inv = !strcmp(code, "channel.invite");
    snprintf(subj, sizeof(subj), "%s on %s", rv(r, "nick") ? rv(r, "nick") : "?",
             rv(r, "chan") ? rv(r, "chan") : "?");
    long long asked = rvi(r, "asked", 0), hubs = rvi(r, "hubs", 0);
    if (rvs(r, "by")) { /* one bot was picked and did it */
      fmt_ok(ctx, inv ? "Invited" : "Opped", subj, out);
      snprintf(ph, sizeof(ph), "%s on %s did it%s%s%s", rv(r, "by"),
               rv(r, "hub_name") ? rv(r, "hub_name") : "?", rvs(r, "detail") ? " (" : "",
               rvs(r, "detail") ? rv(r, "detail") : "", rvs(r, "detail") ? ")" : "");
      effect(ctx, out, ph);
      snprintf(ph, sizeof(ph), "%lld bot%s asked on %lld hub%s; one acted", asked,
               asked == 1 ? "" : "s", hubs, hubs == 1 ? "" : "s");
      effect(ctx, out, ph);
      return;
    }
    fmt_ok(ctx, inv ? "Invite request sent" : "Op request sent", subj, out);
    long long local = rvi(r, "local", 0);
    if (local > 0)
      snprintf(ph, sizeof(ph), "%lld bot%s on this hub asked; forwarded to %lld other hub%s", local,
               local == 1 ? "" : "s", peers, peers == 1 ? "" : "s");
    else
      snprintf(ph, sizeof(ph), "no bots on this hub; forwarded to %lld other hub%s", peers, peers == 1 ? "" : "s");
    effect(ctx, out, ph);
    snprintf(ph, sizeof(ph), "a bot that is opped on %s %s", rv(r, "chan") ? rv(r, "chan") : "?",
             inv ? "will invite them" : "and sees them will op them");
    effect(ctx, out, ph);
  }
}

/* ==========================================================================
 * Modes, settings, bans (docs/modes.md §5.1)
 * ========================================================================== */
/* The on/off options: a setting not in this list is valued (a number or a
 * flood limit).  A new on/off option is one word here. */
static const char *const FLAG_SETTINGS[] = {
  "enforcemodes", "bitch", "protectops", "revenge", "stopnethack", "enforcebans",
  "dynamicbans", "dontkickops", "cycle", "dynamiclimit", NULL};

/* What each setting does and its built-in value, as people read them: help
 * channel set / help network set, the settings tables, channel show.  Names
 * as those show them; the bot floods (net) are flood cmd|msg|ctcp, the
 * words network set takes.  docs/modes.md §4, §8.1, §9.1. */
static const struct {
  const char *name, *def, *what;
  bool        net;
} SET_INFO[] = {
  {"enforcemodes", "off", "put back any change away from the stored modes", false},
  {"bitch", "off", "only authorised users and bots may hold ops", false},
  {"protectops", "on", "re-op an authorised member someone deopped; lift bans on one", false},
  {"revenge", "off", "deop whoever deops, kicks or bans an authorised member; again: kick + ban", false},
  {"stopnethack", "off", "take back ops a netsplit rejoin gave to unauthorised members", false},
  {"enforcebans", "off", "kick the unauthorised members a new ban matches", false},
  {"dynamicbans", "on", "set a listed ban only while someone it matches is in the channel", false},
  {"dontkickops", "on", "ops are never acted on for chan, ctcp, join and nick floods", false},
  {"cycle", "on", "a bot alone in a channel with no ops parts and rejoins for ops", false},
  {"dynamiclimit", "off", "keep +l at the member count plus limitgap", false},
  {"bantime", "120 min", "how long an automatic ban (flood, revenge) lasts; 0 = permanent", false},
  {"bantype", "2", "ban mask shape 0-9: 2 = *!*@host, 4 = *!*@*.host, 7 = nick!*@host", false},
  {"banidle", "60 min", "dynamicbans: a listed ban with no match this long is lifted", false},
  {"limitgap", "5", "dynamiclimit: free places above the member count", false},
  {"limitdelay", "60 s", "dynamiclimit: time between limit changes", false},
  {"flood chan", "15:60", "messages to the channel per host: kick, again: ban", false},
  {"flood ctcp", "3:60", "CTCPs to the channel per host: kick, again: ban", false},
  {"flood join", "5:60", "joins per host (join/part cycling): ban + kick", false},
  {"flood nick", "5:60", "nick changes per host: kick, again: ban", false},
  {"flood deop", "3:10", "deops by an unauthorised op: deop them, re-op the victims", false},
  {"flood kick", "3:10", "kicks by an unauthorised op: deop them, again: kick + ban", false},
  {"flood ban", "3:10", "bans by an unauthorised op: deop them, lift bans on authorised", false},
  {"flood cmd", "10:30", "commands per user: extras dropped; 3x the rate ignores the user", true},
  {"flood msg", "5:60", "other messages to a bot per host: the host is ignored", true},
  {"flood ctcp", "3:60", "CTCPs to a bot per host: the host is ignored", true},
  {"ignoretime", "10 min", "how long a flooding host or user stays ignored", true},
  {"sendq", "10:100", "a bot's IRC output: B lines at once, then one every I ms", true},
};
#define NSETINFO ((int)(sizeof(SET_INFO) / sizeof(SET_INFO[0])))

bool fmt_setting_info(int i, bool net, const char **name, const char **def,
                      const char **what) {
  int k = -1;
  for (int j = 0; j < NSETINFO; j++)
    if (SET_INFO[j].net == net && ++k == i) {
      *name = SET_INFO[j].name;
      *def = SET_INFO[j].def;
      *what = SET_INFO[j].what;
      return true;
    }
  return false;
}

static const char *setting_what(const char *name, bool net, const char **def) {
  for (int j = 0; j < NSETINFO; j++)
    if (SET_INFO[j].net == net && !strcmp(SET_INFO[j].name, name)) {
      if (def) *def = SET_INFO[j].def;
      return SET_INFO[j].what;
    }
  if (def) *def = NULL;
  return NULL;
}

static bool is_flag_setting(const char *name) {
  for (int i = 0; FLAG_SETTINGS[i]; i++)
    if (!strcmp(FLAG_SETTINGS[i], name)) return true;
  return false;
}

/* A setting's value as a person reads it: on / off, minutes, seconds,
 * permanent; floods stay N:S or off. */
static void setting_value(const char *name, const char *kind, const char *v, char *out,
                          size_t cap) {
  if (!v) v = "";
  if (kind && !strcmp(kind, "flag")) snprintf(out, cap, "%s", !strcmp(v, "1") ? "on" : "off");
  else if (!strcmp(name, "bantime") && !strcmp(v, "0")) snprintf(out, cap, "permanent");
  else if (!strcmp(name, "bantime") || !strcmp(name, "banidle") || !strcmp(name, "ignoretime"))
    snprintf(out, cap, "%s min", v);
  else if (!strcmp(name, "limitdelay")) snprintf(out, cap, "%s s", v);
  else snprintf(out, cap, "%s", v);
}

static const char *src_phrase(const char *src) {
  if (!src) return "?";
  if (!strcmp(src, "chan")) return "channel";
  if (!strcmp(src, "net")) return "network";
  return "built-in";
}

static const char *modes_source_phrase(const char *src) {
  if (!src) return "";
  if (!strcmp(src, "chan")) return "set on this channel";
  if (!strcmp(src, "net")) return "network default";
  return "built-in default";
}

static void push_effects(const fmt_ctx_t *ctx, const crec_t *r, flines_t *out) {
  char ph[160], pp[96];
  long long bots = rvi(r, "bots", 0), peers = rvi(r, "peers", 0);
  if (peers > 0) snprintf(pp, sizeof(pp), "synced to %lld other hub%s", peers, peers == 1 ? "" : "s");
  else snprintf(pp, sizeof(pp), "no other hub linked");
  snprintf(ph, sizeof(ph), "pushed to %lld bot%s; %s", bots, bots == 1 ? "" : "s", pp);
  effect(ctx, out, ph);
}

/* channel.mode: the view (view=1) or the answer to a store-and-apply. */
static void render_channel_mode(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const crec_t *r = &rep->res;
  const char *chan = rv(r, "chan") ? rv(r, "chan") : "?", *eff = rv(r, "effective");
  char v[256], ph[200];
  if (rvb(r, "view")) {
    char title[96];
    snprintf(title, sizeof(title), "Modes %s", chan);
    fmt_title(ctx, out, title, "managed");
    const int L = 8;
    snprintf(v, sizeof(v), "%s   (%s)", eff ? eff : "?", modes_source_phrase(rv(r, "source")));
    fmt_card_line(ctx, out, L, "stored", v, RL_NORMAL);
    fmt_card_line(ctx, out, L, "key", rvb(r, "key_set") ? "set (channel show has it)" : "none",
                  RL_NORMAL);
    if (rvs(r, "live")) snprintf(v, sizeof(v), "+%s   (i and k as last reported by a bot)", rv(r, "live"));
    else snprintf(v, sizeof(v), "not reported");
    fmt_card_line(ctx, out, L, "live", v, RL_NORMAL);
    if (rvb(r, "dynlimit"))
      warn(ctx, out, "+l is stored but +dynamiclimit is on: the dynamic limit wins");
    hint(out, "channel mode <#chan> <+modes> [key] [limit]  stores and applies · channel mode <#chan> -  network default");
    return;
  }
  snprintf(v, sizeof(v), "%s   %s", chan, eff ? eff : "?");
  fmt_ok(ctx, "Modes applied", v, out);
  snprintf(ph, sizeof(ph), "stored on every hub and bot (%s)", modes_source_phrase(rv(r, "source")));
  effect(ctx, out, ph);
  if (rvs(r, "by")) {
    snprintf(ph, sizeof(ph), "%s on %s applied them%s%s%s", rv(r, "by"),
             rv(r, "hub_name") ? rv(r, "hub_name") : "?", rvs(r, "detail") ? " (" : "",
             rvs(r, "detail") ? rv(r, "detail") : "", rvs(r, "detail") ? ")" : "");
    effect(ctx, out, ph);
    long long asked = rvi(r, "asked", 0), hubs = rvi(r, "hubs", 0);
    snprintf(ph, sizeof(ph), "%lld bot%s asked on %lld hub%s; one acted", asked,
             asked == 1 ? "" : "s", hubs, hubs == 1 ? "" : "s");
    effect(ctx, out, ph);
  }
  if (rvb(r, "dynlimit"))
    warn(ctx, out, "+l is stored but +dynamiclimit is on: the dynamic limit wins");
}

/* channel.settings / network.settings: every setting, its value, where it comes from. */
static void render_settings_table(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out,
                                  bool network) {
  const crec_t *r = &rep->res;
  bool net_target = !network && rv(r, "name") && !strcmp(rv(r, "name"), "default");
  char title[96], right[160];
  int overrides = 0, rows = 0;
  for (int i = 0; i < rep->n; i++) {
    const crec_t *c = &rep->r[i];
    if (strcmp(c->type, "setting")) continue;
    rows++;
    const char *s = rv(c, "src");
    /* a channel counts its own values; the network default and the bot
     * floods count what the network changed */
    if (s && !strcmp(s, net_target || network ? "net" : "chan")) overrides++;
  }
  if (network) {
    snprintf(title, sizeof(title), "Bot settings");
    snprintf(right, sizeof(right), "network-wide %s %d changed", GL(G_DOT), overrides);
  } else {
    snprintf(title, sizeof(title), "Settings %s", rv(r, "name") ? rv(r, "name") : "?");
    snprintf(right, sizeof(right), "%d %s", overrides, net_target ? "changed" : "of its own");
  }
  fmt_title(ctx, out, title, right);
  static const col_t cols[] = {{"SETTING", 'L', 1}, {"VALUE", 'L', 1}, {"FROM", 'L', 1},
                               {"DEFAULT", 'L', 1}, {"WHAT IT DOES", 'L', 2}};
  tbl_t t;
  tbl_init(&t, cols, 5, -1, 0, 1);
  for (int i = 0; i < rep->n; i++) {
    const crec_t *c = &rep->r[i];
    if (strcmp(c->type, "setting")) continue;
    char val[48];
    const char *name = rv(c, "name") ? rv(c, "name") : "?", *def = NULL;
    const char *what = setting_what(name, network, &def);
    setting_value(name, rv(c, "kind"), rv(c, "value"), val, sizeof(val));
    const char *cells[5] = {name, val, src_phrase(rv(c, "src")), def, what};
    tbl_row(ctx, &t, RL_NORMAL, NULL, cells);
  }
  if (!rows) {
    empty_note(out, "no settings", NULL);
    tbl_free(&t);
    return;
  }
  tbl_render(ctx, out, &t);
  tbl_free(&t);
  rule_line(ctx, out);
  char v[200];
  if (network) {
    line(out, RL_DIM, "  cmd counts per user, msg and ctcp per host; a flooding host is ignored for ignoretime");
    line(out, RL_DIM, "  sendq paces what a bot says: B lines at once, then one every I ms (I 0 = no delay)");
    hint(out, "bot set flood <cmd|msg|ctcp> <N:S|off|default> · bot set ignoretime <min|default> · bot set sendq <B:I|default>");
  } else {
    const char *eff = rv(r, "effective");
    snprintf(v, sizeof(v), "  modes %s (%s)", eff ? eff : "?", modes_source_phrase(rv(r, "source")));
    line(out, RL_DIM, "%s", v);
    hint(out, net_target ? "channel set default +opt|-opt|<name> <value|default>"
                         : "channel set <#chan> +opt|-opt|<name> <value|default> · flood <type> <N:S|off|default>");
  }
}

/* channel.set / network.set: what changed, old -> new. */
static void render_settings_change(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const crec_t *r = &rep->res;
  bool network = !strcmp(rep->code, "network.set");
  const char *name = rv(r, "name") ? rv(r, "name") : "?";
  bool net_target = !network && !strcmp(name, "default");
  char what[96], subj[160], ph[200], a[48], b[48];
  if (network) {
    snprintf(what, sizeof(what), "Bot settings");
    const char *st = rv(r, "setting") ? rv(r, "setting") : "?";
    setting_value(st, rv(r, "kind"), rv(r, "old"), a, sizeof(a));
    setting_value(st, rv(r, "kind"), rv(r, "value"), b, sizeof(b));
    snprintf(subj, sizeof(subj), "%s   %s %s %s", st, a, GL(G_ARROW), b);
    fmt_ok(ctx, what, subj, out);
    if (!rvb(r, "written")) effect(ctx, out, "no change: it already had that value");
    else {
      snprintf(ph, sizeof(ph), "now %s (%s)", b, src_phrase(rv(r, "src")));
      effect(ctx, out, ph);
      push_effects(ctx, r, out);
    }
    return;
  }
  if (net_target) snprintf(what, sizeof(what), "Network default");
  else snprintf(what, sizeof(what), "Channel %s", name);
  long long n = rvi(r, "changes", 0);
  snprintf(subj, sizeof(subj), "%lld setting%s", n, n == 1 ? "" : "s");
  fmt_ok(ctx, what, subj, out);
  for (int i = 0; i < rep->n; i++) {
    const crec_t *c = &rep->r[i];
    if (strcmp(c->type, "chg")) continue;
    const char *st = rv(c, "setting") ? rv(c, "setting") : "?";
    setting_value(st, rv(c, "kind"), rv(c, "old"), a, sizeof(a));
    setting_value(st, rv(c, "kind"), rv(c, "value"), b, sizeof(b));
    snprintf(ph, sizeof(ph), "%s   %s %s %s   (%s)", st, a, GL(G_ARROW), b,
             rvb(c, "reset") ? "default restored" : src_phrase(rv(c, "src")));
    effect(ctx, out, ph);
  }
  if (!rvb(r, "written")) effect(ctx, out, "no change: it already had these values");
  else push_effects(ctx, r, out);
}

/* ban.* */
static void ban_expiry(const fmt_ctx_t *ctx, long long expires, char *out, size_t cap) {
  if (expires <= 0) {
    snprintf(out, cap, "permanent");
  } else if (expires <= ctx->now) {
    snprintf(out, cap, "expired");
  } else {
    char w[32], s[32];
    fmt_when(expires, ctx->now, w, sizeof(w));
    fmt_span(expires - ctx->now, s, sizeof(s));
    snprintf(out, cap, "%s %s in %s", w, GL(G_DOT), s);
  }
}

static int ban_row_cmp(const void *pa, const void *pb) {
  const crec_t *a = *(const crec_t *const *)pa, *b = *(const crec_t *const *)pb;
  const char *ca = rv(a, "chan") ? rv(a, "chan") : "", *cb = rv(b, "chan") ? rv(b, "chan") : "";
  /* "*" (every channel) first, then channel, mask, added */
  int ga = !strcmp(ca, "*"), gb = !strcmp(cb, "*");
  if (ga != gb) return gb - ga;
  int c = ci_cmp(ca, cb);
  if (c) return c;
  c = strcmp(ca, cb);
  if (c) return c;
  const char *ma = rv(a, "mask") ? rv(a, "mask") : "", *mb = rv(b, "mask") ? rv(b, "mask") : "";
  c = ci_cmp(ma, mb);
  if (c) return c;
  c = strcmp(ma, mb);
  if (c) return c;
  long long ta = rvi(a, "ts", 0), tb = rvi(b, "ts", 0);
  return ta < tb ? -1 : ta > tb ? 1 : 0;
}

static void render_ban_list(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const crec_t *r = &rep->res;
  long long count = rvi(r, "count", 0);
  char right[120];
  if (rvs(r, "chan"))
    snprintf(right, sizeof(right), "%lld ban%s %s %s", count, count == 1 ? "" : "s", GL(G_DOT),
             !strcmp(rv(r, "chan"), "*") ? "global" : rv(r, "chan"));
  else snprintf(right, sizeof(right), "%lld ban%s", count, count == 1 ? "" : "s");
  fmt_title(ctx, out, "Bans", right);
  const crec_t **rows = calloc((size_t)rep->n + 1, sizeof(*rows));
  int nr = 0;
  for (int i = 0; rows && i < rep->n; i++)
    if (!strcmp(rep->r[i].type, "ban")) rows[nr++] = &rep->r[i];
  if (!nr) {
    empty_note(out, "no bans listed", "ban add <#chan|*> <mask> [<min>|perm] [sticky] [reason]");
    free(rows);
    return;
  }
  qsort(rows, (size_t)nr, sizeof(*rows), ban_row_cmp);
  static const col_t cols[] = {{"CHANNEL", 'L', 1}, {"MASK", 'L', 1}, {"EXPIRES", 'L', 1},
                               {"LAST USED", 'L', 1}, {"STICKY", 'L', 2}, {"BY", 'L', 2},
                               {"REASON", 'L', 2}, {"ADDED", 'L', 2}};
  tbl_t t;
  tbl_init(&t, cols, 8, -1, 1, 1);
  for (int i = 0; i < nr; i++) {
    const crec_t *c = rows[i];
    char ex[96], when[64], used[64];
    ban_expiry(ctx, rvi(c, "expires", 0), ex, sizeof(ex));
    when_ago(ctx, rvi(c, "ts", 0), when, sizeof(when));
    /* a sticky ban is always on the channel: no match is ever seen */
    if (rvb(c, "sticky")) snprintf(used, sizeof(used), "always");
    else when_ago(ctx, rvi(c, "used", 0), used, sizeof(used));
    const char *cells[8] = {rv(c, "chan"), rv(c, "mask"), ex, used,
                            rvb(c, "sticky") ? "yes" : "no", rv(c, "setter"), rv(c, "reason"),
                            when};
    tbl_row(ctx, &t, RL_NORMAL, NULL, cells);
  }
  tbl_render(ctx, out, &t);
  tbl_free(&t);
  free(rows);
  if (rvb(r, "truncated")) warn(ctx, out, "only the first bans are shown; name a channel to narrow the list");
}

static void render_ban_change(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const crec_t *r = &rep->res;
  char subj[256], ph[256], ex[96];
  const char *chan = rv(r, "chan") ? rv(r, "chan") : "?", *mask = rv(r, "mask") ? rv(r, "mask") : "?";
  snprintf(subj, sizeof(subj), "%s   %s", !strcmp(chan, "*") ? "every channel" : chan, mask);
  if (!strcmp(rep->code, "ban.removed")) {
    fmt_ok(ctx, "Ban removed", subj, out);
    push_effects(ctx, r, out);
    return;
  }
  fmt_ok(ctx, rvb(r, "existed") ? "Ban updated" : "Ban added", subj, out);
  ban_expiry(ctx, rvi(r, "expires", 0), ex, sizeof(ex));
  snprintf(ph, sizeof(ph), "lasts: %s", ex);
  effect(ctx, out, ph);
  if (rvb(r, "sticky")) effect(ctx, out, "sticky: the bots put it back at once if an op removes it");
  if (rvs(r, "reason")) {
    snprintf(ph, sizeof(ph), "reason: %s", rv(r, "reason"));
    effect(ctx, out, ph);
  }
  push_effects(ctx, r, out);
}

/* The settings a channel overrides ("bitch=1,flood join=5:60") as a person
 * would type them: +bitch, flood join 5:60. */
/* channel show: every setting's value from its setting records, on lines
 * (options on, options off, values, message floods, op floods), the
 * channel's own marked '*',
 * then whether it is all default.  False: no setting records (an older hub). */
static bool settings_card(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out, int L) {
  sb_t ln[5] = {{0}};
  int own = 0, rows = 0;
  for (int i = 0; i < rep->n; i++) {
    const crec_t *c = &rep->r[i];
    if (strcmp(c->type, "setting")) continue;
    const char *name = rv(c, "name") ? rv(c, "name") : "?";
    const char *src = rv(c, "src"), *mark = "";
    if (src && !strcmp(src, "chan")) {
      mark = "*";
      own++;
    }
    rows++;
    char val[48];
    setting_value(name, rv(c, "kind"), rv(c, "value"), val, sizeof(val));
    if (is_flag_setting(name)) {
      bool on = !strcmp(val, "on");
      sb_t *b = &ln[on ? 0 : 1];
      sb_addf(b, "%s%c%s%s", b->len ? " " : "", on ? '+' : '-', name, mark);
    } else if (!strncmp(name, "flood ", 6)) {
      /* the message floods, then the op floods (deop kick ban) */
      sb_t *b = &ln[strstr(" deop kick ban ", name + 5) ? 4 : 3];
      if (b->len) sb_addf(b, " %s ", GL(G_DOT));
      else sb_add(b, "flood ");
      sb_addf(b, "%s %s%s", name + 6, val, mark);
    } else {
      if (ln[2].len) sb_addf(&ln[2], " %s ", GL(G_DOT));
      sb_addf(&ln[2], "%s %s%s", name, val, mark);
    }
  }
  if (rows) {
    const char *label = "settings";
    for (int k = 0; k < 5; k++) {
      if (!ln[k].len) continue;
      fmt_card_line(ctx, out, L, label, ln[k].p, RL_NORMAL);
      label = "";
    }
    fmt_card_line(ctx, out, L, "", own ? "(* set on this channel, the rest default settings)"
                                       : "(default settings)", RL_DIM);
  }
  for (int k = 0; k < 5; k++) sb_free(&ln[k]);
  return rows > 0;
}

static void overrides_phrase(const char *ov, char *out, size_t cap) {
  size_t o = 0;
  out[0] = '\0';
  for (const char *p = ov; p && *p;) {
    const char *end = strchr(p, ',');
    size_t tl = end ? (size_t)(end - p) : strlen(p);
    const char *eq = memchr(p, '=', tl);
    char name[48], val[48];
    if (eq && (size_t)(eq - p) < sizeof(name) && tl - (size_t)(eq - p) - 1 < sizeof(val)) {
      size_t nl = (size_t)(eq - p), vl = tl - nl - 1;
      memcpy(name, p, nl);
      name[nl] = '\0';
      memcpy(val, eq + 1, vl);
      val[vl] = '\0';
      char one[112];
      if (is_flag_setting(name)) snprintf(one, sizeof(one), "%c%s", !strcmp(val, "1") ? '+' : '-', name);
      else snprintf(one, sizeof(one), "%s %s", name, val);
      int w = snprintf(out + o, cap - o, "%s%s", o ? ", " : "", one);
      if (w < 0 || (size_t)w >= cap - o) return;
      o += (size_t)w;
    }
    p += tl;
    if (*p == ',') p++;
  }
}

/* ==========================================================================
 * Upgrades (view 4 renders the same)
 * ========================================================================== */
static int node_rank(const char *st) {
  if (!st) return 9;
  if (!strcmp(st, "committing")) return 0;
  if (!strcmp(st, "failed") || !strcmp(st, "unable")) return 1;
  if (!strcmp(st, "pending") || !strcmp(st, "ready")) return 2;
  if (!strcmp(st, "done")) return 3;
  return 4;
}

/* "2.4.8 → 2.5.0 → 2.5.1" from a plan record's <p>_from / <p>_path. */
static void plan_path_line(const fmt_ctx_t *ctx, const crec_t *pl, const char *p, char *out,
                           size_t cap) {
  char k[16], work[1100];
  snprintf(k, sizeof(k), "%s_path", p);
  snprintf(work, sizeof(work), "%s", rv(pl, k) ? rv(pl, k) : "");
  snprintf(k, sizeof(k), "%s_from", p);
  size_t o = 0;
  int w = snprintf(out, cap, "%s", rv(pl, k) ? rv(pl, k) : "");
  if (w > 0) o = (size_t)w < cap ? (size_t)w : cap - 1;
  char *save = NULL;
  for (char *t = strtok_r(work, ",", &save); t && o + 1 < cap; t = strtok_r(NULL, ",", &save)) {
    w = snprintf(out + o, cap - o, "%s%s %s", o ? " " : "", GL(G_ARROW), t);
    if (w < 0) break;
    o += (size_t)w < cap - o ? (size_t)w : cap - o - 1;
  }
}

/* The multi-step plan card lines (view 4 and `upgrade status`). */
static void render_upg_plan(const fmt_ctx_t *ctx, const crec_t *pl, int L, flines_t *out) {
  char v[512], a[48], b[48];
  long long step = rvi(pl, "step", 0), steps = rvi(pl, "steps", 0);
  bool active = rvb(pl, "active");
  const char *st = rv(pl, "state") ? rv(pl, "state") : "";
  if (active && !strcmp(st, "running"))
    snprintf(v, sizeof(v), "step %lld/%lld running", step, steps);
  else if (active) {
    long long nx = rvi(pl, "next", 0) - ctx->now;
    fmt_span(nx > 0 ? nx : 0, b, sizeof(b));
    snprintf(v, sizeof(v), "step %lld/%lld starts in %s", step, steps, b);
  } else
    snprintf(v, sizeof(v), "stopped at step %lld/%lld", step, steps);
  fmt_card_line(ctx, out, L, "multi-step", v, active ? RL_NORMAL : RL_DIM);
  plan_path_line(ctx, pl, "bot", v, sizeof(v));
  if (v[0]) fmt_card_line(ctx, out, L, "  bots", v, RL_NORMAL);
  if (rvs(pl, "hub_final")) {
    plan_path_line(ctx, pl, "hub", v, sizeof(v));
    if (!v[0]) snprintf(v, sizeof(v), "already on %s", rv(pl, "hub_final"));
    fmt_card_line(ctx, out, L, "  hubs", v, RL_NORMAL);
  }
  fmt_when(rvi(pl, "started", 0), ctx->now, a, sizeof(a));
  fmt_span(ctx->now - rvi(pl, "started", 0), b, sizeof(b));
  snprintf(v, sizeof(v), "%s %s %s ago", a, GL(G_DOT), b);
  fmt_card_line(ctx, out, L, "  started", v, RL_DIM);
  if (rvs(pl, "summary")) fmt_card_line(ctx, out, L, "  ended", rv(pl, "summary"), RL_DIM);
  if (active)
    fmt_card_line(ctx, out, L, "", "upgrade abort stops the rest and rolls back only the step running",
                  RL_DIM);
}

static void render_upg_status(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const crec_t *r = &rep->res, *ru = NULL, *pl = NULL;
  for (int i = 0; i < rep->n; i++) {
    if (!strcmp(rep->r[i].type, "rollup")) ru = &rep->r[i];
    if (!strcmp(rep->r[i].type, "plan")) pl = &rep->r[i];
  }
  char v[512], a[48], b[48];
  char plan[160] = "";
  if (ru) {
    if (rvs(ru, "hub_ver"))
      snprintf(plan, sizeof(plan), "bots %s %s, hubs %s %s", GL(G_ARROW), rv(ru, "bot_ver"),
               GL(G_ARROW), rv(ru, "hub_ver"));
    else
      snprintf(plan, sizeof(plan), "bots %s %s", GL(G_ARROW), rv(ru, "bot_ver") ? rv(ru, "bot_ver") : "?");
  }
  const int L = 12;
  if (!rvs(r, "id")) {
    fmt_title(ctx, out, "Upgrades", "no run on this hub");
    if (pl) render_upg_plan(ctx, pl, L, out);
    if (ru) {
      fmt_when(rvi(ru, "set", 0), ctx->now, a, sizeof(a));
      fmt_span(ctx->now - rvi(ru, "set", 0), b, sizeof(b));
      snprintf(v, sizeof(v), "%s  (set %s %s %s ago)", plan, a, GL(G_DOT), b);
      fmt_card_line(ctx, out, L, "roll-up plan", v, RL_NORMAL);
      /* Kept only for nodes that were down when the run went through. */
      if (rvi(ru, "expires", 0) > 0) {
        long long left = rvi(ru, "expires", 0) - ctx->now;
        fmt_span(left > 0 ? left : 0, b, sizeof(b));
        snprintf(v, sizeof(v), "waiting for nodes that missed the run; dropped in %s", b);
        fmt_card_line(ctx, out, L, "", v, RL_DIM);
      }
    } else {
      fmt_card_line(ctx, out, L, "roll-up plan", "none", RL_NORMAL);
    }
    if (rvb(r, "frozen")) warn(ctx, out, "config is frozen: clear option flag F to lift it");
    hint(out, "upgrade releases lists what can be installed");
    return;
  }
  char title[96], right[160];
  snprintf(title, sizeof(title), "Upgrade %s", rv(r, "id"));
  if (rvs(r, "hub_ver"))
    snprintf(right, sizeof(right), "bots %s %s %s hubs %s %s %s %s", GL(G_ARROW), rv(r, "bot_ver"),
             GL(G_DOT), GL(G_ARROW), rv(r, "hub_ver"), GL(G_DOT), rv(r, "phase") ? rv(r, "phase") : "?");
  else
    snprintf(right, sizeof(right), "bots %s %s %s %s", GL(G_ARROW), rv(r, "bot_ver") ? rv(r, "bot_ver") : "?",
             GL(G_DOT), rv(r, "phase") ? rv(r, "phase") : "?");
  fmt_title(ctx, out, title, right);
  fmt_when(rvi(r, "started", 0), ctx->now, a, sizeof(a));
  fmt_span(ctx->now - rvi(r, "started", 0), b, sizeof(b));
  snprintf(v, sizeof(v), "%s %s %s ago", a, GL(G_DOT), b);
  fmt_card_line(ctx, out, L, "started", v, RL_NORMAL);
  if (pl) render_upg_plan(ctx, pl, L, out);
  long long sel = rvi(r, "selective", 0);
  if (sel > 0) snprintf(v, sizeof(v), "%lld node%s named", sel, sel == 1 ? "" : "s");
  else snprintf(v, sizeof(v), "no (whole network)");
  fmt_card_line(ctx, out, L, "selective", v, RL_NORMAL);
  int done = 0, failed = 0, waiting = 0, total = 0;
  for (int i = 0; i < rep->n; i++) {
    const crec_t *n = &rep->r[i];
    if (strcmp(n->type, "node")) continue;
    int k = node_rank(rv(n, "state"));
    if (k == 4) continue;
    total++;
    if (k == 3) done++;
    else if (k == 1) failed++;
    else waiting++;
  }
  sb_t s = {0};
  int bar = 24, fill = total ? done * bar / total : 0;
  sb_rep(&s, GL(G_FULL), fill);
  sb_rep(&s, GL(G_EMPTY), bar - fill);
  sb_addf(&s, "  %d / %d done %s %d failed %s %d waiting", done, total, GL(G_DOT), failed, GL(G_DOT),
          waiting);
  fmt_card_line(ctx, out, L, "progress", s.p, RL_NORMAL);
  sb_free(&s);
  if (ru) fmt_card_line(ctx, out, L, "roll-up", plan, RL_NORMAL);
  if (rvs(r, "summary")) fmt_card_line(ctx, out, L, "summary", rv(r, "summary"), RL_NORMAL);
  if (rvb(r, "frozen")) fmt_card_line(ctx, out, L, "frozen", "yes (until the run ends)", RL_WARN);
  static const col_t cols[] = {{"KIND", 'L', 1}, {"NODE", 'L', 1}, {"STATE", 'L', 1}, {"FROM", 'L', 1},
                               {"TO", 'L', 1}, {"CODE", 'L', 2}, {"UUID", 'L', 2}, {"NOTE", 'L', 2}};
  tbl_t t;
  tbl_init(&t, cols, 8, -1, 1, 1);
  for (int rank = 0; rank <= 4; rank++)
    for (int i = 0; i < rep->n; i++) {
      const crec_t *n = &rep->r[i];
      if (strcmp(n->type, "node") || node_rank(rv(n, "state")) != rank) continue;
      char code[32];
      if (rvs(n, "want")) snprintf(code, sizeof(code), "%s %s %s", rvs(n, "base") ? rv(n, "base") : "?",
                                   GL(G_ARROW), rv(n, "want"));
      else snprintf(code, sizeof(code), "%s", rvs(n, "base") ? rv(n, "base") : "");
      const char *cells[8] = {rv(n, "kind"), rvs(n, "name") ? rv(n, "name") : rv(n, "uuid"),
                              rv(n, "state"), rv(n, "from"), rv(n, "to"), code, rv(n, "uuid"),
                              rv(n, "reason")};
      tbl_row(ctx, &t, rank == 1 ? RL_WARN : rank == 4 ? RL_DIM : RL_NORMAL, rv(n, "state"), cells);
    }
  if (t.nr) {
    flines_add(out, RL_NORMAL, "");
    tbl_render(ctx, out, &t);
  }
  tbl_free(&t);
}

/* Version order for the releases list: a leading v is ignored, digit runs
 * compare as numbers, anything else byte by byte ("2.4.10" > "2.4.9"). */
static int ver_cmp(const char *a, const char *b) {
  if (*a == 'v' || *a == 'V') a++;
  if (*b == 'v' || *b == 'V') b++;
  while (*a || *b) {
    if (isdigit((unsigned char)*a) && isdigit((unsigned char)*b)) {
      while (*a == '0') a++;
      while (*b == '0') b++;
      size_t la = 0, lb = 0;
      while (isdigit((unsigned char)a[la])) la++;
      while (isdigit((unsigned char)b[lb])) lb++;
      if (la != lb) return la < lb ? -1 : 1;
      int c = strncmp(a, b, la);
      if (c) return c < 0 ? -1 : 1;
      a += la;
      b += lb;
    } else {
      if (*a != *b) return (unsigned char)*a < (unsigned char)*b ? -1 : 1;
      a++;
      b++;
    }
  }
  return 0;
}

/* Only the releases newer than the oldest version a node of that product
 * runs: those are the ones a run can still move a node to.  The nodes list
 * below shows what each node runs. */
static void render_upg_releases(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  for (int prod = 0; prod < 2; prod++) {
    const char *p = prod == 0 ? "bot" : "hub";
    const char *oldest = NULL;
    for (int k = 0; k < rep->n; k++) {
      const crec_t *nd = &rep->r[k];
      const char *kind = rv(nd, "kind") ? rv(nd, "kind") : "";
      if (strcmp(nd->type, "node") || !rvs(nd, "ver") || (prod == 0) != !strcmp(kind, "bot")) continue;
      if (!oldest || ver_cmp(rv(nd, "ver"), oldest) < 0) oldest = rv(nd, "ver");
    }
    fmt_title(ctx, out, prod == 0 ? "Bot releases" : "Hub releases",
              prod == 0 ? "ircbot-releases" : "irchub-releases");
    static const col_t cols[] = {{"VERSION", 'L', 1}, {"DATE", 'L', 1}, {"CODE", 'L', 1}};
    tbl_t t;
    tbl_init(&t, cols, 3, -1, 0, 0);
    int listed = 0;
    for (int i = 0; i < rep->n; i++) {
      const crec_t *r = &rep->r[i];
      if (strcmp(r->type, "rel") || !rv(r, "product") || strcmp(rv(r, "product"), p)) continue;
      listed++;
      if (oldest && rv(r, "ver") && ver_cmp(rv(r, "ver"), oldest) <= 0) continue;
      char bases[32];
      snprintf(bases, sizeof(bases), "%s", rv(r, "bases") ? rv(r, "bases") : "");
      sb_t bb = {0};
      for (const char *q = bases; *q; q++) sb_add(&bb, *q == ',' ? ", " : (char[2]){*q, 0});
      const char *cells[3] = {rv(r, "ver"), rv(r, "date"), bb.p ? bb.p : ""};
      tbl_row(ctx, &t, RL_NORMAL, NULL, cells);
      sb_free(&bb);
    }
    if (t.nr) tbl_render(ctx, out, &t);
    else if (listed) line(out, RL_DIM, "  (none newer than %s, the oldest %s version running)", oldest, p);
    else line(out, RL_DIM, "  (no releases listed)");
    if (t.nr && listed > t.nr)
      line(out, RL_DIM, "  %d older release%s not shown (every %s runs %s or later)", listed - t.nr,
           listed - t.nr == 1 ? "" : "s", p, oldest);
    tbl_free(&t);
    for (int i = 0; i < rep->n; i++) {
      const crec_t *r = &rep->r[i];
      if (strcmp(r->type, "relerr") || !rv(r, "product") || strcmp(rv(r, "product"), p)) continue;
      line(out, RL_WARN, "   %s %s tree unreadable: %s", GL(G_WARN), rv(r, "base") ? rv(r, "base") : "?",
           rv(r, "msg") ? rv(r, "msg") : "?");
    }
  }
  flines_add(out, RL_NORMAL, "");
  int hubs = 0, bots = 0;
  for (int i = 0; i < rep->n; i++) {
    const crec_t *r = &rep->r[i];
    if (strcmp(r->type, "node")) continue;
    if (rv(r, "kind") && !strcmp(rv(r, "kind"), "bot")) bots++;
    else hubs++;
  }
  char right[96];
  snprintf(right, sizeof(right), "%d hub%s %s %d bot%s online", hubs, hubs == 1 ? "" : "s", GL(G_DOT),
           bots, bots == 1 ? "" : "s");
  fmt_title(ctx, out, "Nodes", right);
  static const col_t ncols[] = {{"KIND", 'L', 1}, {"NAME", 'L', 1}, {"VERSION", 'L', 1},
                                {"CODE", 'L', 1}, {"UUID", 'L', 2}};
  tbl_t t;
  tbl_init(&t, ncols, 5, -1, 1, 1);
  /* self, then hubs, then bots, each by name (rule 4) */
  int nn = 0;
  sortrow_t *nodes = collect(rep, "node", "name", NULL, &nn);
  for (int pass = 0; pass < 3; pass++)
    for (int i = 0; i < nn; i++) {
      const crec_t *r = nodes[i].r;
      const char *kind = rv(r, "kind") ? rv(r, "kind") : "";
      int want = !strcmp(kind, "self") ? 0 : !strcmp(kind, "hub") ? 1 : 2;
      if (want != pass) continue;
      const char *cells[5] = {kind, rvs(r, "name") ? rv(r, "name") : rv(r, "uuid"), rv(r, "ver"),
                              rv(r, "base"), rv(r, "uuid")};
      tbl_row(ctx, &t, RL_NORMAL, kind, cells);
    }
  free(nodes);
  tbl_render(ctx, out, &t);
  tbl_free(&t);
  line(out, RL_DIM, "  start a run: upgrade start bot=<ver> [hub=<ver>] [nodes=<a,b=c>]");
}

static void render_upg_change(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const crec_t *r = &rep->res;
  char what[128], subj[160], ph[160];
  if (!strcmp(rep->code, "upg.started")) {
    snprintf(what, sizeof(what), "Upgrade %s started", rv(r, "id") ? rv(r, "id") : "?");
    if (rvs(r, "hub_ver"))
      snprintf(subj, sizeof(subj), "bots %s %s %s hubs %s %s", GL(G_ARROW), rv(r, "bot_ver"), GL(G_DOT),
               GL(G_ARROW), rv(r, "hub_ver"));
    else
      snprintf(subj, sizeof(subj), "bots %s %s", GL(G_ARROW), rv(r, "bot_ver") ? rv(r, "bot_ver") : "?");
    fmt_ok(ctx, what, subj, out);
    long long sel = rvi(r, "selected", 0);
    if (sel > 0)
      snprintf(ph, sizeof(ph), "%lld selected node%s; progress: upgrade status, or Alt+4", sel, sel == 1 ? "" : "s");
    else
      snprintf(ph, sizeof(ph), "%lld bot%s and %lld other hub%s asked to prepare, this hub last; progress: upgrade status, or Alt+4",
               rvi(r, "bots", 0), rvi(r, "bots", 0) == 1 ? "" : "s", rvi(r, "peers", 0),
               rvi(r, "peers", 0) == 1 ? "" : "s");
    effect(ctx, out, ph);
    if (rvi(r, "steps", 0) > 1) {
      if (rvs(r, "hub_final"))
        snprintf(ph, sizeof(ph), "step %lld of %lld on the way to bots %s, hubs %s; the next starts when this one is done",
                 rvi(r, "step", 0), rvi(r, "steps", 0), rv(r, "bot_final"), rv(r, "hub_final"));
      else
        snprintf(ph, sizeof(ph), "step %lld of %lld on the way to bots %s; the next starts when this one is done",
                 rvi(r, "step", 0), rvi(r, "steps", 0), rv(r, "bot_final") ? rv(r, "bot_final") : "?");
      effect(ctx, out, ph);
    }
    effect(ctx, out, "the config is frozen until it finishes");
  } else if (!strcmp(rep->code, "upg.aborted")) {
    if (rvs(r, "id")) snprintf(what, sizeof(what), "Upgrade %s aborted", rv(r, "id"));
    else snprintf(what, sizeof(what), "Multi-step upgrade aborted");
    long long n = rvi(r, "rolled_back", 0);
    if (rvs(r, "id"))
      snprintf(subj, sizeof(subj), "rolling back %lld upgraded node%s", n, n == 1 ? "" : "s");
    else
      snprintf(subj, sizeof(subj), "between steps: nothing to roll back");
    fmt_ok(ctx, what, subj, out);
    if (rvi(r, "steps", 0) > 0) {
      snprintf(ph, sizeof(ph), "stopped at step %lld of %lld; no later step will start", rvi(r, "step", 0),
               rvi(r, "steps", 0));
      effect(ctx, out, ph);
    }
  } else if (!strcmp(rep->code, "upg.abort_sent")) {
    long long peers = rvi(r, "peers", 0);
    fmt_ok(ctx, "No upgrade runs on this hub", NULL, out);
    snprintf(ph, sizeof(ph), "told %lld other hub%s to stop any upgrade they drive", peers, peers == 1 ? "" : "s");
    effect(ctx, out, ph);
  } else {
    long long peers = rvi(r, "peers", 0);
    snprintf(ph, sizeof(ph), "told %lld other hub%s to drop theirs", peers, peers == 1 ? "" : "s");
    if (rvb(r, "had")) {
      snprintf(subj, sizeof(subj), "bots %s %s", GL(G_ARROW), rv(r, "bot_ver") ? rv(r, "bot_ver") : "?");
      fmt_ok(ctx, "Roll-up plan forgotten", subj, out);
    } else {
      fmt_ok(ctx, "No roll-up plan on this hub", NULL, out);
    }
    effect(ctx, out, ph);
  }
}

/* ==========================================================================
 * Network (tree rows: H|depth|name|uuid|online|0|ver|var|started,
 * B|depth|nick|uuid|ver|server|0|var|started, D|nick|uuid|last_seen)
 * ========================================================================== */
static const char *pos(const crec_t *r, int i) {
  char k[8];
  snprintf(k, sizeof(k), "%d", i);
  const char *v = rv(r, k);
  return v && strcmp(v, "-") ? v : "";
}

static void render_network_tree(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  int hubs = 0, on = 0, off = 0;
  for (int i = 0; i < rep->n; i++) {
    const char *t = rep->r[i].type;
    hubs += !strcmp(t, "H");
    on += !strcmp(t, "B");
    off += !strcmp(t, "D");
  }
  char right[96];
  snprintf(right, sizeof(right), "%d hub%s %s %d bots online %s %d offline", hubs, hubs == 1 ? "" : "s",
           GL(G_DOT), on, GL(G_DOT), off);
  fmt_title(ctx, out, "Network", right);
  static const col_t cols[] = {{"NODE", 'L', 1}, {"VERSION", 'L', 1}, {"CODE", 'L', 1},
                               {"UPTIME", 'L', 1}, {"SERVER", 'L', 1}, {"UUID", 'L', 2}};
  tbl_t t;
  tbl_init(&t, cols, 6, -1, 0, 1);
  for (int i = 0; i < rep->n; i++) {
    const crec_t *r = &rep->r[i];
    bool H = !strcmp(r->type, "H"), B = !strcmp(r->type, "B");
    if (!H && !B) continue;
    int depth = atoi(pos(r, 0));
    if (depth < 0) depth = 0;
    if (depth > 8) depth = 8;
    sb_t n = {0};
    sb_rep(&n, "  ", depth);
    if (H) {
      bool up = pos(r, 3)[0] == '1';
      sb_addf(&n, "%s %s", up ? GL(G_OPEN) : GL(G_ERR), pos(r, 1));
      if (depth == 0) sb_add(&n, "  (this hub)");
      else if (!up) sb_add(&n, "  (down)");
    } else {
      bool last = true;
      for (int k = i + 1; k < rep->n; k++) {
        const crec_t *x = &rep->r[k];
        if (!strcmp(x->type, "B") && atoi(pos(x, 0)) == depth) {
          last = false;
          break;
        }
        if (strcmp(x->type, "B") || atoi(pos(x, 0)) < depth) break;
      }
      sb_addf(&n, "%s %s", last ? GL(G_TEND) : GL(G_TMID), pos(r, 1));
    }
    char up[24];
    long long st = atoll(pos(r, 7));
    span_since(ctx, (H && pos(r, 3)[0] != '1') ? 0 : st, up, sizeof(up));
    const char *cells[6] = {n.p, H ? pos(r, 5) : pos(r, 3), pos(r, 6), up, B ? pos(r, 4) : "",
                            pos(r, 2)};
    tbl_row(ctx, &t, H ? RL_HEAD : RL_NORMAL, NULL, cells);
    sb_free(&n);
  }
  tbl_render(ctx, out, &t);
  tbl_free(&t);
  if (!off) return;
  static const col_t dcols[] = {{"NOT CONNECTED", 'L', 1}, {"LAST SEEN", 'L', 1}, {"UUID", 'L', 2}};
  tbl_t d;
  tbl_init(&d, dcols, 3, -1, 0, 0);
  for (int i = 0; i < rep->n; i++) {
    const crec_t *r = &rep->r[i];
    if (strcmp(r->type, "D")) continue;
    char nm[96], seen[64];
    snprintf(nm, sizeof(nm), "%s %s", GL(G_OFF), pos(r, 0));
    when_ago(ctx, atoll(pos(r, 2)), seen, sizeof(seen));
    const char *cells[3] = {nm, seen, pos(r, 1)};
    tbl_row(ctx, &d, RL_DIM, NULL, cells);
  }
  tbl_render(ctx, out, &d);
  tbl_free(&d);
}

/* ==========================================================================
 * Results of bot / peer changes
 * ========================================================================== */
static void render_bot_change(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const crec_t *r = &rep->res;
  const char *code = rep->code;
  const char *uuid = rv(r, "uuid") ? rv(r, "uuid") : "?";
  char subj[256], ph[256];
  peers_phrase(ph, sizeof(ph), rvi(r, "peers", 0));
  if (!strcmp(code, "bot.added")) {
    snprintf(subj, sizeof(subj), "%s  %s", rv(r, "nick") ? rv(r, "nick") : "?", uuid);
    fmt_ok(ctx, "Bot registered", subj, out);
    res_kv(out, "key", rvs(r, "fp") ? rv(r, "fp") : "?");
    effect(ctx, out, "saved to this hub's config; other hubs learn it on the next sync");
    res_kv(out, "next", "start the bot; it shows up in bot list when it connects");
  } else if (!strcmp(code, "bot.deleted")) {
    if (rvs(r, "nick")) snprintf(subj, sizeof(subj), "%s  %s", rv(r, "nick"), uuid);
    else snprintf(subj, sizeof(subj), "%s", uuid);
    fmt_ok(ctx, "Bot deleted", subj, out);
    if (rvb(r, "was_online")) effect(ctx, out, "connected here: told to wipe its config and exit");
    long long peers = rvi(r, "peers", 0), bots = rvi(r, "bots", 0);
    snprintf(ph, sizeof(ph), "synced to %lld other hub%s (one it is connected to does the same); %lld bot%s told to drop it from their trusted list",
             peers, peers == 1 ? "" : "s", bots, bots == 1 ? "" : "s");
    effect(ctx, out, ph);
    effect(ctx, out, "revoked for good: if it ever connects to any hub it is told to wipe its config and exit (bot revoked)");
  } else if (!strcmp(code, "bot.kicked")) {
    char s[32];
    fmt_span(ctx->now - rvi(r, "since", ctx->now), s, sizeof(s));
    snprintf(subj, sizeof(subj), "%s  %s  (was connected %s from %s)", rv(r, "nick") ? rv(r, "nick") : "?",
             uuid, s, rv(r, "ip") ? rv(r, "ip") : "?");
    fmt_ok(ctx, "Bot disconnected", subj, out);
    effect(ctx, out, "it reconnects by itself; use bot del to remove it for good");
  } else if (!strcmp(code, "bot.rekey_howto")) {
    const char *nick = rvs(r, "nick") ? rv(r, "nick") : uuid;
    bool on = rvb(r, "online");
    char title[96], right[48];
    snprintf(title, sizeof(title), "Rekey bot %s", nick);
    snprintf(right, sizeof(right), "%s %s", on ? GL(G_ON) : GL(G_OFF), on ? "online" : "offline");
    fmt_title(ctx, out, title, right);
    line(out, RL_NORMAL, "  Only the bot holds its private key, so the rekey runs on the bot:");
    if (!on) {
      snprintf(ph, sizeof(ph), "%s is offline %s wait until it reconnects", nick, GL(G_DASH));
      warn(ctx, out, ph);
    }
    line(out, RL_NORMAL, "   1. in your IRC client, send %s the sealed command:  rekey", nick);
    line(out, RL_NORMAL, "   2. the bot makes a new key pair, sends its new public key here and reconnects");
    line(out, RL_NORMAL, "   3. other hubs pick up the new key with the next sync %s nothing else to do", GL(G_DASH));
    fmt_card_line(ctx, out, 12, "current key", rvs(r, "fp") ? rv(r, "fp") : "(no key)", RL_NORMAL);
  }
}

static void render_peer_change(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  const crec_t *r = &rep->res;
  char addr[96], subj[256];
  addr_of(r, addr, sizeof(addr));
  if (!strcmp(rep->code, "peer.added")) {
    snprintf(subj, sizeof(subj), "%s  %s  (#%lld)", peer_name(r), addr, rvi(r, "n", 0));
    fmt_ok(ctx, "Hub added", subj, out);
    res_kv(out, "uuid", rvs(r, "uuid") ? rv(r, "uuid") : GL(G_DASH));
    res_kv(out, "key", rvs(r, "fp") ? rv(r, "fp") : "?");
    snprintf(subj, sizeof(subj), "this hub dials it now; hub list shows the link once %s has added this hub too",
             peer_name(r));
    effect(ctx, out, subj);
  } else if (!strcmp(rep->code, "peer.removed")) {
    snprintf(subj, sizeof(subj), "%s  %s", peer_name(r), addr);
    fmt_ok(ctx, "Hub unlinked", subj, out);
    effect(ctx, out, rvb(r, "was_up") ? "link closed" : "it was down; there was no link to close");
    effect(ctx, out, "bots and hubs it carried reach the mesh through the other hubs");
    effect(ctx, out, "on this hub only: run hub del on the other hubs, -hub on the bots that list it");
  } else if (!strcmp(rep->code, "peer.set")) {
    char what[96];
    snprintf(what, sizeof(what), "Hub %s", peer_name(r));
    snprintf(subj, sizeof(subj), "%s   %s %s %s", rv(r, "setting") ? rv(r, "setting") : "?",
             rvs(r, "old") ? rv(r, "old") : "(none)", GL(G_ARROW), rvs(r, "value") ? rv(r, "value") : "?");
    fmt_ok(ctx, what, subj, out);
    effect(ctx, out, rvb(r, "relinked") ? "the link was dropped and comes back with the new key"
                                        : "the next connection uses the new key");
  } else {
    long long peers = rvi(r, "peers", 0);
    sb_t names = {0}, skipped = {0};
    for (int i = 0; i < rep->n; i++) {
      const crec_t *p = &rep->r[i];
      if (strcmp(p->type, "peer")) continue;
      sb_t *b = rvb(p, "sent") ? &names : &skipped;
      if (b->len) sb_add(b, ", ");
      sb_add(b, peer_name(p));
    }
    char what[96];
    snprintf(what, sizeof(what), "Full sync sent to %lld other hub%s", peers, peers == 1 ? "" : "s");
    fmt_ok(ctx, what, names.p, out);
    char sz[32], c[32];
    fmt_bytes((unsigned long long)rvi(r, "bytes", 0), sz, sizeof(sz));
    fmt_count((unsigned long long)rvi(r, "records", 0), c, sizeof(c));
    snprintf(subj, sizeof(subj), "%s records %s %s", c, GL(G_DOT), sz);
    effect(ctx, out, subj);
    if (skipped.len) {
      snprintf(subj, sizeof(subj), "%s %s down and %s skipped", skipped.p,
               strchr(skipped.p, ',') ? "are" : "is", strchr(skipped.p, ',') ? "were" : "was");
      warn(ctx, out, subj);
    }
    sb_free(&names);
    sb_free(&skipped);
  }
}

/* ==========================================================================
 * Wrapping: no line past the width (§3.5 acceptance).  Lines break at blanks
 * only, so a key, a uuid or any other unbroken token stays whole (D10) even
 * where it is wider than the view.  A continuation lines up with the value
 * column of a "label   value" line, else just past a leading glyph.
 * ========================================================================== */
static int width_n(const char *s, size_t n) {
  int w = 0;
  for (size_t i = 0; i < n;) {
    unsigned cp;
    int cw;
    i += console_next_char(s + i, n - i, &cp, &cw);
    w += cw;
  }
  return w;
}

static int wrap_indent(const char *t, int W) {
  size_t n = strlen(t), lead = 0;
  while (lead < n && t[lead] == ' ') lead++;
  size_t e = lead;
  while (e < n && t[e] != ' ') e++;
  size_t sp = e;
  while (sp < n && t[sp] == ' ') sp++;
  int ind;
  if (sp - e >= 2 && sp < n) ind = width_n(t, sp);
  else ind = (int)lead + 2;
  if (ind > W / 2) ind = (int)lead + 2;
  return ind;
}

void fmt_wrap(flines_t *f, int W) {
  flines_t o = {0};
  sb_t cur = {0};
  for (int k = 0; k < f->n; k++) {
    const char *t = f->v[k].text;
    int role = f->v[k].role;
    /* a command line (an echo, a help example) stays whole: the terminal
     * wraps it visually and a copy runs as typed */
    if (W <= 0 || role == RL_CMD || console_str_width(t) <= W) {
      flines_add(&o, role, t);
      continue;
    }
    int ind = wrap_indent(t, W);
    size_t n = strlen(t), i = 0;
    bool word = false;     /* the current line has a word on it */
    sb_reset(&cur);
    while (i < n) {
      size_t s0 = i;
      while (i < n && t[i] == ' ') i++;
      size_t w0 = i;
      while (i < n && t[i] != ' ') i++;
      if (w0 == i) {        /* trailing blanks */
        break;
      }
      int sw = (int)(w0 - s0), ww = width_n(t + w0, i - w0);
      /* a token no continuation could hold either (a key) stays where it
       * is: the terminal wraps it visually, the copy stays one line */
      if (!word || cur.w + sw + ww <= W || ww > W - ind) {
        sb_addn(&cur, t + s0, w0 - s0);
      } else {
        sb_emit(&cur, &o, role);
        sb_rep(&cur, " ", ind);
      }
      sb_addn(&cur, t + w0, i - w0);
      word = true;
    }
    sb_emit(&cur, &o, role);
  }
  sb_free(&cur);
  flines_free(f);
  *f = o;
}

/* ==========================================================================
 * Dispatch
 * ========================================================================== */
static void render_generic(const fmt_ctx_t *ctx, const creply_t *rep, flines_t *out) {
  fmt_ok(ctx, rep->code[0] ? rep->code : "done", NULL, out);
  static const char *const none[] = {NULL};
  unknown_keys(ctx, out, &rep->res, none, 12);
  for (int i = 0; i < rep->n; i++) {
    const crec_t *r = &rep->r[i];
    if (!r->n) {
      line(out, RL_NORMAL, "  %s", r->line ? r->line : "");
      continue;
    }
    line(out, RL_HEAD, "  %s", r->type);
    unknown_keys(ctx, out, r, none, 12);
  }
}

void fmt_reply(const fmt_ctx_t *ctx, const creply_t *rep, const char *words, flines_t *out) {
  (void)words;
  const char *c = rep->code ? rep->code : "";
  if (rep->err) {
    fmt_error(ctx, rv(&rep->res, "msg"), rv(&rep->res, "hint"), out);
    if (!strcmp(c, "bot.ambiguous")) {
      static const col_t cols[] = {{"UUID", 'L', 1}, {"NICK", 'L', 1}, {"STATE", 'L', 1}};
      tbl_t t;
      tbl_init(&t, cols, 3, -1, 0, 0);
      t.indent = 3;
      for (int i = 0; i < rep->n; i++) {
        const crec_t *r = &rep->r[i];
        if (strcmp(r->type, "bot")) continue;
        const char *cells[3] = {rv(r, "uuid"), rv(r, "nick"), rvb(r, "online") ? "online" : "offline"};
        tbl_row(ctx, &t, RL_NORMAL, NULL, cells);
      }
      tbl_render(ctx, out, &t);
      tbl_free(&t);
    }
    fmt_wrap(out, ctx->width);
    return;
  }
  if (!rep->ok) {
    /* not a record reply: show it as it came */
    for (int i = 0; i < rep->n; i++) flines_add(out, RL_NORMAL, rep->r[i].line ? rep->r[i].line : "");
    return;
  }
  if (ctx->mode == FMT_MODE_HUB_SETTINGS && !strcmp(c, "hub.show")) render_hub_settings(ctx, &rep->res, out);
  else if (ctx->mode == FMT_MODE_LIMITS && !strcmp(c, "hub.show")) render_limits(ctx, &rep->res, out);
  else if (!strcmp(c, "bot.list")) render_bot_list(ctx, rep, out);
  else if (!strcmp(c, "bot.show")) render_bot_show(ctx, rep, out);
  else if (!strcmp(c, "bot.summary")) render_bot_summary(ctx, rep, out);
  else if (!strcmp(c, "bot.revoked")) render_bot_revoked(ctx, rep, out);
  else if (!strncmp(c, "bot.", 4)) render_bot_change(ctx, rep, out);
  else if (!strcmp(c, "peer.list")) render_peer_list(ctx, rep, out);
  else if (!strcmp(c, "peer.show")) render_peer_show(ctx, rep, out);
  else if (!strcmp(c, "peer.refs")) render_peer_refs(ctx, rep, out);
  else if (!strncmp(c, "peer.", 5) || !strcmp(c, "mesh.synced")) render_peer_change(ctx, rep, out);
  else if (!strcmp(c, "hub.show")) render_hub_show(ctx, &rep->res, out);
  else if (!strcmp(c, "hub.set")) render_hub_set(ctx, rep, out);
  else if (!strcmp(c, "hub.rekeyed")) render_hub_rekeyed(ctx, rep, out);
  else if (!strcmp(c, "tomb.purged")) render_tomb_purged(ctx, rep, out);
  else if (!strcmp(c, "stats")) render_stats(ctx, rep, out);
  else if (!strcmp(c, "log.show")) render_log_show(ctx, rep, out);
  else if (!strcmp(c, "log.set")) render_log_set(ctx, rep, out);
  else if (!strcmp(c, "acl.list")) render_acl_list(ctx, rep, out);
  else if (!strcmp(c, "acl.added") || !strcmp(c, "acl.removed")) render_acl_change(ctx, rep, out);
  else if (!strcmp(c, "option.list")) render_option_list(ctx, rep, out);
  else if (!strcmp(c, "option.set")) render_option_set(ctx, rep, out);
  else if (!strcmp(c, "user.list")) render_user_list(ctx, rep, out);
  else if (!strcmp(c, "user.show")) render_user_show(ctx, rep, out);
  else if (!strncmp(c, "user.", 5)) render_user_change(ctx, rep, out);
  else if (!strcmp(c, "channel.list")) render_channel_list(ctx, rep, out);
  else if (!strcmp(c, "channel.show")) render_channel_show(ctx, rep, out);
  else if (!strcmp(c, "channel.settings")) render_settings_table(ctx, rep, out, false);
  else if (!strcmp(c, "channel.mode")) render_channel_mode(ctx, rep, out);
  else if (!strcmp(c, "channel.set")) render_settings_change(ctx, rep, out);
  else if (!strcmp(c, "ban.list")) render_ban_list(ctx, rep, out);
  else if (!strncmp(c, "ban.", 4)) render_ban_change(ctx, rep, out);
  else if (!strcmp(c, "network.settings")) render_settings_table(ctx, rep, out, true);
  else if (!strcmp(c, "network.set")) render_settings_change(ctx, rep, out);
  else if (!strncmp(c, "channel.", 8)) render_channel_change(ctx, rep, out);
  else if (!strcmp(c, "upg.status")) render_upg_status(ctx, rep, out);
  else if (!strcmp(c, "upg.releases")) render_upg_releases(ctx, rep, out);
  else if (!strncmp(c, "upg.", 4)) render_upg_change(ctx, rep, out);
  else if (!strcmp(c, "network.tree")) render_network_tree(ctx, rep, out);
  else render_generic(ctx, rep, out);
  fmt_wrap(out, ctx->width);
}
