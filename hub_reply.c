/* Admin console replies as records — the builder.  hub_reply.h for the
 * grammar.  Main thread only; a reply lives for one admin command. */
#include "hub_reply.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Room kept for the more| record once the reply is full. */
#define REPLY_MORE_RESERVE 32

void reply_init(reply_t *r) { memset(r, 0, sizeof(*r)); }

static void grow(char **p, size_t *cap, size_t need, bool *oom) {
  if (need <= *cap) return;
  size_t c = *cap ? *cap : 1024;
  while (c < need) c *= 2;
  char *np = realloc(*p, c);
  if (!np) {
    *oom = true;
    return;
  }
  *p = np;
  *cap = c;
}

static void line_add(reply_t *r, const char *s, size_t n) {
  if (r->oom) return;
  grow(&r->line, &r->line_cap, r->line_len + n + 1, &r->oom);
  if (r->oom) return;
  memcpy(r->line + r->line_len, s, n);
  r->line_len += n;
  r->line[r->line_len] = '\0';
}

/* Move the finished record into the reply, or count it as dropped. */
static void commit(reply_t *r) {
  if (!r->in_line) return;
  r->in_line = false;
  if (r->oom) return;
  size_t need = r->len + (r->len ? 1 : 0) + r->line_len;
  if (r->dropped || need > CONSOLE_REPLY_MAX - REPLY_MORE_RESERVE) {
    r->dropped++;
    r->line_len = 0;
    return;
  }
  grow(&r->p, &r->cap, need + 1, &r->oom);
  if (r->oom) return;
  if (r->len) r->p[r->len++] = '\n';
  memcpy(r->p + r->len, r->line, r->line_len);
  r->len += r->line_len;
  r->p[r->len] = '\0';
  r->line_len = 0;
}

static void start(reply_t *r, const char *type) {
  commit(r);
  r->in_line = true;
  r->line_len = 0;
  line_add(r, type, strlen(type));
}

void reply_ok(reply_t *r, const char *code) {
  start(r, "ok|");
  line_add(r, code, strlen(code));
}

void reply_err(reply_t *r, const char *code, const char *msg, const char *hint) {
  start(r, "err|");
  line_add(r, code, strlen(code));
  reply_kv(r, "msg", msg);
  reply_kv(r, "hint", hint);
}

void reply_rec(reply_t *r, const char *type) { start(r, type); }

void reply_kvn(reply_t *r, const char *key, const char *val, size_t n) {
  if (!val || !r->in_line) return;
  line_add(r, "|", 1);
  line_add(r, key, strlen(key));
  line_add(r, "=", 1);
  size_t run = 0;
  for (size_t i = 0; i < n && val[i]; i++) {
    const char *esc = val[i] == '%' ? "%25" : val[i] == '|' ? "%7C"
                    : val[i] == '\n' ? "%0A" : val[i] == '\r' ? "%0D" : NULL;
    if (!esc) {
      run++;
      continue;
    }
    line_add(r, val + i - run, run);
    run = 0;
    line_add(r, esc, 3);
  }
  size_t end = strnlen(val, n);
  line_add(r, val + end - run, run);
}

void reply_kv(reply_t *r, const char *key, const char *val) {
  if (val) reply_kvn(r, key, val, strlen(val));
}

void reply_kvi(reply_t *r, const char *key, long long v) {
  char b[24];
  snprintf(b, sizeof(b), "%lld", v);
  reply_kv(r, key, b);
}

void reply_kvu(reply_t *r, const char *key, unsigned long long v) {
  char b[24];
  snprintf(b, sizeof(b), "%llu", v);
  reply_kv(r, key, b);
}

void reply_kvb(reply_t *r, const char *key, bool v) { reply_kv(r, key, v ? "1" : "0"); }

const char *reply_text(reply_t *r) {
  commit(r);
  if (r->oom) return "err|internal.oom|msg=out of memory";
  if (r->dropped) {
    char m[REPLY_MORE_RESERVE];
    int n = snprintf(m, sizeof(m), "%smore|n=%d", r->len ? "\n" : "", r->dropped);
    r->dropped = 0;
    grow(&r->p, &r->cap, r->len + (size_t)n + 1, &r->oom);
    if (r->oom) return "err|internal.oom|msg=out of memory";
    memcpy(r->p + r->len, m, (size_t)n + 1);
    r->len += (size_t)n;
  }
  return r->p ? r->p : "";
}

void reply_free(reply_t *r) {
  free(r->p);
  free(r->line);
  memset(r, 0, sizeof(*r));
}
