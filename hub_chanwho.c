/* hub_chanwho.c — `channel who` (2.5.4, docs/plans/2026-11-21_channel_who_plan.md):
 * the pure halves of CMD_CHAN_WHO 0x95 at the origin hub.  chanwho_add joins
 * the picked bot's chunks into one heap buffer (CHAN_WHO_MAX, order checked);
 * chanwho_parse reads the joined body (ircbot/bot.h has its lines) into a
 * view with the members sorted the irssi way.  No hub state: hub_logic.c's
 * election calls them, and ircbot-testnet/fuzz/chanwho_fuzz.c fuzzes them.
 * irchub.rs elect.rs (process_who / who_answer) mirrors them. */
#include "hub.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>

void chanwho_reset(chanwho_acc_t *a) {
  if (a->buf) secure_wipe(a->buf, CHAN_WHO_MAX + 1); /* it holds the key */
  free(a->buf);
  memset(a, 0, sizeof(*a));
}

int chanwho_add(chanwho_acc_t *a, const char *seqs, const char *more, const char *body,
                size_t bl) {
  if (!seqs || !more || !body || !seqs[0]) return -1;
  long seq = 0;
  for (const char *p = seqs; *p; p++) {
    if (*p < '0' || *p > '9' || seq > 100000) return -1;
    seq = seq * 10 + (*p - '0');
  }
  if (seq == 0) { /* a retry with the next bot starts afresh */
    a->len = 0;
    a->seq = 0;
    a->done = a->bad = false;
    if (a->buf) a->buf[0] = '\0';
  }
  if (a->bad) return -1;
  if (seq != a->seq || a->done) {
    a->bad = true;
    return -1;
  }
  if (bl > CHAN_WHO_MAX - a->len) {
    a->bad = true;
    return -2;
  }
  if (!a->buf && !(a->buf = malloc(CHAN_WHO_MAX + 1))) {
    a->bad = true;
    return -1;
  }
  memcpy(a->buf + a->len, body, bl);
  a->len += bl;
  a->buf[a->len] = '\0';
  a->seq++;
  if (strcmp(more, "0") == 0) a->done = true;
  return 0;
}

bool chanwho_complete(const chanwho_acc_t *a) { return a->buf && a->done && !a->bad; }

/* Text from a bot for the console: control bytes go ('|' stays; the reply
 * escapes it).  Bounded to cap. */
static void wtext_clean(char *dst, size_t cap, const char *src, size_t n) {
  size_t o = 0;
  for (size_t i = 0; i < n && src[i] && o + 1 < cap; i++) {
    unsigned char ch = (unsigned char)src[i];
    if (ch < 0x20 || ch == 0x7f) continue;
    dst[o++] = (char)ch;
  }
  dst[o] = '\0';
}

/* irssi order: ops, halfops, voices, the rest; A-Z ignoring ASCII case
 * within each; then by bytes (irchub.rs sorts the same). */
static int who_nick_cmp(const void *a, const void *b) {
  const chanwho_nick_t *x = a, *y = b;
  if (x->rank != y->rank) return x->rank - y->rank;
  int c = strcasecmp(x->nick, y->nick);
  return c ? c : strcmp(x->nick, y->nick);
}

/* The value after "<tag>|" of the first body line that starts with it. */
static bool who_line(const char *body, char tag, const char **val, size_t *len) {
  for (const char *p = body; p && *p;) {
    const char *nl = strchr(p, '\n');
    size_t ll = nl ? (size_t)(nl - p) : strlen(p);
    if (ll >= 2 && p[0] == tag && p[1] == '|') {
      *val = p + 2;
      *len = ll - 2;
      return true;
    }
    p = nl ? nl + 1 : NULL;
  }
  return false;
}

/* Field i ('|'-separated) of a line value, cleaned; last = the rest. */
static void who_field(const char *val, size_t len, int i, bool last, char *out, size_t cap) {
  size_t s = 0;
  for (int k = 0; k < i && s <= len; k++) {
    const char *bar = memchr(val + s, '|', len - s);
    if (!bar) {
      out[0] = '\0';
      return;
    }
    s = (size_t)(bar - val) + 1;
  }
  size_t e = len;
  if (!last) {
    const char *bar = memchr(val + s, '|', len - s);
    if (bar) e = (size_t)(bar - val);
  }
  wtext_clean(out, cap, val + s, e - s);
}

static long long who_num(const char *s) {
  long long v = 0;
  for (; *s >= '0' && *s <= '9'; s++) {
    if (v > (long long)1e15) return 0;
    v = v * 10 + (*s - '0');
  }
  return v;
}

int chanwho_parse(const char *body, chanwho_view_t *v) {
  memset(v, 0, sizeof(*v));
  if (!body) return -1;
  const char *val;
  size_t vl;
  char f1[24] = "", f2[24] = "";
  if (who_line(body, 't', &val, &vl)) {
    who_field(val, vl, 0, false, f1, sizeof(f1));
    who_field(val, vl, 1, false, f2, sizeof(f2));
  }
  v->topic_known = strcmp(f1, "1") == 0;
  v->topic_at = who_num(f2);
  if (who_line(body, 'B', &val, &vl)) wtext_clean(v->topic_by, sizeof(v->topic_by), val, vl);
  if (who_line(body, 'T', &val, &vl)) wtext_clean(v->topic, sizeof(v->topic), val, vl);
  f1[0] = f2[0] = '\0';
  if (who_line(body, 'M', &val, &vl)) {
    who_field(val, vl, 0, false, f1, sizeof(f1));
    who_field(val, vl, 1, false, f2, sizeof(f2));
    who_field(val, vl, 2, true, v->modes, sizeof(v->modes));
  }
  v->modes_known = strcmp(f1, "1") == 0;
  v->limit = who_num(f2);
  if (who_line(body, 'K', &val, &vl)) wtext_clean(v->key, sizeof(v->key), val, vl);
  if (who_line(body, 'C', &val, &vl)) {
    who_field(val, vl, 1, false, f1, sizeof(f1));
    v->capped = strcmp(f1, "1") == 0;
  }
  /* the members: N|@a %b +c d ... (any number of N lines) */
  int cap = 0;
  for (const char *p = body; *p; p++)
    if (*p == ' ' || *p == '|') cap++;
  v->nicks = calloc((size_t)cap + 1, sizeof(*v->nicks));
  if (!v->nicks) return -1;
  for (const char *p = body; p && *p;) {
    const char *nl = strchr(p, '\n');
    size_t ll = nl ? (size_t)(nl - p) : strlen(p);
    if (ll >= 2 && p[0] == 'N' && p[1] == '|') {
      size_t i = 2;
      while (i < ll && v->n <= cap) {
        while (i < ll && p[i] == ' ') i++;
        size_t s = i;
        while (i < ll && p[i] != ' ') i++;
        if (i == s) break;
        const char *t = p + s;
        size_t tl = i - s;
        int rank = 3;
        if (t[0] == '@') rank = 0;
        else if (t[0] == '%') rank = 1;
        else if (t[0] == '+') rank = 2;
        if (rank < 3) {
          t++;
          tl--;
        }
        chanwho_nick_t *nk = &v->nicks[v->n];
        wtext_clean(nk->nick, sizeof(nk->nick), t, tl);
        if (!nk->nick[0]) continue;
        nk->rank = rank;
        v->n++;
      }
    }
    p = nl ? nl + 1 : NULL;
  }
  qsort(v->nicks, (size_t)v->n, sizeof(*v->nicks), who_nick_cmp);
  for (int i = 0; i < v->n; i++) v->cnt[v->nicks[i].rank]++;
  return 0;
}

void chanwho_view_free(chanwho_view_t *v) {
  secure_wipe(v->key, sizeof(v->key));
  free(v->nicks);
  v->nicks = NULL;
  v->n = 0;
}
