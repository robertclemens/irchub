/* pool_rec.c — server pool records N|, S| and R| (2.5.4).  See pool_rec.h.
 * Byte-identical in irchub and ircbot. */
#include "pool_rec.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

#define POOL_FIELDS_MAX 9

static char afold(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c; }

/* Split `value` into exactly `want` '|'-separated fields in scratch `buf`. */
static bool split_fields(const char *value, int want, char *buf, size_t cap,
                         char *f[POOL_FIELDS_MAX]) {
  size_t n = strlen(value);
  if (want > POOL_FIELDS_MAX || n >= cap) return false;
  memcpy(buf, value, n + 1);
  int k = 0;
  char *p = buf;
  f[k++] = p;
  for (; *p; p++) {
    if (*p != '|') continue;
    if (k == want) return false;
    *p = '\0';
    f[k++] = p + 1;
  }
  return k == want;
}

/* A decimal 0..hi with no sign, no leading zero (except "0"), ≤ 5 digits. */
static bool num_ok(const char *s, int hi, int *out) {
  size_t n = strlen(s);
  if (n == 0 || n > 5 || (n > 1 && s[0] == '0')) return false;
  int v = 0;
  for (size_t i = 0; i < n; i++) {
    if (s[i] < '0' || s[i] > '9') return false;
    v = v * 10 + (s[i] - '0');
  }
  if (v > hi) return false;
  if (out) *out = v;
  return true;
}

static bool op_parse(const char *s, bool *deleted) {
  if (strcmp(s, "add") == 0) { *deleted = false; return true; }
  if (strcmp(s, "del") == 0) { *deleted = true; return true; }
  return false;
}

bool pool_net_id_ok(const char *s) {
  size_t n = s ? strlen(s) : 0;
  if (n == 0 || n > POOL_NET_ID_MAX) return false;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
  }
  return true;
}

bool pool_host_ok(const char *s) {
  size_t n = s ? strlen(s) : 0;
  if (n == 0 || n > POOL_HOST_MAX) return false;
  if (s[0] == '[') {
    if (n < 4 || s[n - 1] != ']') return false;
    bool colon = false;
    for (size_t i = 1; i + 1 < n; i++) {
      char c = afold(s[i]);
      if (c == ':') colon = true;
      else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || c == '.')) return false;
    }
    return colon;
  }
  if (s[0] == '-' || s[0] == '.') return false;
  bool alnum = false;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
      alnum = true;
    else if (c == '.') {
      if (i + 1 < n && s[i + 1] == '.') return false;
    } else if (c != '-')
      return false;
  }
  return alnum;
}

bool pool_net_name_ok(const char *s) {
  size_t n = s ? strlen(s) : 0;
  if (n == 0 || n > POOL_NET_NAME_MAX) return false;
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c <= 0x20 || c >= 0x7f || c == '|' || c == ',') return false;
  }
  return true;
}

/* Up to POOL_NET_ALIASES names, comma separated, no empty items; "" valid. */
static bool aliases_ok(const char *s) {
  size_t n = strlen(s);
  if (n == 0) return true;
  if (n > POOL_NET_ALIASES_MAX) return false;
  char buf[POOL_NET_ALIASES_MAX + 1];
  memcpy(buf, s, n + 1);
  int count = 0;
  char *save = NULL;
  if (buf[0] == ',' || buf[n - 1] == ',' || strstr(buf, ",,")) return false;
  for (char *t = strtok_r(buf, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
    if (++count > POOL_NET_ALIASES || !pool_net_name_ok(t)) return false;
  }
  return true;
}

/* Printable text without '|' (a label); "" valid. */
static bool text_ok(const char *s, size_t cap) {
  size_t n = strlen(s);
  if (n > cap) return false;
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    if (c < 0x20 || c >= 0x7f || c == '|') return false;
  }
  return true;
}

bool pool_srv_uuid(const char *net_id, const char *host, int port, char *out) {
  if (!pool_net_id_ok(net_id) || !pool_host_ok(host) || port < 1 || port > 65535)
    return false;
  char key[POOL_NET_ID_MAX + 1 + POOL_HOST_MAX + 8];
  size_t hl = strlen(host);
  if (hl > 1 && host[hl - 1] == '.') hl--;
  size_t k = (size_t)snprintf(key, sizeof(key), "%s|", net_id);
  for (size_t i = 0; i < hl; i++) key[k++] = afold(host[i]);
  k += (size_t)snprintf(key + k, sizeof(key) - k, ":%d", port);
  unsigned char h[EVP_MAX_MD_SIZE];
  unsigned int hlen = 0;
  if (!EVP_Digest(key, k, h, &hlen, EVP_sha256(), NULL) || hlen < 16) return false;
  h[6] = (unsigned char)((h[6] & 0x0f) | 0x80); /* version 8 */
  h[8] = (unsigned char)((h[8] & 0x3f) | 0x80); /* RFC 9562 variant */
  static const char hex[] = "0123456789abcdef";
  int o = 0;
  for (int i = 0; i < 16; i++) {
    if (i == 4 || i == 6 || i == 8 || i == 10) out[o++] = '-';
    out[o++] = hex[h[i] >> 4];
    out[o++] = hex[h[i] & 15];
  }
  out[o] = '\0';
  return true;
}

const char *pool_state_name(pool_state_t s) {
  return s == POOL_WRONGNET ? "wrongnet" : s == POOL_DISABLED ? "disabled" : "ok";
}

bool pool_state_parse(const char *s, pool_state_t *out) {
  pool_state_t v;
  if (strcmp(s, "ok") == 0) v = POOL_OK;
  else if (strcmp(s, "wrongnet") == 0) v = POOL_WRONGNET;
  else if (strcmp(s, "disabled") == 0) v = POOL_DISABLED;
  else return false;
  if (out) *out = v;
  return true;
}

bool pool_net_parse(const char *value, pool_net_t *out) {
  char buf[POOL_N_LINE_MAX];
  char *f[POOL_FIELDS_MAX];
  pool_net_t n;
  if (!value || !split_fields(value, 7, buf, sizeof(buf), f)) return false;
  if (!pool_net_id_ok(f[0]) || !text_ok(f[1], POOL_NET_LABEL_MAX)) return false;
  if (f[2][0] && !pool_net_name_ok(f[2])) return false;
  if (!aliases_ok(f[3]) || !num_ok(f[4], POOL_SPLIT_WAIT_MAX, &n.split_wait) ||
      !num_ok(f[5], POOL_PACE_GAP_MAX, &n.pace_gap) || !op_parse(f[6], &n.deleted))
    return false;
  if (out) {
    snprintf(n.net_id, sizeof(n.net_id), "%s", f[0]);
    snprintf(n.label, sizeof(n.label), "%s", f[1]);
    snprintf(n.name, sizeof(n.name), "%s", f[2]);
    snprintf(n.aliases, sizeof(n.aliases), "%s", f[3]);
    *out = n;
  }
  return true;
}

bool pool_srv_parse(const char *value, pool_srv_t *out) {
  char buf[POOL_S_LINE_MAX];
  char *f[POOL_FIELDS_MAX];
  pool_srv_t s;
  if (!value || !split_fields(value, 9, buf, sizeof(buf), f)) return false;
  if (strlen(f[0]) != POOL_UUID_LEN || !pool_net_id_ok(f[1]) || !pool_host_ok(f[2]) ||
      !num_ok(f[3], 65535, &s.port) || s.port < 1 || !num_ok(f[4], POOL_WEIGHT_MAX, &s.weight) ||
      s.weight < 1 || !num_ok(f[5], POOL_MAX_MAX, &s.max) ||
      !pool_state_parse(f[6], &s.state) || !op_parse(f[8], &s.deleted))
    return false;
  /* seen is set only on a wrongnet entry */
  if (f[7][0] && (s.state != POOL_WRONGNET || !pool_net_name_ok(f[7]))) return false;
  char want[POOL_UUID_LEN + 1];
  if (!pool_srv_uuid(f[1], f[2], s.port, want) || strcmp(want, f[0]) != 0) return false;
  if (out) {
    memcpy(s.uuid, want, sizeof(s.uuid));
    snprintf(s.net_id, sizeof(s.net_id), "%s", f[1]);
    snprintf(s.host, sizeof(s.host), "%s", f[2]);
    snprintf(s.seen, sizeof(s.seen), "%s", f[7]);
    *out = s;
  }
  return true;
}

int pool_net_format(const pool_net_t *n, char *buf, size_t cap) {
  int w = snprintf(buf, cap, "%s|%s|%s|%s|%d|%d|%s", n->net_id, n->label, n->name,
                   n->aliases, n->split_wait, n->pace_gap, n->deleted ? "del" : "add");
  if (w < 0 || (size_t)w >= cap || !pool_net_parse(buf, NULL)) return -1;
  return w;
}

int pool_srv_format(const pool_srv_t *s, char *buf, size_t cap) {
  int w = snprintf(buf, cap, "%s|%s|%s|%d|%d|%d|%s|%s|%s", s->uuid, s->net_id, s->host,
                   s->port, s->weight, s->max, pool_state_name(s->state), s->seen,
                   s->deleted ? "del" : "add");
  if (w < 0 || (size_t)w >= cap || !pool_srv_parse(buf, NULL)) return -1;
  return w;
}

static bool ieq(const char *a, const char *b) {
  for (; *a && *b; a++, b++)
    if (afold(*a) != afold(*b)) return false;
  return *a == *b;
}

bool pool_net_matches(const pool_net_t *n, const char *network) {
  if (!n || !network || !network[0] || !n->name[0]) return false;
  if (ieq(n->name, network)) return true;
  const char *p = n->aliases;
  while (*p) {
    const char *e = strchr(p, ',');
    size_t len = e ? (size_t)(e - p) : strlen(p);
    char one[POOL_NET_NAME_MAX + 1];
    if (len <= POOL_NET_NAME_MAX) {
      memcpy(one, p, len);
      one[len] = '\0';
      if (ieq(one, network)) return true;
    }
    if (!e) break;
    p = e + 1;
  }
  return false;
}

bool pool_hostport_parse(const char *in, char *host, size_t hcap, int *port) {
  if (!in || !host || !port || hcap == 0) return false;
  const char *colon = NULL;
  if (in[0] == '[') {
    const char *rb = strchr(in, ']');
    if (!rb) return false;
    if (rb[1] == ':') colon = rb + 1;
    else if (rb[1] != '\0') return false;
  } else {
    colon = strrchr(in, ':');
  }
  size_t hl = colon ? (size_t)(colon - in) : strlen(in);
  if (hl == 0 || hl >= hcap) return false;
  memcpy(host, in, hl);
  host[hl] = '\0';
  *port = POOL_DEFAULT_PORT;
  if (colon && (!num_ok(colon + 1, 65535, port) || *port == 0)) return false;
  return pool_host_ok(host);
}

/* ---- R| ------------------------------------------------------------------ */

static unsigned int fnv32(const char *s, size_t n) {
  unsigned int h = 2166136261u;
  for (size_t i = 0; i < n; i++) {
    h ^= (unsigned char)s[i];
    h *= 16777619u;
  }
  return h;
}

static bool uuid_shape(const char *s, size_t n) {
  if (n != POOL_UUID_LEN) return false;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    bool dash = i == 8 || i == 13 || i == 18 || i == 23;
    if (dash ? c != '-' : !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  }
  return true;
}

/* "<slot>|<slots>|<gap>|<ids>" of o into buf; its length or -1. */
static int order_body(const pool_order_t *o, char *buf, size_t cap) {
  if (o->n < 1 || o->n > POOL_ORDER_MAX || o->slots < 1 || o->slots > POOL_ORDER_SLOTS_MAX ||
      o->slot < 0 || o->slot >= o->slots ||
      o->gap < 0 || o->gap > POOL_PACE_GAP_MAX)
    return -1;
  int w = snprintf(buf, cap, "%d|%d|%d|", o->slot, o->slots, o->gap);
  if (w < 0 || (size_t)w >= cap) return -1;
  size_t off = (size_t)w;
  for (int i = 0; i < o->n; i++) {
    if (!uuid_shape(o->ids[i], strlen(o->ids[i]))) return -1;
    for (int j = 0; j < i; j++)
      if (strcmp(o->ids[i], o->ids[j]) == 0) return -1;
    w = snprintf(buf + off, cap - off, "%s%s", i ? "," : "", o->ids[i]);
    if (w < 0 || (size_t)w >= cap - off) return -1;
    off += (size_t)w;
  }
  return (int)off;
}

int pool_order_format(pool_order_t *o, char *buf, size_t cap) {
  char body[POOL_R_LINE_MAX];
  int bl = order_body(o, body, sizeof(body));
  if (bl < 0) return -1;
  o->gen = fnv32(body, (size_t)bl);
  int w = snprintf(buf, cap, "%08x|%s", o->gen, body);
  if (w < 0 || (size_t)w >= cap) return -1;
  return w;
}

bool pool_order_parse(const char *value, pool_order_t *out) {
  static pool_order_t o; /* ~2.4 KB: off the stack */
  char buf[POOL_R_LINE_MAX];
  char *f[POOL_FIELDS_MAX];
  if (!value || !split_fields(value, 5, buf, sizeof(buf), f)) return false;
  if (strlen(f[0]) != 8) return false;
  unsigned int gen = 0;
  for (int i = 0; i < 8; i++) {
    char c = f[0][i];
    int d = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
    if (d < 0) return false;
    gen = gen << 4 | (unsigned int)d;
  }
  memset(&o, 0, sizeof(o));
  if (!num_ok(f[1], POOL_ORDER_SLOTS_MAX, &o.slot) ||
      !num_ok(f[2], POOL_ORDER_SLOTS_MAX, &o.slots) || !num_ok(f[3], POOL_PACE_GAP_MAX, &o.gap))
    return false;
  const char *p = f[4];
  while (*p) {
    const char *c = strchr(p, ',');
    size_t n = c ? (size_t)(c - p) : strlen(p);
    if (o.n >= POOL_ORDER_MAX || !uuid_shape(p, n)) return false;
    memcpy(o.ids[o.n], p, n);
    o.ids[o.n][n] = '\0';
    for (int j = 0; j < o.n; j++)
      if (strcmp(o.ids[j], o.ids[o.n]) == 0) return false;
    o.n++;
    if (!c) break;
    p = c + 1;
    if (!*p) return false; /* trailing ',' */
  }
  if (o.n < 1) return false;
  char body[POOL_R_LINE_MAX];
  int bl = order_body(&o, body, sizeof(body));
  if (bl < 0 || fnv32(body, (size_t)bl) != gen) return false;
  o.gen = gen;
  if (out) *out = o;
  return true;
}
