/* hub_pubip.c — this hub's public IPv4 address, looked up over DNS.
 *
 * A hub that listens on 0.0.0.0 (or a private address behind NAT) cannot
 * tell the admin what to give other hubs and bots.  Three public "what is my
 * address" DNS names answer that, each asked of its own authoritative server
 * by IP literal (no system resolver, no dig):
 *
 *   OpenDNS     myip.opendns.com        IN A   @208.67.222.222
 *   Google      o-o.myaddr.l.google.com IN TXT @216.239.32.10
 *   Cloudflare  whoami.cloudflare       CH TXT @1.1.1.1
 *
 * They are tried in that order; the first global unicast IPv4 answer wins.
 * The result is display and advice only (hub list, hub show, -id, -setup's
 * paste lines): nothing dials it and nothing is sent to the mesh, so a wrong
 * or spoofed answer misleads a printout, never a link.  Still, replies are
 * hostile input: the source must be the server asked, the id must match a
 * random one, and every length is checked before it is read.
 *
 * Lookups: -setup (blocking, hub_pubip_lookup), then at every start and once
 * a day (hub_pubip_tick, non-blocking, one UDP socket, polled each loop).
 * The answer is kept in public|<ip>|<ts> and cannot be set by hand. */
#include "hub.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#define PUBIP_TIMEOUT 2    /* seconds per server */
#define PUBIP_MAX_ANSWERS 16

typedef struct {
  const char *who;
  const char *server; /* IPv4 literal */
  const char *qname;
  unsigned short qtype;  /* 1 = A, 16 = TXT */
  unsigned short qclass; /* 1 = IN, 3 = CH */
} pubip_src_t;

static const pubip_src_t g_src[PUBIP_SOURCES] = {
  {"OpenDNS", "208.67.222.222", "myip.opendns.com", 1, 1},
  {"Google", "216.239.32.10", "o-o.myaddr.l.google.com", 16, 1},
  {"Cloudflare", "1.1.1.1", "whoami.cloudflare", 16, 3},
};

const char *hub_pubip_source_name(int i) {
  return i >= 0 && i < PUBIP_SOURCES ? g_src[i].who : "?";
}

/* A public answer only: no private, shared, loopback, link-local, multicast
 * or reserved range (any of those means the server answered something else). */
bool hub_pubip_is_global(const char *ip) {
  struct in_addr a;
  if (!ip || inet_pton(AF_INET, ip, &a) != 1) return false;
  uint32_t h = ntohl(a.s_addr);
  unsigned o1 = h >> 24, o2 = (h >> 16) & 0xff;
  if (o1 == 0 || o1 == 10 || o1 == 127 || o1 >= 224) return false;
  if (o1 == 100 && (o2 & 0xc0) == 64) return false;  /* 100.64/10 CGNAT */
  if (o1 == 169 && o2 == 254) return false;
  if (o1 == 172 && (o2 & 0xf0) == 16) return false;
  if (o1 == 192 && o2 == 168) return false;
  if (o1 == 192 && o2 == 0 && ((h >> 8) & 0xff) == 0) return false; /* 192.0.0/24 */
  if (o1 == 198 && (o2 & 0xfe) == 18) return false;  /* 198.18/15 benchmarking */
  return true;
}

/* The query for source i into buf (cap >= 512); returns its length, 0 on error. */
static size_t pubip_build(int i, unsigned short id, unsigned char *buf, size_t cap) {
  const pubip_src_t *s = &g_src[i];
  size_t n = 0;
  if (cap < 512) return 0;
  buf[n++] = (unsigned char)(id >> 8);
  buf[n++] = (unsigned char)id;
  buf[n++] = 0x00; /* QR=0 opcode=0, RD=0: these are authoritative servers */
  buf[n++] = 0x00;
  buf[n++] = 0; buf[n++] = 1; /* QDCOUNT */
  for (int k = 0; k < 6; k++) buf[n++] = 0;
  const char *p = s->qname;
  while (*p) {
    const char *dot = strchr(p, '.');
    size_t l = dot ? (size_t)(dot - p) : strlen(p);
    if (l == 0 || l > 63 || n + l + 6 >= cap) return 0;
    buf[n++] = (unsigned char)l;
    memcpy(buf + n, p, l);
    n += l;
    p += l;
    if (*p == '.') p++;
  }
  buf[n++] = 0;
  buf[n++] = (unsigned char)(s->qtype >> 8);
  buf[n++] = (unsigned char)s->qtype;
  buf[n++] = (unsigned char)(s->qclass >> 8);
  buf[n++] = (unsigned char)s->qclass;
  return n;
}

/* Skip a (possibly compressed) name at *off; false when it runs off the end. */
static bool pubip_skip_name(const unsigned char *b, size_t n, size_t *off) {
  size_t o = *off;
  for (int guard = 0; guard < 128; guard++) {
    if (o >= n) return false;
    unsigned char l = b[o];
    if (l == 0) { *off = o + 1; return true; }
    if ((l & 0xc0) == 0xc0) {
      if (o + 2 > n) return false;
      *off = o + 2;
      return true;
    }
    if (l & 0xc0) return false;
    o += 1u + l;
  }
  return false;
}

/* The reply to query id for source i: the first global IPv4 answer, into out. */
bool hub_pubip_parse(int i, unsigned short id, const unsigned char *b, size_t n,
                     char *out, size_t cap) {
  if (i < 0 || i >= PUBIP_SOURCES || !b || n < 12 || n > 4096 || !out || cap < 16)
    return false;
  const pubip_src_t *s = &g_src[i];
  if ((unsigned short)((b[0] << 8) | b[1]) != id) return false;
  if (!(b[2] & 0x80) || (b[2] & 0x78) || (b[3] & 0x0f)) return false; /* QR, opcode, rcode */
  unsigned qd = (unsigned)((b[4] << 8) | b[5]), an = (unsigned)((b[6] << 8) | b[7]);
  if (qd != 1 || an == 0 || an > PUBIP_MAX_ANSWERS) return false;
  size_t o = 12;
  if (!pubip_skip_name(b, n, &o) || o + 4 > n) return false;
  o += 4;
  for (unsigned a = 0; a < an; a++) {
    if (!pubip_skip_name(b, n, &o) || o + 10 > n) return false;
    unsigned type = (unsigned)((b[o] << 8) | b[o + 1]);
    unsigned cls = (unsigned)((b[o + 2] << 8) | b[o + 3]);
    size_t rdlen = (size_t)((b[o + 8] << 8) | b[o + 9]);
    o += 10;
    if (rdlen > n - o) return false;
    char ip[INET_ADDRSTRLEN] = "";
    if (type == s->qtype && cls == s->qclass) {
      if (type == 1 && rdlen == 4) {
        inet_ntop(AF_INET, b + o, ip, sizeof(ip));
      } else if (type == 16 && rdlen >= 1) {
        size_t sl = b[o]; /* the first character-string */
        if (sl >= 7 && sl <= 15 && sl + 1 <= rdlen) {
          memcpy(ip, b + o + 1, sl);
          ip[sl] = '\0';
        }
      }
    }
    if (ip[0] && hub_pubip_is_global(ip)) {
      struct in_addr chk;
      if (inet_pton(AF_INET, ip, &chk) != 1) return false;
      inet_ntop(AF_INET, &chk, out, (socklen_t)cap); /* canonical form */
      return true;
    }
    o += rdlen;
  }
  return false;
}

/* One query socket, sent; -1 on error. */
static int pubip_send(int i, unsigned short *id) {
  unsigned char q[512], r[2];
  if (RAND_bytes(r, 2) != 1) return -1;
  *id = (unsigned short)((r[0] << 8) | r[1]);
  size_t ql = pubip_build(i, *id, q, sizeof(q));
  if (!ql) return -1;
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) return -1;
  int fl = fcntl(fd, F_GETFL, 0);
  if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) { close(fd); return -1; }
  (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons(53);
  if (inet_pton(AF_INET, g_src[i].server, &sa.sin_addr) != 1 ||
      sendto(fd, q, ql, 0, (struct sockaddr *)&sa, sizeof(sa)) != (ssize_t)ql) {
    close(fd);
    return -1;
  }
  return fd;
}

/* Read what has arrived on fd for source i; 1 = answer in out, 0 = nothing
 * yet, -1 = this server gave no usable answer. */
static int pubip_recv(int fd, int i, unsigned short id, char *out, size_t cap) {
  for (int k = 0; k < 8; k++) {
    unsigned char b[1500];
    struct sockaddr_in from;
    socklen_t fl = sizeof(from);
    ssize_t n = recvfrom(fd, b, sizeof(b), 0, (struct sockaddr *)&from, &fl);
    if (n < 0) return (IO_WOULD_BLOCK(errno) || errno == EINTR) ? 0 : -1;
    struct in_addr want;
    if (inet_pton(AF_INET, g_src[i].server, &want) != 1) return -1;
    /* only the server asked, from port 53: anything else is dropped */
    if (fl < sizeof(from) || from.sin_family != AF_INET || from.sin_port != htons(53) ||
        from.sin_addr.s_addr != want.s_addr)
      continue;
    return hub_pubip_parse(i, id, b, (size_t)n, out, cap) ? 1 : -1;
  }
  return 0;
}

#ifdef IRC_TEST_HOOKS
/* IRCHUB_TEST_PUBIP: "off" never looks up; an IPv4 address is the answer
 * (a sandbox must neither reach the internet nor show a varying address). */
static const char *pubip_hook(void) {
  const char *h = getenv("IRCHUB_TEST_PUBIP");
  return h && h[0] ? h : NULL;
}
#endif

/* Blocking lookup for -setup: tries each server for PUBIP_TIMEOUT seconds. */
bool hub_pubip_lookup(char *out, size_t cap, int *src) {
  if (!out || cap < INET_ADDRSTRLEN) return false;
  out[0] = '\0';
#ifdef IRC_TEST_HOOKS
  const char *h = pubip_hook();
  if (h) {
    struct in_addr a;
    if (strcmp(h, "off") == 0 || inet_pton(AF_INET, h, &a) != 1) return false;
    snprintf(out, cap, "%s", h);
    if (src) *src = -1;
    return true;
  }
#endif
  for (int i = 0; i < PUBIP_SOURCES; i++) {
    unsigned short id = 0;
    int fd = pubip_send(i, &id);
    if (fd < 0) continue;
    time_t until = time(NULL) + PUBIP_TIMEOUT;
    int got = 0;
    while (got == 0) {
      time_t now = time(NULL);
      if (now >= until) break;
      struct pollfd p = {fd, POLLIN, 0};
      int pr = poll(&p, 1, (int)(until - now) * 1000);
      if (pr < 0 && errno != EINTR) break;
      if (pr > 0) got = pubip_recv(fd, i, id, out, cap);
    }
    close(fd);
    if (got == 1) {
      if (src) *src = i;
      return true;
    }
  }
  out[0] = '\0';
  return false;
}

/* The running hub's lookup, one step per main-loop pass, never blocking. */
static struct {
  int fd;
  int src;
  unsigned short id;
  time_t sent;
  time_t next; /* when the next round starts (0 = at once) */
  bool failed_logged;
} g_pl = {-1, 0, 0, 0, 0, false};

static void pubip_close(void) {
  if (g_pl.fd >= 0) close(g_pl.fd);
  g_pl.fd = -1;
}

static void pubip_found(hub_state_t *state, const char *ip, int src, time_t now) {
  g_pl.failed_logged = false;
  bool changed = strcmp(state->public_ip, ip) != 0;
  if (changed)
    hub_log_info("[HUB] Public address %s (looked up via %s)\n", ip,
                 src >= 0 ? hub_pubip_source_name(src) : "test hook");
  snprintf(state->public_ip, sizeof(state->public_ip), "%s", ip);
  state->public_ip_at = now;
  /* the timestamp alone is not worth a config rewrite: a day-old one only
   * says the last restart looked */
  if (changed) state->config_dirty = true;
}

void hub_pubip_tick(hub_state_t *state, time_t now) {
#ifdef IRC_TEST_HOOKS
  const char *h = pubip_hook();
  if (h) {
    if (now < g_pl.next) return;
    g_pl.next = now + PUBIP_REFRESH;
    if (strcmp(h, "off") != 0 && hub_pubip_is_global(h)) pubip_found(state, h, -1, now);
    return;
  }
#endif
  if (g_pl.fd < 0) {
    if (now < g_pl.next) return;
    g_pl.src = 0;
    for (; g_pl.src < PUBIP_SOURCES; g_pl.src++) {
      g_pl.fd = pubip_send(g_pl.src, &g_pl.id);
      if (g_pl.fd >= 0) break;
    }
    g_pl.sent = now;
    if (g_pl.fd < 0) goto failed;
    return;
  }
  char ip[INET_ADDRSTRLEN];
  int got = pubip_recv(g_pl.fd, g_pl.src, g_pl.id, ip, sizeof(ip));
  if (got == 1) {
    pubip_close();
    g_pl.next = now + PUBIP_REFRESH;
    pubip_found(state, ip, g_pl.src, now);
    return;
  }
  if (got == 0 && now - g_pl.sent < PUBIP_TIMEOUT) return;
  /* this server is silent or useless: the next one */
  pubip_close();
  while (++g_pl.src < PUBIP_SOURCES) {
    g_pl.fd = pubip_send(g_pl.src, &g_pl.id);
    if (g_pl.fd >= 0) {
      g_pl.sent = now;
      return;
    }
  }
failed:
  /* every server failed: keep the last known address, try again in an hour */
  g_pl.next = now + PUBIP_RETRY;
  if (!g_pl.failed_logged)
    hub_log_info("[HUB] Public address lookup failed (OpenDNS, Google, Cloudflare); "
                 "%s\n", state->public_ip[0] ? "keeping the last one" : "retrying hourly");
  g_pl.failed_logged = true;
}

const char *hub_dial_address(const hub_state_t *state) {
  if (state->public_ip[0]) return state->public_ip;
  if (state->bind_ip[0] && strcmp(state->bind_ip, "0.0.0.0") != 0) return state->bind_ip;
  return NULL;
}
