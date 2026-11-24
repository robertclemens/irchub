/* pool_rec.h — server pool records N| and S| (2.5.4).
 *
 * Byte-identical in irchub and ircbot (like cfg_delta.[ch] and
 * glob_overlap.[ch]).  Plan: irchub/docs/plans/2026-10-29_server_pool_plan.md
 * §3.  Pure apart from SHA-256 (OpenSSL EVP): no I/O, no globals.
 *
 * Stored value (the line minus its "N|"/"S|" tag and its trailing |<ts>):
 *   N: <net_id>|<label>|<name>|<aliases csv>|<split_wait min>|<add|del>
 *   S: <uuid>|<net_id>|<host>|<port>|<weight>|<max>|<state>|<seen>|<add|del>
 *
 * An S| uuid is derived, never chosen: the first 16 bytes of
 * SHA-256(<net_id> "|" <key>) with the RFC 9562 version-8 / variant bits set,
 * where <key> = lower(host without one trailing '.') ":" port.  Every entry
 * has an explicit port (1..65535): one typed without gets POOL_DEFAULT_PORT,
 * so "host" and "host:6667" are one entry; TLS is port 6697 (the bot's rule).  The same server added on any hub or bot is the same record, and a
 * value whose uuid does not match its own net_id/host/port is refused. */
#ifndef POOL_REC_H
#define POOL_REC_H

#include <stdbool.h>
#include <stddef.h>

#define POOL_NET_ID_MAX      16   /* [a-z0-9-], immutable                 */
#define POOL_NET_LABEL_MAX   32
#define POOL_NET_NAME_MAX    64   /* a NETWORK= value                     */
#define POOL_NET_ALIASES     8    /* aliases per network                  */
#define POOL_NET_ALIASES_MAX (POOL_NET_ALIASES * (POOL_NET_NAME_MAX + 1))
#define POOL_SPLIT_WAIT_MAX  1440 /* minutes                              */
#define POOL_HOST_MAX        253
#define POOL_WEIGHT_MAX      100
#define POOL_MAX_MAX         100  /* soft cap on bots per entry; 0 = none */
#define POOL_UUID_LEN        36
#define POOL_DEFAULT_NET     "main"
#define POOL_DEFAULT_PORT    6667

/* One serialized line each at its caps: tag + fields + op + 20-digit stamp +
 * separators + newline, rounded up. */
#define POOL_N_LINE_MAX \
  (2 + POOL_NET_ID_MAX + POOL_NET_LABEL_MAX + POOL_NET_NAME_MAX + \
   POOL_NET_ALIASES_MAX + 4 + 3 + 20 + 16)
#define POOL_S_LINE_MAX \
  (2 + POOL_UUID_LEN + POOL_NET_ID_MAX + POOL_HOST_MAX + 5 + 3 + 4 + 8 + \
   POOL_NET_NAME_MAX + 3 + 20 + 16)

typedef enum { POOL_OK = 0, POOL_WRONGNET, POOL_DISABLED } pool_state_t;

typedef struct {
  char net_id[POOL_NET_ID_MAX + 1];
  char label[POOL_NET_LABEL_MAX + 1];
  char name[POOL_NET_NAME_MAX + 1];
  char aliases[POOL_NET_ALIASES_MAX + 1];
  int split_wait;
  bool deleted;
} pool_net_t;

typedef struct {
  char uuid[POOL_UUID_LEN + 1];
  char net_id[POOL_NET_ID_MAX + 1];
  char host[POOL_HOST_MAX + 1];
  int port;                /* 1..65535                       */
  int weight;              /* 1..POOL_WEIGHT_MAX             */
  int max;                 /* 0..POOL_MAX_MAX, 0 = none      */
  pool_state_t state;
  char seen[POOL_NET_NAME_MAX + 1]; /* NETWORK= that flagged it */
  bool deleted;
} pool_srv_t;

/* A net_id: 1..POOL_NET_ID_MAX of [a-z0-9-]. */
bool pool_net_id_ok(const char *s);
/* A host: 1..POOL_HOST_MAX of [A-Za-z0-9.-] not starting with '-', or a
 * bracketed IPv6 literal [hex:.]. */
bool pool_host_ok(const char *s);
/* A NETWORK= value: 1..POOL_NET_NAME_MAX printable ASCII, no '|' or ','. */
bool pool_net_name_ok(const char *s);

/* The derived uuid for (net_id, host, port) into out[POOL_UUID_LEN + 1].
 * False on a bad net_id/host or a port outside 1..65535. */
bool pool_srv_uuid(const char *net_id, const char *host, int port, char *out);

/* Parse a stored value (see top).  False on any shape, cap or charset
 * error, or (S) a uuid that is not the derived one.  `out` may be NULL. */
bool pool_net_parse(const char *value, pool_net_t *out);
bool pool_srv_parse(const char *value, pool_srv_t *out);

/* Format a stored value (no tag, no stamp).  Returns the length, or -1 if it
 * did not fit or the record is invalid. */
int pool_net_format(const pool_net_t *n, char *buf, size_t cap);
int pool_srv_format(const pool_srv_t *s, char *buf, size_t cap);

/* ASCII case-insensitive match of `network` against a network's name and
 * aliases.  An empty name matches nothing (the caller decides "not learned"). */
bool pool_net_matches(const pool_net_t *n, const char *network);

/* The text of a state, and back.  pool_state_parse false if unknown. */
const char *pool_state_name(pool_state_t s);
bool pool_state_parse(const char *s, pool_state_t *out);

/* Split "host[:port]" or "[v6][:port]" as typed by an admin; a missing port
 * is POOL_DEFAULT_PORT.  False on a bad host or port. */
bool pool_hostport_parse(const char *in, char *host, size_t hcap, int *port);

#endif /* POOL_REC_H */
