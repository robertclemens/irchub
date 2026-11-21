/* sync_digest.h — hash-first hub anti-entropy (CMD_SYNC_DIGEST 0x94), 2.5.4.
 *
 * Pure: a sync packet (hub_generate_sync_packet's text) in, digest / pull /
 * selection text out; SHA-256 through OpenSSL EVP.  irchub.rs carries the
 * same rules in src/sync_digest.rs.  Spec and reference model:
 * ircbot-testnet/proto/syncdigest/model.py (`digest`, `norm`), which the
 * testnet checks both copies against.
 *
 * A record kind is a line's first field (the bytes before its first '|',
 * the whole line when it has none).  Before hashing, a line's max-merged
 * activity field is blanked: field 5 of a|/o| (last_seen), field 4 of m|
 * (last_used).  A kind's normalised lines are sorted bytewise and hashed
 * each followed by '\n'.  Digest: "v|1\n" then "s|<kind>|<count>|<hex>\n" per
 * kind, kinds sorted bytewise. */
#ifndef SYNC_DIGEST_H
#define SYNC_DIGEST_H

#include <stdbool.h>
#include <stddef.h>

#define SDG_KIND_MAX  15
#define SDG_KINDS_MAX 48
#define SDG_HEX       64

typedef struct {
  char kind[SDG_KIND_MAX + 1];
  long count;
  char hex[SDG_HEX + 1];
} sdg_entry_t;

/* The digest of `packet` into `out`: its length, or -1 (a kind over
 * SDG_KIND_MAX bytes or more than SDG_KINDS_MAX kinds, `cap` too small, OOM,
 * a digest failure). */
long sdg_digest(const char *packet, size_t len, char *out, size_t cap);

/* Parse a digest: the entries (kinds strictly ascending), or -1 when
 * malformed. */
int sdg_parse(const char *p, size_t len, sdg_entry_t *out, int max);

/* The kinds whose entry differs (count or hash, or present on one side
 * only), ascending, into kinds[]; their number, or -1 past `max`. */
int sdg_mismatch(const sdg_entry_t *a, int na, const sdg_entry_t *b, int nb,
                 char kinds[][SDG_KIND_MAX + 1], int max);

/* A pull "r|k1,k2\n" / "r|*\n": the kinds into kinds[] (*all for '*');
 * their number, or -1 when malformed. */
int sdg_parse_pull(const char *p, size_t len, char kinds[][SDG_KIND_MAX + 1], int max,
                   bool *all);

/* The lines of `packet` whose kind is one of kinds[0..nk) (every line when
 * `all`), unchanged, into `out` (NUL-terminated); their bytes, or -1 when
 * they do not fit. */
long sdg_select(const char *packet, size_t len, char kinds[][SDG_KIND_MAX + 1], int nk,
                bool all, char *out, size_t cap);

#endif
