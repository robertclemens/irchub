/* cfg_delta.h — bot config text deltas (CMD_CONFIG_DELTA 0x91), 2.5.4.
 *
 * Byte-identical in irchub and ircbot (like glob_overlap.[ch]); the Rust hub
 * and bot carry the same rules in cfg_delta.rs.  The reference model and the
 * exact spec are ircbot-testnet/proto/cfgdelta/model.py.
 *
 * Payload:  <base sha256 hex>|<new sha256 hex>\n  then ops, each ending \n:
 *             =<n>     keep the next n base lines
 *             -<n>     drop the next n base lines
 *             +<text>  insert one line
 * A line is a run of bytes ending in \n; both texts must be empty or end in
 * \n.  The ops must consume the base exactly.  Pure: no hashing, no I/O —
 * the caller checks the base hash before cfgd_patch and the result hash
 * after it, and applies nothing unless both match. */
#ifndef CFG_DELTA_H
#define CFG_DELTA_H

#include <stddef.h>

#define CFGD_HASH_HEX     64
#define CFGD_HEADER_LEN   (CFGD_HASH_HEX * 2 + 2)   /* "<64>|<64>\n" */
#define CFG_DELTA_LINE_MAX 8192   /* longest line a delta may insert          */
#define CFG_DELTA_MAX_EDITS 256   /* Myers D past which the hub sends full    */
#define CFG_DELTA_MAX_PCT  50     /* delta >= this % of the full text: full   */

/* Diff `base` -> `nw` into `out` (header from the two hex hashes, then ops).
 * Returns the payload length, or -1 for "send a full push instead": a text
 * not line framed, a line over CFG_DELTA_LINE_MAX, more than
 * CFG_DELTA_MAX_EDITS edits, a delta >= CFG_DELTA_MAX_PCT % of `nw`, a
 * payload over `cap`, or out of memory. */
long cfgd_diff(const char *base, size_t blen, const char *nw, size_t nlen,
               const char base_hex[CFGD_HASH_HEX], const char new_hex[CFGD_HASH_HEX],
               char *out, size_t cap);

/* The two hex hashes of a delta's header into base_hex / new_hex (each
 * CFGD_HASH_HEX bytes, not terminated).  0, or -1 for a malformed header. */
int cfgd_header(const char *payload, size_t plen, char *base_hex, char *new_hex);

/* Apply the ops of `payload` (header already checked) to `held` into `out`.
 * Returns the new text length, or -1 with *why set; on -1 `out` holds
 * nothing to use (the caller wipes it). */
long cfgd_patch(const char *held, size_t hlen, const char *payload, size_t plen,
                char *out, size_t cap, const char **why);

#endif
