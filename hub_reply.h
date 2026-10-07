/* Admin console replies as records (docs/console.md §3.1).
 *
 * Every CMD_ADMIN_* reply is UTF-8 text, one record per line:
 *
 *   ok|<code>[|k=v…]                       or
 *   err|<code>|msg=<text>[|hint=<text>][|k=v…]
 *   <type>|k=v|k=v…                        (data records, any number)
 *   more|n=<count>                         (records that did not fit)
 *
 * <code> is a dotted slug that never changes once shipped.  Values escape
 * '%' '|' '\n' '\r' as %25 %7C %0A %0D and nothing else; times are Unix
 * seconds, sizes bytes, booleans 0/1, lists ','-separated, and a missing
 * value is an absent key.  The console renders them (hub_console_fmt.c);
 * the Rust hub's src/reply.rs builds the same bytes. */
#ifndef HUB_REPLY_H
#define HUB_REPLY_H

#include <stdbool.h>
#include <stddef.h>

/* A reply never grows past this; records past it are counted in more|. */
#define CONSOLE_REPLY_MAX (256 * 1024)

typedef struct reply {
  char  *p;          /* committed records, '\n'-separated                */
  size_t len, cap;
  char  *line;       /* the record being built                           */
  size_t line_len, line_cap;
  bool   in_line;
  bool   oom;
  int    dropped;    /* records that did not fit                         */
} reply_t;

void reply_init(reply_t *r);
/* Result line (always the first record). */
void reply_ok(reply_t *r, const char *code);
void reply_err(reply_t *r, const char *code, const char *msg, const char *hint);
/* Start a data record of this type; the k=v calls below append to it. */
void reply_rec(reply_t *r, const char *type);
/* key=value on the current record; a NULL value adds nothing. */
void reply_kv(reply_t *r, const char *key, const char *val);
void reply_kvn(reply_t *r, const char *key, const char *val, size_t n);
void reply_kvi(reply_t *r, const char *key, long long v);
void reply_kvu(reply_t *r, const char *key, unsigned long long v);
void reply_kvb(reply_t *r, const char *key, bool v);
/* The finished text (NUL-terminated, with a more| record when needed);
 * owned by r until reply_free. */
const char *reply_text(reply_t *r);
void reply_free(reply_t *r);

#endif
