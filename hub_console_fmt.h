/* SSH admin console — the output renderer (docs/console.md §3.5).
 *
 * The hub answers every admin command with records (hub_reply.h); this file
 * parses them and lays them out for the view: title rules, aligned tables
 * that go wide → stacked → cards as the width shrinks (never dropping a
 * field), key/value cards, ✓/✗ results with their effects, UTC times,
 * 1024-based sizes.  Pure functions of (records, width, glyphs, clock): the
 * Rust console (src/console/fmt.rs) produces the same bytes. */
#ifndef HUB_CONSOLE_FMT_H
#define HUB_CONSOLE_FMT_H

#include "hub_console_ui.h"

/* Line mode's output width unless "display width" says otherwise. */
#define CONSOLE_LINE_WIDTH 100
#define CONSOLE_WIDTH_MIN  60
#define CONSOLE_WIDTH_MAX  250

/* Line roles (the full screen colours them; line mode ignores them). */
enum {
  RL_NORMAL = 0, RL_CMD, RL_ERR, RL_OK, RL_TITLE, RL_WARN, RL_DIM, RL_HEAD, RL_RULE
};

/* ---- Parsed replies ---------------------------------------------------- */
typedef struct {
  char  *type;       /* "bot", "peer", … (tree rows: "H", "B", "D")      */
  int    n;
  char **k, **v;     /* un-escaped, sanitized                            */
  char  *line;       /* the whole record, sanitized (raw output)         */
} crec_t;

typedef struct {
  bool    ok, err;   /* neither: not a record reply (shown as text)      */
  char   *code;
  crec_t  res;       /* the result line's k=v (msg, hint, …)             */
  crec_t *r;         /* data records                                     */
  int     n;
} creply_t;

void creply_parse(const char *text, size_t len, creply_t *out);
void creply_free(creply_t *rep);
const char *rv(const crec_t *rec, const char *key);         /* NULL if absent */
long long rvi(const crec_t *rec, const char *key, long long dflt);
bool rvb(const crec_t *rec, const char *key);                 /* 0/1 */
const char *rvs(const crec_t *rec, const char *key);         /* NULL if absent or empty */

/* ---- Output ------------------------------------------------------------ */
typedef struct {
  char *text;
  int   role;
} fline_t;

typedef struct {
  fline_t *v;
  int      n, cap;
} flines_t;

void flines_add(flines_t *o, int role, const char *text);
void flines_free(flines_t *o);

/* What a renderer needs to know about the session. */
typedef struct {
  int         width;       /* cells                                       */
  bool        ascii;
  long long   now;         /* Unix seconds                                */
  const char *admin, *ip, *hubname;
  int         mode;        /* FMT_MODE_*: how a reply is to be shown      */
  const char *session_log; /* log show: this session's log subscription  */
} fmt_ctx_t;

enum {
  FMT_MODE_NORMAL = 0,
  FMT_MODE_HUB_SETTINGS,   /* "hub set" alone: the settings table         */
  FMT_MODE_VIEW            /* full-screen views 4/5: no result line       */
};

/* Render a parsed reply.  `words` is the command ("bot list"). */
void fmt_reply(const fmt_ctx_t *ctx, const creply_t *rep, const char *words,
               flines_t *out);
/* A console-side refusal or note in the same shape as a hub's. */
void fmt_error(const fmt_ctx_t *ctx, const char *msg, const char *hint, flines_t *out);
void fmt_ok(const fmt_ctx_t *ctx, const char *what, const char *subject, flines_t *out);
/* Break lines wider than `width` at blanks (tokens stay whole). */
void fmt_wrap(flines_t *f, int width);

/* Pieces the UI uses directly. */
void fmt_title(const fmt_ctx_t *ctx, flines_t *out, const char *title,
               const char *right);
void fmt_card_line(const fmt_ctx_t *ctx, flines_t *out, int label_w,
                   const char *label, const char *value, int role);
const char *fmt_glyph(const fmt_ctx_t *ctx, int g);
const char *fmt_ascii_char(const char *s, size_t n, size_t *len);
char *fmt_ascii(const char *s);
void fmt_when(long long ts, long long now, char *out, size_t cap);
void fmt_span(long long secs, char *out, size_t cap);
void fmt_bytes(unsigned long long n, char *out, size_t cap);
void fmt_count(unsigned long long n, char *out, size_t cap);

enum {
  G_RULE = 0, G_ON, G_OFF, G_PEND, G_OK, G_ERR, G_WARN, G_BULLET, G_ELL, G_DOT,
  G_ARROW, G_TMID, G_TEND, G_TV, G_DASH, G_TIMES, G_FULL, G_EMPTY, G_OPEN,
  G_UNKNOWN, G_COUNT
};

/* Help for one command group, or the group list (hub_console_ui.c owns the
 * command table; it hands the rows here). */
typedef struct {
  const char *usage, *help, *args;
} fmt_help_row_t;

/* Text helpers shared with hub_console_ui.c. */
int    console_str_width(const char *s);
/* %.*s precision for at most max bytes of s, never splitting a character. */
int    console_uprec(const char *s, size_t max);
size_t console_next_char(const char *s, size_t n, unsigned *cp, int *w);

#endif
