/* SSH admin console — one session's user interface.  docs/console.md.
 *
 * Runs on the console thread only.  Everything the admin sees is built here:
 * the line-mode transcript (TERM=dumb, the testnet's interface) and the
 * full-screen irssi-style console (output pane, network tree, status bar,
 * input line), with the key parser, the command language and the sanitizer
 * that keeps text from bots, peers and logs from reaching the terminal as
 * escape sequences.  No libssh, no hub_state_t. */
#include "hub_console_fmt.h"
#include <ctype.h>
#include <stdarg.h>
#include <strings.h>

/* ==========================================================================
 * Byte buffers
 * ========================================================================== */
void cbuf_add(cbuf_t *b, const void *data, size_t n) {
  if (n == 0) return;
  if (b->len + n > b->cap) {
    size_t cap = b->cap ? b->cap : 4096;
    while (cap < b->len + n) cap *= 2;
    unsigned char *np = realloc(b->p, cap);
    if (!np) return;   /* out of memory: output is lost, the session goes on */
    b->p = np;
    b->cap = cap;
  }
  memcpy(b->p + b->len, data, n);
  b->len += n;
}

void cbuf_adds(cbuf_t *b, const char *s) { cbuf_add(b, s, strlen(s)); }

static void cbuf_addf(cbuf_t *b, const char *fmt, ...) {
  char tmp[512];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
  va_end(ap);
  if (n > 0) cbuf_add(b, tmp, (size_t)n < sizeof(tmp) ? (size_t)n : sizeof(tmp) - 1);
}

void cbuf_consume(cbuf_t *b, size_t n) {
  if (n >= b->len) {
    b->len = 0;
    return;
  }
  memmove(b->p, b->p + n, b->len - n);
  b->len -= n;
}

void cbuf_free(cbuf_t *b) {
  if (b->p) secure_wipe(b->p, b->cap);
  free(b->p);
  b->p = NULL;
  b->len = b->cap = 0;
}

/* ==========================================================================
 * Text: UTF-8, display width, sanitizer (docs/console.md §5)
 * ========================================================================== */
size_t console_utf8_len(const unsigned char *p, size_t n) {
  size_t len;
  unsigned min, cp;
  if (n == 0) return 0;
  if (p[0] < 0x80) return 1;
  if (p[0] >= 0xC2 && p[0] <= 0xDF)      { len = 2; min = 0x80;    cp = p[0] & 0x1F; }
  else if (p[0] >= 0xE0 && p[0] <= 0xEF) { len = 3; min = 0x800;   cp = p[0] & 0x0F; }
  else if (p[0] >= 0xF0 && p[0] <= 0xF4) { len = 4; min = 0x10000; cp = p[0] & 0x07; }
  else return 0;
  if (n < len) return 0;
  for (size_t i = 1; i < len; i++) {
    if ((p[i] & 0xC0) != 0x80) return 0;
    cp = (cp << 6) | (p[i] & 0x3F);
  }
  if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return 0;
  return len;
}

/* Code point of a valid sequence (console_utf8_len said len). */
static unsigned utf8_cp(const unsigned char *p, size_t len) {
  if (len == 1) return p[0];
  unsigned cp = p[0] & (len == 2 ? 0x1F : len == 3 ? 0x0F : 0x07);
  for (size_t i = 1; i < len; i++) cp = (cp << 6) | (p[i] & 0x3F);
  return cp;
}

size_t console_sanitize(const char *in, size_t n, char *out, size_t cap) {
  const unsigned char *p = (const unsigned char *)in;
  size_t o = 0;
  if (cap == 0) return 0;
  for (size_t i = 0; i < n && o + 1 < cap;) {
    unsigned char c = p[i];
    if (c == '\t') {
      out[o++] = ' ';
      i++;
    } else if (c < 0x20 || c == 0x7f) {
      i++;
    } else if (c < 0x80) {
      out[o++] = (char)c;
      i++;
    } else {
      size_t ul = console_utf8_len(p + i, n - i);
      if (!ul) {
        out[o++] = '?';
        i++;
        continue;
      }
      unsigned cp = utf8_cp(p + i, ul);
      if (cp >= 0x80 && cp <= 0x9F) {   /* C1 controls */
        i += ul;
        continue;
      }
      if (o + ul >= cap) break;
      memcpy(out + o, p + i, ul);
      o += ul;
      i += ul;
    }
  }
  out[o] = '\0';
  return o;
}

/* Where a cut of s[0..len) must end so no UTF-8 character is split: len,
 * or the start of a trailing lead byte whose sequence runs past len.  The
 * Rust UI's utf8_cut is the same walk, so both hubs cut identically. */
static size_t utf8_cut(const char *s, size_t len) {
  const unsigned char *p = (const unsigned char *)s;
  if (len == 0) return 0;
  size_t i = len - 1;
  int back = 0;
  while (i > 0 && back < 3 && (p[i] & 0xC0) == 0x80) {
    i--;
    back++;
  }
  size_t need = p[i] >= 0xF0 && p[i] <= 0xF7 ? 4 : p[i] >= 0xE0 && p[i] < 0xF0 ? 3
              : p[i] >= 0xC0 && p[i] < 0xE0 ? 2 : 1;
  return i + need > len ? i : len;
}

/* snprintf for display text: a truncated result never ends in half a
 * character.  Returns what vsnprintf returns. */
static int usnprintf(char *buf, size_t cap, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
static int usnprintf(char *buf, size_t cap, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int r = vsnprintf(buf, cap, fmt, ap);
  va_end(ap);
  if (cap > 0 && r >= 0 && (size_t)r >= cap) buf[utf8_cut(buf, cap - 1)] = '\0';
  return r;
}

/* %.*s length for "at most max bytes of s" without splitting a character. */
static int uprec(const char *s, size_t max) {
  size_t n = strnlen(s, max);
  return (int)(n == max && s[n] ? utf8_cut(s, n) : n);
}

/* Terminal cells a code point takes: 0 for combining marks, 2 for the wide
 * East Asian ranges and emoji, else 1.  Mirrored in irchub.rs. */
static int cp_width(unsigned cp) {
  if (cp >= 0x0300 && cp <= 0x036F) return 0;
  if (cp == 0x200B || cp == 0x200C || cp == 0x200D || cp == 0xFE0F) return 0;
  if ((cp >= 0x1100 && cp <= 0x115F) || (cp >= 0x2E80 && cp <= 0xA4CF) ||
      (cp >= 0xAC00 && cp <= 0xD7A3) || (cp >= 0xF900 && cp <= 0xFAFF) ||
      (cp >= 0xFE30 && cp <= 0xFE4F) || (cp >= 0xFF00 && cp <= 0xFF60) ||
      (cp >= 0xFFE0 && cp <= 0xFFE6) || (cp >= 0x1F300 && cp <= 0x1F64F) ||
      (cp >= 0x1F900 && cp <= 0x1F9FF) || (cp >= 0x20000 && cp <= 0x3FFFD))
    return 2;
  return 1;
}

/* Decode the next character of an already-sanitized string. */
static size_t next_char(const char *s, size_t n, unsigned *cp, int *w) {
  size_t ul = console_utf8_len((const unsigned char *)s, n);
  if (!ul) ul = 1;
  *cp = utf8_cp((const unsigned char *)s, ul);
  *w = cp_width(*cp);
  return ul;
}

/* Case-insensitive (ASCII) substring test. */
static bool ci_contains(const char *hay, const char *needle) {
  size_t nl = strlen(needle);
  if (nl == 0) return true;
  for (; *hay; hay++)
    if (strncasecmp(hay, needle, nl) == 0) return true;
  return false;
}

static int str_width(const char *s);
int console_str_width(const char *s) { return str_width(s); }
int console_uprec(const char *s, size_t max) { return uprec(s, max); }
size_t console_next_char(const char *s, size_t n, unsigned *cp, int *w) {
  return next_char(s, n, cp, w);
}

static int str_width(const char *s) {
  int w = 0;
  size_t n = strlen(s);
  for (size_t i = 0; i < n;) {
    unsigned cp;
    int cw;
    i += next_char(s + i, n - i, &cp, &cw);
    w += cw;
  }
  return w;
}

/* End offset of the segment of `s` (from `start`) that fits in `width` cells
 * (hard wrap).  Always advances by at least one character. */
static size_t wrap_end(const char *s, size_t len, size_t start, int width) {
  int w = 0;
  size_t i = start;
  while (i < len) {
    unsigned cp;
    int cw;
    size_t ul = next_char(s + i, len - i, &cp, &cw);
    if (w + cw > width && i > start) break;
    w += cw;
    i += ul;
  }
  return i;
}

static int wrap_rows(const char *s, int width) {
  size_t len = strlen(s);
  if (len == 0 || width <= 0) return 1;
  int rows = 0;
  for (size_t i = 0; i < len; rows++) i = wrap_end(s, len, i, width);
  return rows;
}

/* ==========================================================================
 * Scrollback: a ring of sanitized lines, each with a colour class
 * ========================================================================== */

typedef struct {
  char   *text;
  uint8_t kind;
  uint8_t level;      /* log view: LOG_ERROR..LOG_DEBUG */
} sline_t;

typedef struct {
  sline_t  *v;
  int       cap;
  long long first;    /* sequence number of the oldest line kept */
  long long next;     /* sequence number the next line gets      */
} sback_t;

static void sb_init(sback_t *sb, int cap) {
  sb->v = calloc((size_t)cap, sizeof(sline_t));
  sb->cap = sb->v ? cap : 0;
  sb->first = sb->next = 0;
}

static void sb_free(sback_t *sb) {
  for (int i = 0; i < sb->cap; i++) free(sb->v[i].text);
  free(sb->v);
  sb->v = NULL;
  sb->cap = 0;
}

static void sb_add(sback_t *sb, const char *text, int kind, int level) {
  if (!sb->cap) return;
  sline_t *l = &sb->v[sb->next % sb->cap];
  free(l->text);
  l->text = strdup(text);
  l->kind = (uint8_t)kind;
  l->level = (uint8_t)level;
  sb->next++;
  if (sb->next - sb->first > sb->cap) sb->first = sb->next - sb->cap;
}

static const sline_t *sb_get(const sback_t *sb, long long seq) {
  if (seq < sb->first || seq >= sb->next || !sb->cap) return NULL;
  return &sb->v[seq % sb->cap];
}

static void sb_clear(sback_t *sb) {
  for (int i = 0; i < sb->cap; i++) {
    free(sb->v[i].text);
    sb->v[i].text = NULL;
  }
  sb->first = sb->next;
}

/* ==========================================================================
 * Key parser
 * ========================================================================== */
enum {
  K_NONE = 0, K_CHAR, K_ENTER, K_BS, K_TAB, K_UP, K_DOWN, K_LEFT, K_RIGHT,
  K_HOME, K_END, K_PGUP, K_PGDN, K_DEL, K_ESC, K_F, K_ALT, K_ALT_LEFT,
  K_ALT_RIGHT, K_CTRL, K_PASTE_BEGIN, K_PASTE_END
};

typedef struct {
  int      type;
  unsigned cp;   /* K_CHAR / K_ALT: the character; K_F: 1-12; K_CTRL: letter */
} ckey_t;

/* Decode one CSI / SS3 sequence (without the leading ESC).  The xterm,
 * PuTTY, linux-console, rxvt and tmux spellings of the same key all land on
 * the same ckey_t. */
static ckey_t decode_seq(const unsigned char *s, size_t n) {
  ckey_t k = {K_NONE, 0};
  if (n >= 2 && s[0] == 'O') {             /* SS3 */
    switch (s[1]) {
    case 'A': k.type = K_UP; break;
    case 'B': k.type = K_DOWN; break;
    case 'C': k.type = K_RIGHT; break;
    case 'D': k.type = K_LEFT; break;
    case 'H': k.type = K_HOME; break;
    case 'F': k.type = K_END; break;
    case 'P': k.type = K_F; k.cp = 1; break;
    case 'Q': k.type = K_F; k.cp = 2; break;
    case 'R': k.type = K_F; k.cp = 3; break;
    case 'S': k.type = K_F; k.cp = 4; break;
    case 'M': k.type = K_ENTER; break;
    }
    return k;
  }
  if (n < 2 || s[0] != '[') return k;
  if (n == 3 && s[1] == '[') {             /* linux console F1-F5: ESC [ [ A */
    if (s[2] >= 'A' && s[2] <= 'E') { k.type = K_F; k.cp = (unsigned)(s[2] - 'A' + 1); }
    return k;
  }
  unsigned char fin = s[n - 1];
  /* parameters: ESC [ p1 ; p2 fin */
  int p1 = 0, p2 = 0, which = 0;
  for (size_t i = 1; i + 1 < n; i++) {
    if (s[i] >= '0' && s[i] <= '9') {
      int *p = which ? &p2 : &p1;
      if (*p < 1000) *p = *p * 10 + (s[i] - '0');
    } else if (s[i] == ';') {
      which = 1;
    }
  }
  bool alt = (p2 == 3 || p2 == 4);          /* xterm modifier 3 = Alt */
  switch (fin) {
  case 'A': k.type = K_UP; break;
  case 'B': k.type = K_DOWN; break;
  case 'C': k.type = alt ? K_ALT_RIGHT : K_RIGHT; break;
  case 'D': k.type = alt ? K_ALT_LEFT : K_LEFT; break;
  case 'H': k.type = K_HOME; break;
  case 'F': k.type = K_END; break;
  case 'P': k.type = K_F; k.cp = 1; break;
  case 'Q': k.type = K_F; k.cp = 2; break;
  case 'R': k.type = K_F; k.cp = 3; break;
  case 'S': k.type = K_F; k.cp = 4; break;
  case '~':
    switch (p1) {
    case 1: case 7: k.type = K_HOME; break;
    case 4: case 8: k.type = K_END; break;
    case 3: k.type = K_DEL; break;
    case 5: k.type = K_PGUP; break;
    case 6: k.type = K_PGDN; break;
    case 11: case 12: case 13: case 14: case 15:
      k.type = K_F; k.cp = (unsigned)(p1 - 10); break;
    case 17: case 18: case 19: case 20: case 21:
      k.type = K_F; k.cp = (unsigned)(p1 - 11); break;
    case 23: case 24: k.type = K_F; k.cp = (unsigned)(p1 - 12); break;
    case 200: k.type = K_PASTE_BEGIN; break;
    case 201: k.type = K_PASTE_END; break;
    }
    break;
  }
  return k;
}

/* Length of a complete escape sequence at s (s[0] == ESC), 0 if it is not
 * complete yet, -1 if it can never be one (then ESC stands alone). */
static int seq_complete(const unsigned char *s, size_t n) {
  if (n < 2) return 0;
  if (s[1] == '[') {
    if (n >= 3 && s[2] == '[') return n >= 4 ? 4 : 0;   /* ESC [ [ A */
    for (size_t i = 2; i < n; i++) {
      if (s[i] >= 0x40 && s[i] <= 0x7e) return (int)i + 1;
      if (i > 16) return -1;
    }
    return 0;
  }
  if (s[1] == 'O') return n >= 3 ? 3 : 0;
  return 2;                                            /* Alt + key */
}

/* ==========================================================================
 * Session state
 * ========================================================================== */
enum { V_CONSOLE = 0, V_LOG, V_NET, V_UPG, V_STATS, V_COUNT };
static const char *const VIEW_NAME[V_COUNT] = {"console", "log", "network",
                                               "upgrades", "stats"};

/* y/N, type an exact word, or type a number that becomes the payload */
typedef enum { CF_NONE = 0, CF_YN, CF_TYPE, CF_PICK } confirm_t;

/* What a request in flight was for: replies come back in order. */
enum { RQ_USER = 0, RQ_PRE, RQ_VIEW_UPG, RQ_VIEW_STATS };

/* A read made before a confirmation so the question can name the object
 * (D2): what it reads, and what the question is built from. */
enum pre {
  PRE_NONE = 0, PRE_BOT_DEL, PRE_BOT_KICK, PRE_PEER_DEL, PRE_OPT, PRE_USER_DEL,
  PRE_USER_KEY, PRE_UPG_START
};

typedef struct {
  int  kind;
  int  seq;              /* the command number */
  char words[32];        /* "bot list" */
  char audit[320];       /* what the audit line says was asked */
  int  audit_level;
  int  mode;             /* FMT_MODE_* */
} pending_rq_t;

#define MAX_PENDING_RQ 16
#define MAX_QUEUED_LINES 256
#define MAX_AUDIT 16

typedef struct {
  char name[64];
  int  peers_up, peers_total, bots_on, bots_total;
  char upg[24];
  bool frozen, rollup, split;
  int  loglevel, consolelevel;
  bool have;
} status_t;

/* The command a pre-read is for, and what its question needs. */
typedef struct {
  int           pre;
  uint8_t       op;
  unsigned char payload[1024];
  size_t        len;
  char          arg[256];      /* the object: uuid, #, name, flags        */
  char          extra[4][256]; /* upgrade start: hub=, nodes=, botbase=, hubbase= */
  pending_rq_t  rq;
} pend_cmd_t;

/* One entry of the full-screen console view: a finished line, or a reply
 * kept as it came so it can be laid out again at a new width (D5). */
typedef struct {
  char   *text;     /* a line, or NULL for a reply                         */
  uint8_t kind;
  char   *reply;    /* the reply's records                                 */
  char    words[32];
  int     mode;
} centry_t;

struct console_ui {
  bool line_mode, ascii;
  int  cols, rows;
  char admin[CONSOLE_NAME_MAX], ip[64], hubname[64];
  cbuf_t term, core;

  /* input line */
  char in[CONSOLE_INPUT_MAX];
  int  in_len, in_cur;          /* bytes */
  int  in_scroll;               /* first visible cell */
  char *hist[CONSOLE_HISTORY];
  int  hist_n, hist_pos;
  char hist_stash[CONSOLE_INPUT_MAX];

  /* key parser */
  unsigned char esc[32];
  int  esc_len;
  long long esc_ms;
  bool pasting;
  unsigned char utf8[4];
  int  utf8_len;
  bool last_cr;

  /* commands */
  int  seq;
  int  ncmds;                   /* commands run, for the goodbye line */
  bool user_busy;               /* a user command is in flight */
  pending_rq_t rq[MAX_PENDING_RQ];
  int  rq_n;
  char *queued[MAX_QUEUED_LINES];
  int  queued_n;
  confirm_t confirming;
  int  confirm_seq;
  char confirm_want[128];
  int  confirm_pick_max;
  uint8_t confirm_op;
  unsigned char confirm_payload[1024];
  size_t confirm_len;
  pending_rq_t confirm_rq;
  pend_cmd_t pend;
  /* line mode: events held back while a command's output is pending */
  cbuf_t held;
  unsigned long dropped;

  /* display settings (docs/console.md §2 display) */
  bool raw;                     /* display format raw */
  int  width_set;               /* line mode: 0 default, -1 auto, else n */
  bool events_on;               /* line mode: human event lines */
  bool greeted;
  long long now_ms, start_ms;

  /* data from the core */
  status_t st;
  char *tree;                   /* rows, '\n'-separated */
  char *upg_text, *stats_text;  /* view 4 / 5 replies */
  long long upg_at, stats_at;
  char last_upg[256];
  bool log_on;                  /* line mode: "log on" */
  int  log_sub_level;

  /* full screen */
  int  view;
  sback_t sb[V_COUNT];          /* V_CONSOLE and V_LOG are used */
  centry_t *ent;                /* V_CONSOLE entries, a ring */
  long long ent_first, ent_next;
  int  render_w;                /* width the console view was laid out at */
  long long anchor[V_COUNT];    /* bottom line shown; -1 = live */
  bool act[V_COUNT];
  bool pane_user_off;           /* F3 on a wide terminal */
  bool overlay;                 /* F3 on a narrow terminal */
  int  log_show;                /* LOG_ERROR..LOG_DEBUG */
  char filter[128];
  bool paused;
  long long paused_next;        /* log lines at/after this are held */
  char search[128];
  bool searching;               /* the input line is a search prompt */
  int  net_sel;
  char **prev_rows;
  int  prev_n;
  bool dirty, full_redraw;
  long long resize_ms, last_draw_ms, last_clock_ms;
  long long last_input_ms;
  bool started;

  char audit_msg[MAX_AUDIT][384];
  int  audit_lvl[MAX_AUDIT];
  int  audit_n;

  bool closing;
  char close_why[64];
};

/* ==========================================================================
 * Command table (docs/console.md §2): <noun> <verb> [args] (D15)
 * ========================================================================== */
enum bk {
  B_NONE, B_ARG, B_PIPE, B_PEER_ADD, B_PEER_DEL, B_PEER_SET, B_CHAN_ADD, B_CHAN_SET,
  B_CHAN_OP, B_OPT_SET, B_LOG_SET, B_PURGE, B_HUB_SET, B_ACL, B_USER_LIST,
  B_USER_ADD, B_USER_SET, B_USER_MASK, B_UPG_RELEASES, B_UPG_START, B_FIXED, B_LOCAL
};

typedef struct {
  const char *cmd, *sub;
  uint8_t     op;
  enum bk     build;
  int         nargs, optargs;
  confirm_t   confirm;
  int         pre;
  const char *fixed;
  const char *usage;
  const char *help;
  const char *args;     /* help <group>: a second line for the arguments */
} cmd_def_t;

static const cmd_def_t CMDS[] = {
  {"help", NULL, 0, B_LOCAL, 0, 2, CF_NONE, 0, NULL, "help [group [command]]", "the command groups, one group's commands, or one command in full (? does the same)", NULL},
  {"quit", NULL, 0, B_LOCAL, 0, 0, CF_NONE, 0, NULL, "quit", "close this console", NULL},
  {"bot", "list", CMD_ADMIN_LIST_FULL, B_NONE, 0, 0, CF_NONE, 0, NULL, "bot list", "every registered bot: state, hub, version, last seen", NULL},
  {"bot", "show", CMD_ADMIN_LIST_FULL, B_ARG, 1, 0, CF_NONE, 0, NULL, "bot show <uuid|nick>", "one bot in detail", NULL},
  {"bot", "summary", CMD_ADMIN_LIST_SUMMARY, B_NONE, 0, 0, CF_NONE, 0, NULL, "bot summary", "every bot's nick and uuid", NULL},
  {"bot", "pending", CMD_ADMIN_GET_PENDING, B_NONE, 0, 0, CF_NONE, 0, NULL, "bot pending", "bots that tried to connect but are not authorized", NULL},
  {"bot", "approve", CMD_ADMIN_APPROVE, B_ARG, 1, 0, CF_NONE, 0, NULL, "bot approve <#|uuid>", "approve a pending bot; # is the number from bot pending", NULL},
  {"bot", "authorize", CMD_ADMIN_ADD, B_ARG, 1, 0, CF_NONE, 0, NULL, "bot authorize <uuid>", "authorize a uuid before the bot first connects", NULL},
  {"bot", "add", CMD_ADMIN_CREATE_BOT, B_PIPE, 3, 0, CF_NONE, 0, NULL, "bot add <nick> <uuid> <key>", "register a bot from the identity its -setup printed", "key: the 88-char base64 public key"},
  {"bot", "del", CMD_ADMIN_DEL, B_ARG, 1, 0, CF_YN, PRE_BOT_DEL, NULL, "bot del <uuid>", "delete a bot everywhere (asks y/N; disconnects it)", NULL},
  {"bot", "kick", CMD_ADMIN_DISCONNECT_BOT, B_ARG, 1, 0, CF_YN, PRE_BOT_KICK, NULL, "bot kick <uuid>", "drop its connection to this hub (asks y/N; it reconnects)", NULL},
  {"bot", "rekey", CMD_ADMIN_REKEY_BOT, B_ARG, 1, 0, CF_NONE, 0, NULL, "bot rekey <uuid>", "how to rekey a bot (only the bot can)", NULL},
  {"peer", "list", CMD_ADMIN_LIST_PEERS, B_NONE, 0, 0, CF_NONE, 0, NULL, "peer list", "peer hubs, the mesh links and their health", NULL},
  {"peer", "show", CMD_ADMIN_LIST_PEERS, B_ARG, 1, 0, CF_NONE, 0, NULL, "peer show <#|uuid|name>", "one peer hub in detail", NULL},
  {"peer", "add", CMD_ADMIN_ADD_PEER, B_PEER_ADD, 5, 0, CF_NONE, 0, NULL, "peer add <ip> <port> <uuid> <name|-> <key>", "add a peer hub", "key: the 88-char key from that hub's hub show"},
  {"peer", "del", CMD_ADMIN_DEL_PEER, B_PEER_DEL, 0, 1, CF_TYPE, PRE_PEER_DEL, NULL, "peer del [#]", "remove a peer hub (types its number to confirm)", NULL},
  {"peer", "set", CMD_ADMIN_SET_PEER_PUBKEY, B_PEER_SET, 3, 0, CF_NONE, 0, NULL, "peer set <#|uuid|name> key <key>", "replace a peer's key (the link comes back with it)", NULL},
  {"peer", "sync", CMD_ADMIN_SYNC_MESH, B_NONE, 0, 0, CF_NONE, 0, NULL, "peer sync", "send a full sync to every peer", NULL},
  {"network", "tree", CMD_CONSOLE, B_FIXED, 0, 0, CF_NONE, 0, "get|tree", "network tree", "every hub and bot as a tree", NULL},
  {"network", "status", CMD_CONSOLE, B_FIXED, 0, 0, CF_NONE, 0, "get|status", "network status", "the mesh-wide status (what the status bar shows)", NULL},
  {"hub", "show", CMD_ADMIN_GET_PUBKEY, B_NONE, 0, 0, CF_NONE, 0, NULL, "hub show", "this hub: identity, key, listener, counts", NULL},
  {"hub", "set", 0, B_HUB_SET, 0, 2, CF_NONE, 0, NULL, "hub set <setting> <value>", "name, bindip, port, pubkey or autopurge (alone: the table)", NULL},
  {"hub", "stats", CMD_ADMIN_STATS, B_NONE, 0, 0, CF_NONE, 0, NULL, "hub stats", "traffic counters since the hub started", NULL},
  {"hub", "rekey", CMD_ADMIN_REGEN_KEYS, B_NONE, 0, 0, CF_TYPE, 0, NULL, "hub rekey", "new hub keypair; every peer and bot must re-learn it", NULL},
  {"hub", "purge", CMD_ADMIN_PURGE_TOMBSTONES, B_PURGE, 1, 0, CF_YN, 0, NULL, "hub purge <now|days>", "purge tombstones now, or those older than <days>", NULL},
  {"log", "show", CMD_CONSOLE, B_FIXED, 0, 0, CF_NONE, 0, "get|log", "log show", "log levels, sizes and this session's log", NULL},
  {"log", "set", 0, B_LOG_SET, 2, 0, CF_NONE, 0, NULL, "log set file|console|size <value>", "the file or console ring level, or the file size limit", "level: none error warning info debug or 0-4 · size: <MB>, <n>k or <n>b, at most 1024 MB"},
  {"log", "on", 0, B_LOCAL, 0, 1, CF_NONE, 0, NULL, "log on [level]", "line mode: stream hub log lines", NULL},
  {"log", "off", 0, B_LOCAL, 0, 0, CF_NONE, 0, NULL, "log off", "line mode: stop the log lines", NULL},
  {"log", "filter", 0, B_LOCAL, 1, 64, CF_NONE, 0, NULL, "log filter <text|clear>", "full screen: log view lines containing <text>", NULL},
  {"acl", "list", CMD_ADMIN_LIST_ALLOWLIST, B_NONE, 0, 0, CF_NONE, 0, NULL, "acl list", "the allow and deny lists", NULL},
  {"acl", "add", 0, B_ACL, 2, 0, CF_NONE, 0, NULL, "acl add allow|deny <ip[/n]>", "add an address or network", NULL},
  {"acl", "del", 0, B_ACL, 2, 0, CF_YN, 0, NULL, "acl del allow|deny <ip[/n]>", "remove an address or network (asks y/N)", NULL},
  {"option", "list", CMD_ADMIN_GET_OPT_FLAGS, B_NONE, 0, 0, CF_NONE, 0, NULL, "option list", "the network option flags", NULL},
  {"option", "set", CMD_ADMIN_SET_OPT_FLAGS, B_OPT_SET, 1, 0, CF_YN, PRE_OPT, NULL, "option set <flags|->", "set the network option flags (- clears)", NULL},
  {"user", "list", 0, B_USER_LIST, 0, 1, CF_NONE, 0, NULL, "user list [admin|oper]", "every user (or one role): key, last seen, masks", NULL},
  {"user", "show", CMD_ADMIN_MATCH, B_ARG, 1, 0, CF_NONE, 0, NULL, "user show <name|*>", "one user (or all) with masks and their last use", NULL},
  {"user", "add", 0, B_USER_ADD, 4, 0, CF_NONE, 0, NULL, "user add admin|oper <name> <key> <mask>", "add an admin or an oper", "key: their 88-char public key · mask: nick!user@host"},
  {"user", "del", CMD_ADMIN_DEL_ADMIN, B_ARG, 1, 0, CF_YN, PRE_USER_DEL, NULL, "user del <name>", "remove a user and their masks", NULL},
  {"user", "set", CMD_ADMIN_SET_USERKEY, B_USER_SET, 3, 0, CF_YN, PRE_USER_KEY, NULL, "user set <name> key <key>", "replace a user's key (asks y/N)", NULL},
  {"user", "mask", 0, B_USER_MASK, 3, 0, CF_NONE, 0, NULL, "user mask add|del <name> <mask>", "add or remove a usermask (del asks y/N)", NULL},
  {"channel", "list", CMD_ADMIN_LIST_CHANNELS, B_NONE, 0, 0, CF_NONE, 0, NULL, "channel list", "every managed channel with its settings", NULL},
  {"channel", "show", CMD_ADMIN_LIST_CHANNELS, B_ARG, 1, 0, CF_NONE, 0, NULL, "channel show <#chan>", "one channel in detail", NULL},
  {"channel", "add", CMD_ADMIN_ADD_CHANNEL, B_CHAN_ADD, 1, 1, CF_NONE, 0, NULL, "channel add <#chan> [key]", "add (or re-add) a channel", NULL},
  {"channel", "del", CMD_ADMIN_DEL_CHANNEL, B_ARG, 1, 0, CF_YN, 0, NULL, "channel del <#chan>", "remove it from every bot (asks y/N)", NULL},
  {"channel", "set", CMD_ADMIN_ADD_CHANNEL, B_CHAN_SET, 3, 0, CF_NONE, 0, NULL, "channel set <#chan> <setting> <value|->", "change one setting (key today; - clears)", NULL},
  {"channel", "op", CMD_ADMIN_OP_USER, B_CHAN_OP, 2, 0, CF_NONE, 0, NULL, "channel op <#chan> <nick>", "have one opped bot op a user", NULL},
  {"channel", "invite", CMD_ADMIN_INVITE_USER, B_CHAN_OP, 2, 0, CF_NONE, 0, NULL, "channel invite <#chan> <nick>", "have one opped bot invite a user", NULL},
  {"upgrade", "status", CMD_ADMIN_UPGRADE_STATUS, B_FIXED, 0, 0, CF_NONE, 0, "", "upgrade status", "the upgrade run on this hub", NULL},
  {"upgrade", "releases", CMD_ADMIN_UPGRADE_STATUS, B_UPG_RELEASES, 0, 2, CF_NONE, 0, NULL, "upgrade releases [bot=<base>] [hub=<base>]", "releases both products offer, and the nodes", NULL},
  {"upgrade", "start", CMD_ADMIN_UPGRADE_NET, B_UPG_START, 1, 4, CF_TYPE, PRE_UPG_START, NULL, "upgrade start <botver> [hub=<ver>] [nodes=<a,b=c>] [botbase=<url>] [hubbase=<url>]", "start a rolling network upgrade", NULL},
  {"upgrade", "abort", CMD_ADMIN_UPGRADE_STATUS, B_FIXED, 0, 0, CF_YN, 0, "abort", "upgrade abort", "stop the run and roll back", NULL},
  {"upgrade", "forget", CMD_ADMIN_UPGRADE_STATUS, B_FIXED, 0, 0, CF_YN, 0, "forget", "upgrade forget", "drop the roll-up plan on every hub", NULL},
  {"display", "show", 0, B_LOCAL, 0, 0, CF_NONE, 0, NULL, "display show", "this session's display settings", NULL},
  {"display", "view", 0, B_LOCAL, 1, 0, CF_NONE, 0, NULL, "display view <1-5>", "full screen: console, log, network, upgrades, stats", NULL},
  {"display", "pane", 0, B_LOCAL, 0, 0, CF_NONE, 0, NULL, "display pane", "full screen: show or hide the tree pane (F3)", NULL},
  {"display", "ascii", 0, B_LOCAL, 0, 0, CF_NONE, 0, NULL, "display ascii", "plain ASCII glyphs for this session (again: Unicode)", NULL},
  {"display", "format", 0, B_LOCAL, 1, 0, CF_NONE, 0, NULL, "display format pretty|raw", "laid-out output, or the records as the hub sends them", NULL},
  {"display", "width", 0, B_LOCAL, 1, 0, CF_NONE, 0, NULL, "display width <60-250|auto>", "line mode: the output width", NULL},
  {"display", "events", 0, B_LOCAL, 1, 0, CF_NONE, 0, NULL, "display events on|off", "line mode: a line for each peer, bot and upgrade change", NULL},
  {"display", "clear", 0, B_LOCAL, 0, 0, CF_NONE, 0, NULL, "display clear", "full screen: clear the current view", NULL},
};
#define NCMDS ((int)(sizeof(CMDS) / sizeof(CMDS[0])))

/* The root nouns, in help order, with what each groups. */
static const struct {
  const char *name, *what;
} GROUPS[] = {
  {"bot", "registered bots"},      {"peer", "peer hubs"},
  {"network", "the whole mesh"},   {"hub", "this hub"},
  {"log", "the hub log"},          {"acl", "IP allow / deny lists"},
  {"option", "network option flags"}, {"user", "admins and opers"},
  {"channel", "managed channels"}, {"upgrade", "rolling upgrades"},
  {"display", "this session's screen"},
};
#define NGROUPS ((int)(sizeof(GROUPS) / sizeof(GROUPS[0])))

/* help <group> <command> (§2.2): each argument, then examples that run as
 * typed.  args: "name\ttext" lines; examples: one per line. */
#define EX_UUID "00010203-0405-4607-8809-0a0b0c0d0e0f"
#define EX_KEY  "O7Eu2jwpjbXeJVl/VNkk8uF+eKJq2JU+2CGO5oLwu76QIeLzAJ0VLJEb8fJexoOpAnFBZnZ6+9jlvQ+wEk7Lig=="
static const struct {
  const char *cmd, *sub, *args, *examples;
} CMD_HELP[] = {
  {"help", NULL,
   "group\tone of: bot peer network hub log acl option user channel upgrade display\n"
   "command\tone of that group's commands: its arguments and an example\n"
   "?\ttyped in place of help it does the same",
   "help\nhelp bot\nhelp bot add\n? upgrade start"},
  {"quit", NULL, NULL, "quit"},
  {"bot", "list", NULL, "bot list"},
  {"bot", "show", "uuid|nick\tthe bot's uuid or its current nick (Tab completes both)",
   "bot show alpha\nbot show " EX_UUID},
  {"bot", "summary", NULL, "bot summary"},
  {"bot", "pending", NULL, "bot pending"},
  {"bot", "approve",
   "#|uuid\tthe number bot pending shows in its # column, or the pending bot's uuid",
   "bot approve 1\nbot approve " EX_UUID},
  {"bot", "authorize", "uuid\tthe uuid of a bot that has not connected yet",
   "bot authorize " EX_UUID},
  {"bot", "add",
   "nick\tthe bot's IRC nick\n"
   "uuid\tthe uuid the bot's -setup printed\n"
   "key\tthe 88-character base64 public key the bot's -setup printed",
   "bot add alpha " EX_UUID " " EX_KEY},
  {"bot", "del", "uuid\tthe bot's uuid (Tab completes); asks y/N, then disconnects it",
   "bot del " EX_UUID},
  {"bot", "kick", "uuid\ta connected bot's uuid (Tab completes); asks y/N; it reconnects",
   "bot kick " EX_UUID},
  {"bot", "rekey", "uuid\tthe bot's uuid; prints how to rekey it on its host",
   "bot rekey " EX_UUID},
  {"peer", "list", NULL, "peer list"},
  {"peer", "show", "#|uuid|name\tthe number peer list shows, the hub's uuid, or its name",
   "peer show 1\npeer show east"},
  {"peer", "add",
   "ip\tthe peer hub's address (no ':', so an IPv4 address or a host name)\n"
   "port\tits listening port, 1-65535\n"
   "uuid\tits uuid, from hub show on that hub\n"
   "name|-\ta name for it, or - to learn its name from the peer\n"
   "key\tthe 88-character public key from hub show on that hub",
   "peer add 203.0.113.7 6697 " EX_UUID " east " EX_KEY "\n"
   "peer add 203.0.113.7 6697 " EX_UUID " - " EX_KEY},
  {"peer", "del", "#\tthe number peer list shows; alone it lists the peers to pick from; "
   "you type the number again to confirm",
   "peer del\npeer del 2"},
  {"peer", "set",
   "#|uuid|name\tthe peer: its number in peer list, its uuid, or its name\n"
   "key\tthe setting; key is the only one\n"
   "key\tthe new 88-character public key from hub show on that hub",
   "peer set east key " EX_KEY},
  {"peer", "sync", NULL, "peer sync"},
  {"network", "tree", NULL, "network tree"},
  {"network", "status", NULL, "network status"},
  {"hub", "show", NULL, "hub show"},
  {"hub", "set",
   "setting\tname, bindip, port, pubkey or autopurge; alone it shows them all\n"
   "value\tname: this hub's name · bindip: the address it listens on · port: 1-65535 · "
   "pubkey: the key its private key derives (a new key is hub rekey) · "
   "autopurge: days to keep tombstones, 0 = off",
   "hub set\nhub set name west\nhub set port 6697\nhub set autopurge 30"},
  {"hub", "stats", NULL, "hub stats"},
  {"hub", "rekey", "(confirm)\tyou type this hub's name to go ahead; every peer and bot "
   "must then learn the new key",
   "hub rekey"},
  {"hub", "purge", "now|days\tnow purges every tombstone; a number purges those older "
   "than that many days (asks y/N)",
   "hub purge now\nhub purge 30"},
  {"log", "show", NULL, "log show"},
  {"log", "set",
   "file|console|size\twhich: the log file's level, the console ring's level, or the file "
   "size limit\n"
   "value\ta level (none error warning info debug, or 0-4) for file and console; for size "
   "<MB>, <n>k or <n>b, at most 1024 MB",
   "log set file info\nlog set console debug\nlog set size 50\nlog set size 512k"},
  {"log", "on", "level\tnone error warning info debug, or 0-4 (default info)",
   "log on\nlog on debug"},
  {"log", "off", NULL, "log off"},
  {"log", "filter", "text|clear\tthe rest of the line is the text a log view line must "
   "contain (any case); clear drops the filter",
   "log filter UPGRADE\nlog filter peer east\nlog filter clear"},
  {"acl", "list", NULL, "acl list"},
  {"acl", "add",
   "allow|deny\twhich list\n"
   "ip[/n]\tan IPv4 or IPv6 address, or a network as address/prefix",
   "acl add allow 203.0.113.0/24\nacl add deny 198.51.100.9"},
  {"acl", "del",
   "allow|deny\twhich list\n"
   "ip[/n]\tthe entry exactly as acl list shows it (asks y/N)",
   "acl del deny 198.51.100.9"},
  {"option", "list", NULL, "option list"},
  {"option", "set", "flags|-\tthe whole new set of flag letters (it replaces the old "
   "set; option list explains each); - clears them all (asks y/N)",
   "option set h\noption set -"},
  {"user", "list", "admin|oper\tonly that role (default both)",
   "user list\nuser list oper"},
  {"user", "show", "name|*\ta user's name, or * for every user", "user show robert\nuser show *"},
  {"user", "add",
   "admin|oper\tthe role\n"
   "name\tthe user's name\n"
   "key\ttheir 88-character public key (keygen's <stamp>_<name>.public.b64)\n"
   "mask\ta first usermask, nick!user@host (* and ? match)",
   "user add oper alice " EX_KEY " alice!*@*.example.net"},
  {"user", "del", "name\tthe user, either role; their masks go too (an admin: type the "
   "name to confirm; an oper: y/N)", "user del alice"},
  {"user", "set",
   "name\tthe user\n"
   "key\tthe setting; key is the only one\n"
   "key\ttheir new 88-character public key (asks y/N)",
   "user set alice key " EX_KEY},
  {"user", "mask",
   "add|del\tadd a mask, or remove one (del asks y/N)\n"
   "name\tthe user\n"
   "mask\tnick!user@host (* and ? match)",
   "user mask add alice alice!*@203.0.113.*\nuser mask del alice alice!*@*.example.net"},
  {"channel", "list", NULL, "channel list"},
  {"channel", "show", "#chan\tthe channel's name", "channel show #ops"},
  {"channel", "add", "#chan\tthe channel's name\nkey\tits channel key, if it has one",
   "channel add #ops\nchannel add #ops s3cret"},
  {"channel", "del", "#chan\tthe channel; every bot parts it (asks y/N)", "channel del #ops"},
  {"channel", "set",
   "#chan\tthe channel\n"
   "setting\tthe setting's name; key today\n"
   "value|-\tthe new value (at most 128 bytes), or - to clear it",
   "channel set #ops key s3cret\nchannel set #ops key -"},
  {"channel", "op", "#chan\tthe channel\nnick\tthe user's current nick on IRC",
   "channel op #ops alice"},
  {"channel", "invite", "#chan\tthe channel\nnick\tthe user's current nick on IRC",
   "channel invite #ops alice"},
  {"upgrade", "status", NULL, "upgrade status"},
  {"upgrade", "releases",
   "bot=<base>\ta different release site for the bot builds (a URL)\n"
   "hub=<base>\ta different release site for the hub builds (a URL)",
   "upgrade releases\nupgrade releases bot=https://example.net/ircbot"},
  {"upgrade", "start",
   "botver\tthe bot version to move to, as upgrade releases lists it\n"
   "hub=<ver>\talso move the hubs to this version (- = leave them)\n"
   "nodes=<sel>\tonly these nodes: names or uuids, comma-separated; name=c or name=rs "
   "also switches that node's build (default: the whole network)\n"
   "botbase=<url>\ta different release site for the bot builds\n"
   "hubbase=<url>\ta different release site for the hub builds\n"
   "(confirm)\tit shows the plan, then you type the bot version to start",
   "upgrade start 2.4.6\nupgrade start 2.4.6 hub=2.4.4\nupgrade start 2.4.6 nodes=alpha,beta=rs"},
  {"upgrade", "abort", NULL, "upgrade abort"},
  {"upgrade", "forget", NULL, "upgrade forget"},
  {"display", "show", NULL, "display show"},
  {"display", "view", "1-5\t1 console, 2 log, 3 network, 4 upgrades, 5 stats (Alt+1..5)",
   "display view 2"},
  {"display", "pane", NULL, "display pane"},
  {"display", "ascii", NULL, "display ascii"},
  {"display", "format", "pretty|raw\tpretty lays replies out; raw shows the records as the "
   "hub sent them",
   "display format raw\ndisplay format pretty"},
  {"display", "width", "60-250|auto\tthe columns to lay output out for; auto follows the "
   "terminal",
   "display width 100\ndisplay width auto"},
  {"display", "events", "on|off\ta line for each peer, bot and upgrade change",
   "display events on"},
  {"display", "clear", NULL, "display clear"},
};
#define NCMDHELP ((int)(sizeof(CMD_HELP) / sizeof(CMD_HELP[0])))

static const char *const LEVEL_WORD[] = {"none", "error", "warning", "info", "debug"};

/* ==========================================================================
 * Output helpers
 * ========================================================================== */
static void audit(console_ui_t *ui, int level, const char *fmt, ...) {
  if (ui->audit_n >= MAX_AUDIT) return;
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(ui->audit_msg[ui->audit_n], sizeof(ui->audit_msg[0]), fmt, ap);
  va_end(ap);
  ui->audit_lvl[ui->audit_n++] = level;
}

bool ui_take_audit(console_ui_t *ui, int *level, char *buf, size_t cap) {
  if (ui->audit_n == 0) return false;
  *level = ui->audit_lvl[0];
  usnprintf(buf, cap, "%s", ui->audit_msg[0]);
  ui->audit_n--;
  memmove(ui->audit_msg[0], ui->audit_msg[1], sizeof(ui->audit_msg[0]) * (size_t)ui->audit_n);
  memmove(ui->audit_lvl, ui->audit_lvl + 1, sizeof(int) * (size_t)ui->audit_n);
  return true;
}

static void core_frame(console_ui_t *ui, uint8_t op, const void *p, size_t n) {
  uint32_t nl = htonl((uint32_t)(1 + n));
  cbuf_add(&ui->core, &nl, 4);
  cbuf_add(&ui->core, &op, 1);
  cbuf_add(&ui->core, p, n);
}

static void subscribe(console_ui_t *ui) {
  char s[64];
  if (ui->line_mode) {
    if (ui->log_on) usnprintf(s, sizeof(s), "sub|status,tree,upg,log=%d", ui->log_sub_level);
    else usnprintf(s, sizeof(s), "sub|status,tree,upg");
  } else {
    usnprintf(s, sizeof(s), "sub|status,tree,upg,log=%d,logreplay", LOG_DEBUG);
  }
  core_frame(ui, CMD_CONSOLE, s, strlen(s));
}

/* Line mode: one line of output (already sanitized), ending in CRLF. */
static void lm_line(console_ui_t *ui, const char *s) {
  char *a = ui->ascii ? fmt_ascii(s) : NULL;
  cbuf_adds(&ui->term, a ? a : s);
  free(a);
  cbuf_add(&ui->term, "\r\n", 2);
}

/* Line mode: the prompt and whatever is typed so far. */
static void lm_prompt(console_ui_t *ui) {
  cbuf_adds(&ui->term, ui->confirming ? "? " : "> ");
  cbuf_add(&ui->term, ui->in, (size_t)ui->in_len);
}

/* Line mode: something arrives while the admin is at the prompt.  A CR puts
 * it over the prompt (a reader takes the text after a line's last CR), then
 * the prompt and the partial input are printed again.  While a command is in
 * flight it is held until that command's marker. */
static void lm_async(console_ui_t *ui, const char *text) {
  if (ui->term.len + ui->held.len > CONSOLE_TERM_OUTQ_MAX) {
    ui->dropped++;
    return;
  }
  bool hold = ui->user_busy || ui->confirming;
  cbuf_t *b = hold ? &ui->held : &ui->term;
  if (!hold) cbuf_add(b, "\r", 1);
  char *a = ui->ascii ? fmt_ascii(text) : NULL;
  if (a) text = a;
  for (const char *p = text; *p;) {           /* one CRLF line per '\n' */
    const char *nl = strchr(p, '\n');
    size_t n = nl ? (size_t)(nl - p) : strlen(p);
    cbuf_add(b, p, n);
    cbuf_add(b, "\r\n", 2);
    p = nl ? nl + 1 : p + n;
  }
  free(a);
  if (!hold) lm_prompt(ui);
}

/* The width output is laid out for (§1.4). */
static int main_width(const console_ui_t *ui);
static int out_width(const console_ui_t *ui) {
  if (!ui->line_mode) return main_width(ui);
  if (ui->width_set > 0) return ui->width_set;
  if (ui->width_set < 0) {
    int w = ui->cols;
    return w < CONSOLE_MIN_COLS ? CONSOLE_MIN_COLS : w > CONSOLE_WIDTH_MAX ? CONSOLE_WIDTH_MAX : w;
  }
  return CONSOLE_LINE_WIDTH;
}

static long long now_s(void) { return (long long)time(NULL); }

/* "HH:MM:SSZ" now (UTC, D3) */
static void clock_utc(char *out, size_t cap, bool secs) {
  long long t = now_s();
  long long s = ((t % 86400) + 86400) % 86400;
  if (secs) usnprintf(out, cap, "%02lld:%02lld:%02lldZ", s / 3600, s / 60 % 60, s % 60);
  else usnprintf(out, cap, "%02lld:%02lldZ", s / 3600, s / 60 % 60);
}

static void session_log_phrase(const console_ui_t *ui, char *out, size_t cap);

static void ctx_init(const console_ui_t *ui, fmt_ctx_t *c, int mode, char *slog, size_t slog_cap) {
  memset(c, 0, sizeof(*c));
  c->width = out_width(ui);
  /* full screen keeps its lines in Unicode and shows them through
   * fmt_ascii, so display ascii can change every line both ways */
  c->ascii = ui->ascii && ui->line_mode;
  c->now = now_s();
  c->admin = ui->admin;
  c->ip = ui->ip;
  c->hubname = ui->hubname;
  c->mode = mode;
  session_log_phrase(ui, slog, slog_cap);
  c->session_log = slog;
}

/* Full screen: add a line to a view's scrollback. */
static void fs_add(console_ui_t *ui, int view, const char *text, int kind, int level) {
  /* the console view is rebuilt on a glyph change (relayout), so it holds
   * the shown form; other views are filtered as drawn (rb_text) */
  char *a = ui->ascii && view == V_CONSOLE ? fmt_ascii(text) : NULL;
  sb_add(&ui->sb[view], a ? a : text, kind, level);
  free(a);
  if (view != ui->view && (view != V_LOG || level <= LOG_WARNING)) ui->act[view] = true;
  ui->dirty = true;
}

static void ent_push(console_ui_t *ui, const char *text, int kind, const char *reply,
                     const char *words, int mode) {
  if (!ui->ent) return;
  centry_t *e = &ui->ent[ui->ent_next % CONSOLE_SCROLLBACK];
  free(e->text);
  free(e->reply);
  memset(e, 0, sizeof(*e));
  e->text = text ? strdup(text) : NULL;
  e->reply = reply ? strdup(reply) : NULL;
  e->kind = (uint8_t)kind;
  if (words) usnprintf(e->words, sizeof(e->words), "%s", words);
  e->mode = mode;
  ui->ent_next++;
  if (ui->ent_next - ui->ent_first > CONSOLE_SCROLLBACK)
    ui->ent_first = ui->ent_next - CONSOLE_SCROLLBACK;
}

/* Full screen: a finished console-view line (kept for a re-layout). */
static void fs_line(console_ui_t *ui, const char *text, int kind) {
  fs_add(ui, V_CONSOLE, text, kind, LOG_INFO);
  ent_push(ui, text, kind, NULL, NULL, 0);
}

static void fs_timestamped(console_ui_t *ui, int view, const char *text, int kind) {
  char buf[CONSOLE_INPUT_MAX + 32], t[16];
  clock_utc(t, sizeof(t), true);
  usnprintf(buf, sizeof(buf), "%s %s", t, text);
  if (view == V_CONSOLE) fs_line(ui, buf, kind);
  else fs_add(ui, view, buf, kind, LOG_INFO);
}

/* Lines into the current output: line mode prints, the full screen keeps. */
static void emit_flines(console_ui_t *ui, flines_t *f) {
  if (!ui->raw) fmt_wrap(f, out_width(ui));
  for (int i = 0; i < f->n; i++) {
    if (ui->line_mode) lm_line(ui, f->v[i].text);
    else fs_line(ui, f->v[i].text, f->v[i].role);
  }
}

/* A console-side note (help, a refused command) in either mode. */
static void note(console_ui_t *ui, const char *text, int kind) {
  if (ui->line_mode) lm_line(ui, text);
  else fs_timestamped(ui, V_CONSOLE, text, kind);
}

/* Render a reply into lines (pretty) for the current width. */
static void render_reply(const console_ui_t *ui, const char *text, size_t len,
                         const char *words, int mode, flines_t *out) {
  creply_t rep;
  creply_parse(text, len, &rep);
  fmt_ctx_t c;
  char slog[128];
  ctx_init(ui, &c, mode, slog, sizeof(slog));
  c.ascii = ui->ascii;              /* re-rendered by relayout() on a change */
  fmt_reply(&c, &rep, words, out);
  creply_free(&rep);
}

/* Raw format: the records as the hub sent them, sanitized, one per line. */
static void raw_lines(const char *text, size_t len, flines_t *out, int role) {
  size_t end = len;
  while (end > 0 && (text[end - 1] == '\n' || text[end - 1] == '\r')) end--;
  for (size_t i = 0; i < end;) {
    size_t j = i;
    while (j < end && text[j] != '\n') j++;
    size_t n = j - i;
    if (n > 0 && text[i + n - 1] == '\r') n--;
    char *clean = malloc(n + 2);
    if (clean) {
      console_sanitize(text + i, n, clean, n + 2);
      flines_add(out, role, clean);
      free(clean);
    }
    i = j + 1;
  }
}

/* Show a reply: laid out (pretty) or as records (raw). */
static void show_reply(console_ui_t *ui, const char *text, size_t len, const char *words,
                       int mode, bool err) {
  flines_t f = {0};
  if (ui->raw) {
    raw_lines(text, len, &f, err ? RL_ERR : RL_NORMAL);
    emit_flines(ui, &f);
  } else if (ui->line_mode) {
    render_reply(ui, text, len, words, mode, &f);
    emit_flines(ui, &f);
  } else {
    /* kept as records so a resize lays it out again (D5) */
    render_reply(ui, text, len, words, mode, &f);
    for (int i = 0; i < f.n; i++) fs_add(ui, V_CONSOLE, f.v[i].text, f.v[i].role, LOG_INFO);
    char *copy = malloc(len + 1);
    if (copy) {
      memcpy(copy, text, len);
      copy[len] = '\0';
      ent_push(ui, NULL, 0, copy, words, mode);
      free(copy);
    }
  }
  flines_free(&f);
}

/* ==========================================================================
 * Replies and events from the core
 * ========================================================================== */
static void flush_held(console_ui_t *ui) {
  if (ui->held.len) {
    cbuf_add(&ui->term, ui->held.p, ui->held.len);
    ui->held.len = 0;
  }
}

static void run_line(console_ui_t *ui, const char *line);
static void confirm_answer(console_ui_t *ui, const char *answer, bool cancelled);

/* The command in flight finished: held events, then the next queued line.
 * from_reply: it ended with the core's answer (asynchronously), so line mode
 * owes the prompt here; otherwise the input handler prints it. */
static void command_done(console_ui_t *ui, bool from_reply) {
  ui->user_busy = false;
  ui->dirty = true;
  /* Lines typed ahead: the next one answers a confirmation a queued
   * command asked for, as it would have at the prompt. */
  while (!ui->user_busy && ui->queued_n > 0 && !ui->closing) {
    char *next = ui->queued[0];
    ui->queued_n--;
    memmove(ui->queued, ui->queued + 1, sizeof(char *) * (size_t)ui->queued_n);
    if (ui->confirming) confirm_answer(ui, next, false);
    else run_line(ui, next);
    free(next);
  }
  if (ui->line_mode && from_reply && !ui->user_busy && !ui->closing) {
    if (ui->confirming) {
      lm_prompt(ui);
    } else {
      flush_held(ui);
      lm_prompt(ui);
    }
  }
}

static void marker_ok(console_ui_t *ui, int seq, const char *words) {
  if (ui->line_mode) {
    char m[96];
    usnprintf(m, sizeof(m), "[ok #%d] %s", seq, words);
    lm_line(ui, m);
  }
}

/* The error marker: "<msg>" (pretty) or "<code>: <msg>" (raw, D6). */
static void marker_err(console_ui_t *ui, int seq, const char *code, const char *msg) {
  if (!ui->line_mode) return;
  char m[CONSOLE_INPUT_MAX + 96];
  if (ui->raw && code && *code)
    usnprintf(m, sizeof(m), "[err #%d] %s: %s", seq, code, msg && *msg ? msg : code);
  else
    usnprintf(m, sizeof(m), "[err #%d] %s", seq, msg && *msg ? msg : code ? code : "failed");
  lm_line(ui, m);
}

/* A console-side refusal: the ✗ block (pretty), then the marker. */
static void refuse(console_ui_t *ui, int seq, const char *code, const char *msg,
                   const char *hint) {
  if (!ui->raw && strcmp(code, "cmd.cancelled") != 0) {
    fmt_ctx_t c;
    char slog[128];
    ctx_init(ui, &c, FMT_MODE_NORMAL, slog, sizeof(slog));
    flines_t f = {0};
    fmt_error(&c, msg, hint, &f);
    emit_flines(ui, &f);
    flines_free(&f);
  }
  marker_err(ui, seq, code, msg);
}

/* A hub-side refusal the console found itself (a D2 pre-read that ends the
 * command): raw format shows it as the err| record the hub would have sent,
 * escaped the same way (docs/console.md §3.1), then the marker. */
static void esc_kv(char *out, size_t cap, size_t *o, const char *key, const char *val) {
  usnprintf(out + *o, cap - *o, "|%s=", key);
  *o += strlen(out + *o);
  for (const char *p = val; *p && *o + 4 < cap; p++) {
    const char *e = *p == '%' ? "%25" : *p == '|' ? "%7C" : *p == '\n' ? "%0A"
                  : *p == '\r' ? "%0D" : NULL;
    if (e) {
      memcpy(out + *o, e, 3);
      *o += 3;
    } else {
      out[(*o)++] = *p;
    }
  }
  out[*o] = '\0';
}

static void refuse_hub(console_ui_t *ui, int seq, const char *code, const char *msg,
                       const char *hint) {
  if (!ui->raw) {
    refuse(ui, seq, code, msg, hint);
    return;
  }
  char rec[1024];
  usnprintf(rec, sizeof(rec), "err|%s", code);
  size_t o = strlen(rec);
  esc_kv(rec, sizeof(rec), &o, "msg", msg);
  if (hint) esc_kv(rec, sizeof(rec), &o, "hint", hint);
  flines_t f = {0};
  raw_lines(rec, o, &f, RL_ERR);
  emit_flines(ui, &f);
  flines_free(&f);
  marker_err(ui, seq, code, msg);
}

/* ✓ result of a console-side command (display, log on/off, …). */
static void local_ok(console_ui_t *ui, const char *what, const char *subject,
                     const char *effect_text) {
  if (ui->raw) return;
  fmt_ctx_t c;
  char slog[128];
  ctx_init(ui, &c, FMT_MODE_NORMAL, slog, sizeof(slog));
  flines_t f = {0};
  fmt_ok(&c, what, subject, &f);
  if (effect_text) {
    char e[256];
    usnprintf(e, sizeof(e), "   %s %s", fmt_glyph(&c, G_BULLET), effect_text);
    flines_add(&f, RL_NORMAL, e);
  }
  emit_flines(ui, &f);
  flines_free(&f);
}

static void send_request(console_ui_t *ui, uint8_t op, const void *payload,
                         size_t len, const pending_rq_t *rq);
static void ask_confirm(console_ui_t *ui, confirm_t kind, const char *want, int pick_max,
                        const char *question);
static void pre_reply(console_ui_t *ui, const pending_rq_t *rq, const char *text, size_t len);

static void on_reply(console_ui_t *ui, const char *text, size_t len) {
  if (ui->rq_n == 0) return;   /* nothing asked: ignore */
  pending_rq_t rq = ui->rq[0];
  ui->rq_n--;
  memmove(ui->rq, ui->rq + 1, sizeof(pending_rq_t) * (size_t)ui->rq_n);

  if (rq.kind == RQ_VIEW_UPG || rq.kind == RQ_VIEW_STATS) {
    char **dst = rq.kind == RQ_VIEW_UPG ? &ui->upg_text : &ui->stats_text;
    free(*dst);
    *dst = malloc(len + 1);
    if (*dst) {
      memcpy(*dst, text, len);
      (*dst)[len] = '\0';
    }
    ui->dirty = true;
    return;
  }
  if (rq.kind == RQ_PRE) {
    pre_reply(ui, &rq, text, len);
    return;
  }
  if (rq.kind != RQ_USER) return;

  creply_t rep;
  creply_parse(text, len, &rep);
  bool err = rep.err;
  char code[64], msg[320];
  usnprintf(code, sizeof(code), "%s", rep.code ? rep.code : "");
  usnprintf(msg, sizeof(msg), "%s", err && rv(&rep.res, "msg") ? rv(&rep.res, "msg") : "");
  creply_free(&rep);
  show_reply(ui, text, len, rq.words, rq.mode, err);
  if (err) marker_err(ui, rq.seq, code, msg);
  else marker_ok(ui, rq.seq, rq.words);
  audit(ui, rq.audit_level, "[CONSOLE] %s@%s #%d %s -> %s%s%s%.*s", ui->admin, ui->ip,
        rq.seq, rq.audit, err ? "err: " : "ok", err ? code : "", err ? ": " : "",
        err ? uprec(msg, 120) : 0, err ? msg : "");
  command_done(ui, true);
}

static void parse_status(console_ui_t *ui, const char *data) {
  status_t st;
  memset(&st, 0, sizeof(st));
  usnprintf(st.upg, sizeof(st.upg), "-");
  char buf[512];
  usnprintf(buf, sizeof(buf), "%s", data);
  char *save = NULL;
  for (char *f = strtok_r(buf, "|", &save); f; f = strtok_r(NULL, "|", &save)) {
    char *eq = strchr(f, '=');
    if (!eq) continue;
    *eq = '\0';
    const char *v = eq + 1;
    if (!strcmp(f, "name")) console_sanitize(v, strlen(v), st.name, sizeof(st.name));
    else if (!strcmp(f, "peers")) sscanf(v, "%d/%d", &st.peers_up, &st.peers_total);
    else if (!strcmp(f, "bots")) sscanf(v, "%d/%d", &st.bots_on, &st.bots_total);
    else if (!strcmp(f, "upg")) console_sanitize(v, strlen(v), st.upg, sizeof(st.upg));
    else if (!strcmp(f, "frozen")) st.frozen = atoi(v) != 0;
    else if (!strcmp(f, "rollup")) st.rollup = atoi(v) != 0;
    else if (!strcmp(f, "split")) st.split = atoi(v) != 0;
    else if (!strcmp(f, "loglevel")) st.loglevel = atoi(v);
    else if (!strcmp(f, "consolelevel")) st.consolelevel = atoi(v);
  }
  st.have = true;
  ui->st = st;
  if (st.name[0]) usnprintf(ui->hubname, sizeof(ui->hubname), "%s", st.name);
}

static void request_view(console_ui_t *ui, int kind, long long now_ms) {
  /* Replies come back in request order, and a command may be answered late
   * (channel op waits for a bot): refresh only between commands. */
  if (ui->user_busy) return;
  for (int i = 0; i < ui->rq_n; i++)
    if (ui->rq[i].kind == kind) return;         /* one at a time */
  if (ui->rq_n >= MAX_PENDING_RQ) return;
  pending_rq_t *r = &ui->rq[ui->rq_n++];
  memset(r, 0, sizeof(*r));
  r->kind = kind;
  if (kind == RQ_VIEW_UPG) {
    core_frame(ui, CMD_ADMIN_UPGRADE_STATUS, "", 0);
    ui->upg_at = now_ms;
  } else {
    core_frame(ui, CMD_ADMIN_STATS, "", 0);
    ui->stats_at = now_ms;
  }
}

/* Human event lines (§3, D14): pretty only; line mode with display events
 * on, the full-screen console view always. */
static bool human_events(const console_ui_t *ui) {
  return !ui->raw && (!ui->line_mode || ui->events_on);
}

static void human_event(console_ui_t *ui, const char *text, int kind) {
  if (ui->line_mode) lm_async(ui, text);
  else fs_timestamped(ui, V_CONSOLE, text, kind);
}

/* ---- tree rows ---- */
typedef struct {
  char type;          /* H B D */
  int  depth;
  char name[64], uuid[64], ver[24], var[8], server[72];
  bool online;
  long long started;  /* H/B: start time, D: last seen */
} trow_t;

static int parse_tree(const char *tree, trow_t *out, int max);
#define MAX_TROWS 1400

/* What changed between two trees, as a line each (D14). */
static void tree_events(console_ui_t *ui, const char *old, const char *cur) {
  static trow_t a[MAX_TROWS], b[MAX_TROWS];
  int na = parse_tree(old, a, MAX_TROWS), nb = parse_tree(cur, b, MAX_TROWS);
  fmt_ctx_t c;
  char slog[128];
  ctx_init(ui, &c, FMT_MODE_NORMAL, slog, sizeof(slog));
  char line[256];
  /* peers up/down */
  for (int j = 0; j < nb; j++) {
    if (b[j].type != 'H' || b[j].depth < 1) continue;
    for (int i = 0; i < na; i++) {
      if (a[i].type != 'H' || strcmp(a[i].uuid, b[j].uuid) || strcmp(a[i].name, b[j].name)) continue;
      if (a[i].online != b[j].online) {
        usnprintf(line, sizeof(line), "%s peer %s %s", fmt_glyph(&c, b[j].online ? G_ON : G_WARN),
                  b[j].name, b[j].online ? "is up" : "went down");
        human_event(ui, line, b[j].online ? RL_DIM : RL_WARN);
      }
      break;
    }
  }
  /* bots in / out / moved: the hub is the nearest H row above */
  const char *hub_a[MAX_TROWS], *hub_b[MAX_TROWS];
  const char *h = "";
  for (int i = 0; i < na; i++) {
    if (a[i].type == 'H') h = a[i].name;
    hub_a[i] = h;
  }
  h = "";
  for (int j = 0; j < nb; j++) {
    if (b[j].type == 'H') h = b[j].name;
    hub_b[j] = h;
  }
  for (int j = 0; j < nb; j++) {
    if (b[j].type != 'B') continue;
    int i = 0;
    while (i < na && !(a[i].type == 'B' && !strcmp(a[i].uuid, b[j].uuid))) i++;
    if (i == na) {
      usnprintf(line, sizeof(line), "%s bot %s connected to %s", fmt_glyph(&c, G_ON), b[j].name,
                hub_b[j]);
      human_event(ui, line, RL_DIM);
    } else if (strcmp(hub_a[i], hub_b[j])) {
      usnprintf(line, sizeof(line), "%s bot %s moved from %s to %s", fmt_glyph(&c, G_ON),
                b[j].name, hub_a[i], hub_b[j]);
      human_event(ui, line, RL_DIM);
    }
  }
  for (int i = 0; i < na; i++) {
    if (a[i].type != 'B') continue;
    int j = 0;
    while (j < nb && !(b[j].type == 'B' && !strcmp(b[j].uuid, a[i].uuid))) j++;
    if (j == nb) {
      usnprintf(line, sizeof(line), "%s bot %s disconnected from %s", fmt_glyph(&c, G_OFF),
                a[i].name, hub_a[i]);
      human_event(ui, line, RL_DIM);
    }
  }
}

/* After login: what the mesh looks like, once (§2.1). */
static void greet_status(console_ui_t *ui) {
  if (ui->greeted) return;
  ui->greeted = true;
  if (ui->raw || ui->seq > 0) return;
  fmt_ctx_t c;
  char slog[128];
  ctx_init(ui, &c, FMT_MODE_NORMAL, slog, sizeof(slog));
  char l1[256], l2[64];
  const char *dot = fmt_glyph(&c, G_DOT);
  usnprintf(l1, sizeof(l1), " peers %d/%d up %s bots %d/%d online %s log file %s, console %s",
            ui->st.peers_up, ui->st.peers_total, dot, ui->st.bots_on, ui->st.bots_total, dot,
            ui->st.loglevel >= 0 && ui->st.loglevel <= 4 ? LEVEL_WORD[ui->st.loglevel] : "?",
            ui->st.consolelevel >= 0 && ui->st.consolelevel <= 4 ? LEVEL_WORD[ui->st.consolelevel] : "?");
  usnprintf(l2, sizeof(l2), " type help for commands");
  if (ui->line_mode) {
    lm_async(ui, l1);
    lm_async(ui, l2);
  } else {
    fs_line(ui, l1, RL_DIM);
    fs_line(ui, l2, RL_DIM);
  }
}

static void on_event(console_ui_t *ui, const char *payload, size_t len,
                     long long now_ms) {
  const char *bar = memchr(payload, '|', len);
  if (!bar) return;
  size_t tl = (size_t)(bar - payload);
  const char *data = bar + 1;
  size_t dl = len - tl - 1;
  char topic[16];
  /* a NUL inside the topic would end it early for strcmp below */
  if (tl >= sizeof(topic) || memchr(payload, '\0', tl)) return;
  memcpy(topic, payload, tl);
  topic[tl] = '\0';

  if (!strcmp(topic, "status")) {
    char *clean = malloc(dl + 1);
    if (!clean) return;
    console_sanitize(data, dl, clean, dl + 1);
    parse_status(ui, clean);
    if (ui->line_mode) {
      char *line = malloc(dl + 32);
      if (line) {
        usnprintf(line, dl + 32, "[evt status] %s", clean);
        lm_async(ui, line);
        free(line);
      }
    }
    free(clean);
    greet_status(ui);
    ui->dirty = true;
  } else if (!strcmp(topic, "tree")) {
    /* each row keeps its newline, and a last row without one gains it:
     * at most dl + 1 bytes of rows, then the NUL */
    char *tree = malloc(dl + 2);
    if (!tree) return;
    /* sanitize each row, keep the newlines */
    size_t o = 0;
    int rows = 0;
    for (size_t i = 0; i < dl;) {
      size_t j = i;
      while (j < dl && data[j] != '\n') j++;
      if (j > i) {
        o += console_sanitize(data + i, j - i, tree + o, dl + 2 - o);
        tree[o++] = '\n';
        rows++;
      }
      i = j + 1;
    }
    tree[o] = '\0';
    if (ui->line_mode) {
      size_t cap = o + (size_t)rows * 12 + 64;
      char *blk = malloc(cap);
      if (blk) {
        size_t b = (size_t)usnprintf(blk, cap, "[evt tree] begin %d\n", rows);
        for (const char *p = tree; *p;) {
          const char *nl = strchr(p, '\n');
          size_t n = nl ? (size_t)(nl - p) : strlen(p);
          b += (size_t)usnprintf(blk + b, cap - b, "[evt tree] %.*s\n", (int)n, p);
          p = nl ? nl + 1 : p + n;
        }
        usnprintf(blk + b, cap - b, "[evt tree] end");
        lm_async(ui, blk);
        free(blk);
      }
    }
    if (ui->tree && human_events(ui)) tree_events(ui, ui->tree, tree);
    free(ui->tree);
    ui->tree = tree;
    ui->dirty = true;
  } else if (!strcmp(topic, "upg")) {
    char clean[256];
    console_sanitize(data, dl, clean, sizeof(clean));
    if (ui->line_mode) {
      char line[300];
      usnprintf(line, sizeof(line), "[evt upg] %s", clean);
      lm_async(ui, line);
    } else if (ui->view == V_UPG) {
      request_view(ui, RQ_VIEW_UPG, now_ms);
    }
    if (human_events(ui) && strcmp(clean, ui->last_upg)) {
      /* <id>|<phase>|<done>/<total>|<failed> */
      char f[4][64] = {"", "", "", ""};
      int k = 0;
      for (const char *p = clean; k < 4;) {
        const char *q = strchr(p, '|');
        size_t n = q ? (size_t)(q - p) : strlen(p);
        usnprintf(f[k++], sizeof(f[0]), "%.*s", (int)(n < 63 ? n : 63), p);
        if (!q) break;
        p = q + 1;
      }
      char line[300];
      usnprintf(line, sizeof(line), "upgrade %s: %s done (%s)%s%s%s", f[0], f[2], f[1],
                atoi(f[3]) > 0 ? ", " : "", atoi(f[3]) > 0 ? f[3] : "", atoi(f[3]) > 0 ? " failed" : "");
      if (clean[0]) human_event(ui, line, atoi(f[3]) > 0 ? RL_WARN : RL_DIM);
    }
    usnprintf(ui->last_upg, sizeof(ui->last_upg), "%s", clean);
  } else if (!strcmp(topic, "log")) {
    const char *b2 = memchr(data, '|', dl);
    if (!b2) return;
    char lvl[16];
    size_t ll = (size_t)(b2 - data);
    if (ll >= sizeof(lvl)) return;
    memcpy(lvl, data, ll);
    lvl[ll] = '\0';
    char clean[CONSOLE_LOG_LINE_MAX + 8];
    console_sanitize(b2 + 1, dl - ll - 1, clean, sizeof(clean));
    int level = LOG_INFO;
    for (int i = 1; i <= LOG_DEBUG; i++)
      if (!strcmp(lvl, LEVEL_WORD[i])) level = i;
    if (ui->line_mode) {
      if (!ui->log_on) return;
      char line[CONSOLE_LOG_LINE_MAX + 48];
      if (ui->raw) {
        usnprintf(line, sizeof(line), "[log %s] %s", LEVEL_WORD[level], clean);
      } else {
        char t[16];
        clock_utc(t, sizeof(t), true);
        usnprintf(line, sizeof(line), "[log %s %s] %s", LEVEL_WORD[level], t, clean);
      }
      lm_async(ui, line);
    } else {
      int kind = level == LOG_ERROR ? RL_ERR : level == LOG_WARNING ? RL_WARN
               : level == LOG_DEBUG ? RL_DIM : RL_NORMAL;
      fs_add(ui, V_LOG, clean, kind, level);
    }
  } else if (!strcmp(topic, "drop")) {
    /* the payload is not NUL-terminated: parse a bounded copy */
    char num[24];
    size_t nl = dl < sizeof(num) - 1 ? dl : sizeof(num) - 1;
    memcpy(num, data, nl);
    num[nl] = '\0';
    ui->dropped += strtoul(num, NULL, 10);
  }
}

void ui_core_frame(console_ui_t *ui, uint8_t op, const char *payload, size_t len,
                   long long now_ms) {
  ui->now_ms = now_ms;
  if (op == CONSOLE_REPLY) on_reply(ui, payload, len);
  else if (op == CMD_CONSOLE) on_event(ui, payload, len, now_ms);
}

/* ==========================================================================
 * Running a command line
 * ========================================================================== */
#define MAX_WORDS 16

typedef struct {
  char  buf[CONSOLE_INPUT_MAX];
  char *w[MAX_WORDS];
  int   n;
  size_t off[MAX_WORDS];   /* where each word starts in the original line */
} words_t;

static void split_words(const char *line, words_t *ws) {
  usnprintf(ws->buf, sizeof(ws->buf), "%s", line);
  ws->n = 0;
  char *p = ws->buf;
  while (*p && ws->n < MAX_WORDS) {
    while (*p == ' ') p++;
    if (!*p) break;
    ws->off[ws->n] = (size_t)(p - ws->buf);
    ws->w[ws->n++] = p;
    while (*p && *p != ' ') p++;
    if (*p) *p++ = '\0';
  }
}

static bool cmd_has_subs(const char *cmd);
static const cmd_def_t *find_cmd(const words_t *ws, int *argi) {
  const char *c = strcmp(ws->w[0], "?") ? ws->w[0] : "help";   /* ? = help */
  for (int i = 0; i < NCMDS; i++) {
    if (strcasecmp(CMDS[i].cmd, c) != 0) continue;
    if (CMDS[i].sub) {
      if (ws->n >= 2 && strcasecmp(CMDS[i].sub, ws->w[1]) == 0) {
        *argi = 2;
        return &CMDS[i];
      }
    } else {
      *argi = 1;
      return &CMDS[i];
    }
  }
  return NULL;
}

static bool cmd_known_word(const char *w) {
  for (int i = 0; i < NCMDS; i++)
    if (strcasecmp(CMDS[i].cmd, w) == 0) return true;
  return false;
}

/* help <group> <command>: usage, what it does, each argument, examples. */
static void help_command(const fmt_ctx_t *c, flines_t *f, const cmd_def_t *d) {
  char words[32], line[1024];
  usnprintf(words, sizeof(words), "%s%s%s", d->cmd, d->sub ? " " : "", d->sub ? d->sub : "");
  const char *args = NULL, *ex = NULL;
  for (int i = 0; i < NCMDHELP; i++)
    if (!strcmp(CMD_HELP[i].cmd, d->cmd) &&
        (CMD_HELP[i].sub ? d->sub && !strcmp(CMD_HELP[i].sub, d->sub) : !d->sub)) {
      args = CMD_HELP[i].args;
      ex = CMD_HELP[i].examples;
    }
  char right[64];
  const char *conf = d->confirm == CF_YN ? "asks y/N" : d->confirm == CF_TYPE ? "type to confirm" : NULL;
  if (d->sub) usnprintf(right, sizeof(right), "%s%shelp %s for the group", conf ? conf : "",
                        conf ? " · " : "", d->cmd);
  else usnprintf(right, sizeof(right), "%s", conf ? conf : "");
  fmt_title(c, f, words, right[0] ? right : NULL);
  usnprintf(line, sizeof(line), "   %s", d->usage);
  flines_add(f, RL_NORMAL, line);
  usnprintf(line, sizeof(line), "   %s", d->help);
  flines_add(f, RL_DIM, line);
  /* "name<TAB>text" lines as a two-column list; a long name puts its text
   * on the next line */
  if (args) {
    flines_add(f, RL_NORMAL, "");
    flines_add(f, RL_HEAD, " Arguments");
    int nw = 0;
    for (const char *p = args; *p;) {
      const char *tab = strchr(p, '\t'), *nl = strchr(p, '\n');
      if (!nl) nl = p + strlen(p);
      int w = tab && tab < nl ? (int)(tab - p) : 0;
      if (w > nw && w <= 16) nw = w;
      p = *nl ? nl + 1 : nl;
    }
    for (const char *p = args; *p;) {
      const char *tab = strchr(p, '\t'), *nl = strchr(p, '\n');
      if (!nl) nl = p + strlen(p);
      if (!tab || tab > nl) tab = p;
      int w = (int)(tab - p);
      const char *t = tab == p ? p : tab + 1;
      if (w <= nw) {
        usnprintf(line, sizeof(line), "   %.*s%*s  %.*s", w, p, nw - w, "", (int)(nl - t), t);
        flines_add(f, RL_NORMAL, line);
      } else {
        usnprintf(line, sizeof(line), "   %.*s", w, p);
        flines_add(f, RL_NORMAL, line);
        usnprintf(line, sizeof(line), "   %*s  %.*s", nw, "", (int)(nl - t), t);
        flines_add(f, RL_NORMAL, line);
      }
      p = *nl ? nl + 1 : nl;
    }
  } else {
    flines_add(f, RL_DIM, "   (no arguments)");
  }
  if (ex) {
    flines_add(f, RL_NORMAL, "");
    flines_add(f, RL_HEAD, strchr(ex, '\n') ? " Examples" : " Example");
    for (const char *p = ex; *p;) {
      const char *nl = strchr(p, '\n');
      if (!nl) nl = p + strlen(p);
      usnprintf(line, sizeof(line), "   %.*s", (int)(nl - p), p);
      flines_add(f, RL_CMD, line);          /* never wrapped: it copies as typed */
      p = *nl ? nl + 1 : nl;
    }
  }
}

/* help: the groups; help <group>: its commands; help <group> <command>: one
 * command in full (§2.2). */
static void show_help(console_ui_t *ui, const char *topic, const cmd_def_t *one) {
  fmt_ctx_t c;
  char slog[128];
  ctx_init(ui, &c, FMT_MODE_NORMAL, slog, sizeof(slog));
  flines_t f = {0};
  char right[96], line[512];
  const char *dot = fmt_glyph(&c, G_DOT);
  if (one) {
    help_command(&c, &f, one);
  } else if (!topic) {
    usnprintf(right, sizeof(right), "%d groups %s help <group> for its commands", NGROUPS, dot);
    fmt_title(&c, &f, "Commands", right);
    for (int g = 0; g < NGROUPS; g++) {
      /* the separator, once per verb */
      char sep[8];
      usnprintf(sep, sizeof(sep), " %s ", dot);
      char joined[512] = "";
      size_t jo = 0;
      bool first = true;
      for (int i = 0; i < NCMDS; i++) {
        if (!CMDS[i].sub || strcmp(CMDS[i].cmd, GROUPS[g].name)) continue;
        jo += (size_t)usnprintf(joined + jo, sizeof(joined) - jo, "%s%s", first ? "" : sep,
                                CMDS[i].sub);
        first = false;
      }
      usnprintf(line, sizeof(line), "   %-9s %-22s %s", GROUPS[g].name, GROUPS[g].what, joined);
      if (console_str_width(line) <= c.width) {
        flines_add(&f, RL_NORMAL, line);
      } else {
        usnprintf(line, sizeof(line), "   %-9s %s", GROUPS[g].name, GROUPS[g].what);
        flines_add(&f, RL_NORMAL, line);
        usnprintf(line, sizeof(line), "             %s", joined);
        flines_add(&f, RL_DIM, line);
      }
    }
    usnprintf(line, sizeof(line), "   help [group [command]] %s ? [group [command]] %s quit", dot, dot);
    flines_add(&f, RL_NORMAL, line);
    if (!ui->line_mode) {
      flines_add(&f, RL_NORMAL, "");
      flines_add(&f, RL_DIM, " Keys  Alt+1..5 views, Alt+Left/Right cycle, F2 log level, F3 tree pane,");
      flines_add(&f, RL_DIM, "       PgUp/PgDn/End scroll, Tab completes, Up/Down history, Ctrl-C cancels");
    }
  } else {
    int n = 0, uw = 0;
    for (int i = 0; i < NCMDS; i++)
      if (!strcasecmp(CMDS[i].cmd, topic)) {
        n++;
        int w = console_str_width(CMDS[i].usage);
        if (w > uw) uw = w;
      }
    if (uw > 34) uw = 34;
    usnprintf(right, sizeof(right), "%d command%s %s help %s <command> for one", n,
              n == 1 ? "" : "s", dot, topic);
    fmt_title(&c, &f, topic, right);
    for (int i = 0; i < NCMDS; i++) {
      if (strcasecmp(CMDS[i].cmd, topic)) continue;
      int w = console_str_width(CMDS[i].usage);
      if (w <= uw && 1 + uw + 2 + console_str_width(CMDS[i].help) <= c.width) {
        usnprintf(line, sizeof(line), " %s%*s  %s", CMDS[i].usage, uw - w, "", CMDS[i].help);
        flines_add(&f, RL_NORMAL, line);
      } else {
        usnprintf(line, sizeof(line), " %s", CMDS[i].usage);
        flines_add(&f, RL_NORMAL, line);
        usnprintf(line, sizeof(line), " %*s  %s", uw, "", CMDS[i].help);
        flines_add(&f, RL_NORMAL, line);
      }
      if (CMDS[i].args) {
        usnprintf(line, sizeof(line), " %*s  %s", uw, "", CMDS[i].args);
        flines_add(&f, RL_DIM, line);
      }
    }
  }
  emit_flines(ui, &f);
  flines_free(&f);
}

static int level_arg(const char *a) {
  if (strlen(a) == 1 && a[0] >= '0' && a[0] <= '4') return a[0] - '0';
  for (int i = 0; i <= LOG_DEBUG; i++)
    if (strcasecmp(a, LEVEL_WORD[i]) == 0) return i;
  if (strcasecmp(a, "warn") == 0) return LOG_WARNING;
  return -1;
}

static bool all_digits(const char *s) {
  if (!*s || strlen(s) > 10) return false;
  for (; *s; s++)
    if (!isdigit((unsigned char)*s)) return false;
  return true;
}

/* key=value option of "upgrade" commands; returns the value or NULL. */
static const char *kv_opt(const char *arg, const char *key) {
  size_t kl = strlen(key);
  return (strncasecmp(arg, key, kl) == 0 && arg[kl] == '=') ? arg + kl + 1 : NULL;
}

static void send_request(console_ui_t *ui, uint8_t op, const void *payload,
                         size_t len, const pending_rq_t *rq) {
  if (ui->rq_n >= MAX_PENDING_RQ) {
    refuse(ui, rq->seq, "cmd.busy", "too many requests in flight", NULL);
    return;
  }
  ui->rq[ui->rq_n++] = *rq;
  core_frame(ui, op, payload, len);
  ui->user_busy = true;
}

static void session_log_phrase(const console_ui_t *ui, char *out, size_t cap) {
  if (ui->line_mode) {
    if (ui->log_on)
      usnprintf(out, cap, "%s and worse (log on)", LEVEL_WORD[ui->log_sub_level]);
    else
      usnprintf(out, cap, "off (log on [level] streams it here)");
  } else {
    usnprintf(out, cap, "log view (Alt+2): %s and worse%s%s", LEVEL_WORD[ui->log_show],
              ui->filter[0] ? ", filter " : "", ui->filter);
  }
}

static void display_show(console_ui_t *ui) {
  fmt_ctx_t c;
  char slog[128];
  ctx_init(ui, &c, FMT_MODE_NORMAL, slog, sizeof(slog));
  flines_t f = {0};
  char right[64], v[192];
  if (ui->line_mode) usnprintf(right, sizeof(right), "line mode %d", out_width(ui));
  else usnprintf(right, sizeof(right), "full screen %d%s%d", ui->cols, "×", ui->rows);
  fmt_title(&c, &f, "Display", right);
  const int L = 9;
  if (!ui->line_mode) {
    usnprintf(v, sizeof(v), "%s (Alt+%d)", VIEW_NAME[ui->view], ui->view + 1);
    fmt_card_line(&c, &f, L, "view", v, RL_NORMAL);
    bool shown = ui->cols >= CONSOLE_PANE_MIN_COLS ? !ui->pane_user_off : ui->overlay;
    fmt_card_line(&c, &f, L, "tree pane", shown ? "shown (F3 hides it)" : "hidden (F3 shows it)", RL_NORMAL);
  }
  fmt_card_line(&c, &f, L, "glyphs", ui->ascii ? "ascii" : "unicode", RL_NORMAL);
  fmt_card_line(&c, &f, L, "format", ui->raw ? "raw" : "pretty", RL_NORMAL);
  if (ui->line_mode) {
    if (ui->width_set < 0) usnprintf(v, sizeof(v), "auto (%d)", out_width(ui));
    else usnprintf(v, sizeof(v), "%d", out_width(ui));
    fmt_card_line(&c, &f, L, "width", v, RL_NORMAL);
    fmt_card_line(&c, &f, L, "events", ui->events_on ? "on" : "off", RL_NORMAL);
    fmt_card_line(&c, &f, L, "colors", "off (line mode)", RL_NORMAL);
  } else {
    usnprintf(v, sizeof(v), "%d for output", out_width(ui));
    fmt_card_line(&c, &f, L, "width", v, RL_NORMAL);
    fmt_card_line(&c, &f, L, "colors", "on", RL_NORMAL);
  }
  session_log_phrase(ui, v, sizeof(v));
  fmt_card_line(&c, &f, L, "log", v, RL_NORMAL);
  emit_flines(ui, &f);
  flines_free(&f);
}

static void local_command(console_ui_t *ui, const cmd_def_t *c, const words_t *ws,
                          int argi, const char *line, int seq, const char *words) {
  const char *a1 = ws->n > argi ? ws->w[argi] : NULL;
  char from[64];
  if (!strcmp(c->cmd, "help")) {
    if (a1 && !cmd_known_word(a1)) {
      char m[96];
      usnprintf(m, sizeof(m), "no command group \"%.*s\"", uprec(a1, 40), a1);
      refuse(ui, seq, "cmd.unknown", m, "help");
      return;
    }
    const cmd_def_t *one = NULL;
    const char *a2 = ws->n > argi + 1 ? ws->w[argi + 1] : NULL;
    if (a1 && (a2 || !cmd_has_subs(a1))) {
      for (int i = 0; i < NCMDS && !one; i++)
        if (!strcasecmp(CMDS[i].cmd, a1) &&
            (CMDS[i].sub ? a2 && !strcasecmp(CMDS[i].sub, a2) : !a2))
          one = &CMDS[i];
      if (!one) {
        char m[128], h[64];
        usnprintf(m, sizeof(m), "%s has no command %.*s", a1, uprec(a2 ? a2 : "", 40), a2 ? a2 : "");
        usnprintf(h, sizeof(h), "help %s", a1);
        refuse(ui, seq, "cmd.unknown", m, h);
        return;
      }
    }
    show_help(ui, a1, one);
  } else if (!strcmp(c->cmd, "quit")) {
    if (!ui->raw) {
      char m[160], d[32];
      long long s = (ui->now_ms - ui->start_ms) / 1000;
      if (s < 0) s = 0;
      usnprintf(d, sizeof(d), "%02lld:%02lld:%02lld", s / 3600, s / 60 % 60, s % 60);
      fmt_ctx_t cx;
      char slog[128];
      ctx_init(ui, &cx, FMT_MODE_NORMAL, slog, sizeof(slog));
      const char *dot = fmt_glyph(&cx, G_DOT);
      usnprintf(m, sizeof(m), " Goodbye %s %s session %s %s %d command%s", ui->admin, dot, d, dot,
                ui->ncmds, ui->ncmds == 1 ? "" : "s");
      note(ui, m, RL_DIM);
    }
    marker_ok(ui, seq, words);
    ui->closing = true;
    usnprintf(ui->close_why, sizeof(ui->close_why), "quit");
    return;
  } else if (!strcmp(c->cmd, "log")) {
    if (!strcmp(c->sub, "filter")) {
      if (ui->line_mode) {
        refuse(ui, seq, "cmd.mode", "only in the full-screen console", "log on [level] in line mode");
        return;
      }
      const char *rest = line + ws->off[argi];
      usnprintf(from, sizeof(from), "%s", ui->filter[0] ? ui->filter : "-");
      if (!strcasecmp(rest, "clear")) ui->filter[0] = '\0';
      else usnprintf(ui->filter, sizeof(ui->filter), "%s", rest);
      ui->dirty = true;
      char s[300];
      usnprintf(s, sizeof(s), "filter   %s %s %s", from, "→",
                ui->filter[0] ? ui->filter : "-");
      local_ok(ui, "Log", s, NULL);
    } else {
      if (!ui->line_mode) {
        refuse(ui, seq, "cmd.mode", "the log is the Alt+2 view in the full-screen console", NULL);
        return;
      }
      if (!strcmp(c->sub, "on")) {
        int lvl = a1 ? level_arg(a1) : LOG_INFO;
        if (lvl <= 0) {
          refuse(ui, seq, "cmd.bad_arg", "level: error, warning, info or debug", "log on [level]");
          return;
        }
        ui->log_on = true;
        ui->log_sub_level = lvl;
        char s[96], e[96];
        usnprintf(s, sizeof(s), "%s and worse", LEVEL_WORD[lvl]);
        usnprintf(e, sizeof(e), "the ring keeps %s; log off stops it",
                  ui->st.have && ui->st.consolelevel >= 0 && ui->st.consolelevel <= 4
                      ? LEVEL_WORD[ui->st.consolelevel] : "what its level says");
        local_ok(ui, "Log stream on", s, e);
      } else {
        ui->log_on = false;
        local_ok(ui, "Log stream off", NULL, NULL);
      }
      subscribe(ui);
    }
  } else if (!strcmp(c->cmd, "display")) {
    const char *sub = c->sub;
    bool fs_only = !strcmp(sub, "view") || !strcmp(sub, "pane") || !strcmp(sub, "clear");
    bool lm_only = !strcmp(sub, "width") || !strcmp(sub, "events");
    if (fs_only && ui->line_mode) {
      refuse(ui, seq, "cmd.mode", "only in the full-screen console", NULL);
      return;
    }
    if (lm_only && !ui->line_mode) {
      refuse(ui, seq, "cmd.mode", "only in line mode", NULL);
      return;
    }
    const char *arrow = "→";      /* lm_line / fs_add show it as -> */
    char s[160];
    if (!strcmp(sub, "show")) {
      display_show(ui);
    } else if (!strcmp(sub, "view")) {
      if (!a1 || strlen(a1) != 1 || a1[0] < '1' || a1[0] > '5') {
        refuse(ui, seq, "cmd.bad_arg", "view 1-5", "display view <1-5>");
        return;
      }
      usnprintf(from, sizeof(from), "%s", VIEW_NAME[ui->view]);
      ui->view = a1[0] - '1';
      ui->act[ui->view] = false;
      usnprintf(s, sizeof(s), "view   %s %s %s", from, arrow, VIEW_NAME[ui->view]);
      local_ok(ui, "Display", s, NULL);
    } else if (!strcmp(sub, "pane")) {
      bool was;
      if (ui->cols >= CONSOLE_PANE_MIN_COLS) {
        was = !ui->pane_user_off;
        ui->pane_user_off = !ui->pane_user_off;
      } else {
        was = ui->overlay;
        ui->overlay = !ui->overlay;
      }
      usnprintf(s, sizeof(s), "tree pane   %s %s %s (F3 toggles)", was ? "shown" : "hidden", arrow,
                was ? "hidden" : "shown");
      local_ok(ui, "Display", s, NULL);
    } else if (!strcmp(sub, "ascii")) {
      bool was = ui->ascii;
      ui->ascii = !ui->ascii;
      ui->full_redraw = true;
      ui->render_w = -1;
      usnprintf(s, sizeof(s), "glyphs   %s %s %s", was ? "ascii" : "unicode", "→",
                ui->ascii ? "ascii" : "unicode");
      local_ok(ui, "Display", s, NULL);
    } else if (!strcmp(sub, "format")) {
      bool raw;
      if (!strcasecmp(a1, "raw")) raw = true;
      else if (!strcasecmp(a1, "pretty")) raw = false;
      else {
        refuse(ui, seq, "cmd.bad_arg", "format: pretty or raw", "display format pretty|raw");
        return;
      }
      bool was = ui->raw;
      usnprintf(s, sizeof(s), "format   %s %s %s%s", was ? "raw" : "pretty", arrow,
                raw ? "raw" : "pretty", raw ? " (records as the hub sends them)" : "");
      local_ok(ui, "Display", s, NULL);
      ui->raw = raw;
    } else if (!strcmp(sub, "width")) {
      int was = out_width(ui);
      if (!strcasecmp(a1, "auto")) {
        ui->width_set = -1;
      } else if (all_digits(a1) && atoi(a1) >= CONSOLE_WIDTH_MIN && atoi(a1) <= CONSOLE_WIDTH_MAX) {
        ui->width_set = atoi(a1);
      } else {
        refuse(ui, seq, "cmd.bad_arg", "width: 60-250 or auto", "display width <60-250|auto>");
        return;
      }
      usnprintf(s, sizeof(s), "width   %d %s %d%s", was, arrow, out_width(ui),
                ui->width_set < 0 ? " (auto)" : "");
      local_ok(ui, "Display", s, NULL);
    } else if (!strcmp(sub, "events")) {
      bool on;
      if (!strcasecmp(a1, "on")) on = true;
      else if (!strcasecmp(a1, "off")) on = false;
      else {
        refuse(ui, seq, "cmd.bad_arg", "events: on or off", "display events on|off");
        return;
      }
      usnprintf(s, sizeof(s), "events   %s %s %s", ui->events_on ? "on" : "off", arrow, on ? "on" : "off");
      ui->events_on = on;
      local_ok(ui, "Display", s, NULL);
    } else if (!strcmp(sub, "clear")) {
      if (ui->view == V_CONSOLE || ui->view == V_LOG) sb_clear(&ui->sb[ui->view]);
      if (ui->view == V_CONSOLE) {
        for (long long e = ui->ent_first; e < ui->ent_next; e++) {
          centry_t *x = &ui->ent[e % CONSOLE_SCROLLBACK];
          free(x->text);
          free(x->reply);
          memset(x, 0, sizeof(*x));
        }
        ui->ent_first = ui->ent_next;
      }
      ui->anchor[ui->view] = -1;
      usnprintf(s, sizeof(s), "%s view cleared", VIEW_NAME[ui->view]);
      local_ok(ui, "Display", s, NULL);
    }
    ui->dirty = true;
  }
  marker_ok(ui, seq, words);
}

/* Build the request (op and payload); false (with *why, *hint) when the
 * arguments are bad.  *op starts as the table's opcode and *confirm as its
 * confirmation; a command whose arguments pick the opcode sets both. */
static bool build_payload(console_ui_t *ui, const cmd_def_t *c, const words_t *ws,
                          int argi, unsigned char *out, size_t *outlen, uint8_t *op,
                          confirm_t *confirm, int *mode, const char **why,
                          const char **hint) {
  (void)ui;
  int na = ws->n - argi;
  const char *const *a = (const char *const *)&ws->w[argi];
  char *o = (char *)out;
  size_t cap = 1024;
  int w = 0;
  *hint = c->usage;
  switch (c->build) {
  case B_NONE:
  case B_LOCAL:
    *outlen = 0;
    return true;
  case B_FIXED:
    *outlen = (size_t)usnprintf(o, cap, "%s", c->fixed);
    return true;
  case B_ARG:
    w = usnprintf(o, cap, "%s", a[0]);
    break;
  case B_PIPE: {
    size_t off = 0;
    for (int i = 0; i < na; i++) {
      int k = usnprintf(o + off, cap - off, "%s%s", i ? "|" : "", a[i]);
      if (k < 0 || (size_t)k >= cap - off) {
        *why = "arguments too long";
        return false;
      }
      off += (size_t)k;
    }
    *outlen = off;
    return true;
  }
  case B_PEER_ADD:
    for (int i = 0; i < 5; i++)
      if (strchr(a[i], ':')) {
        *why = "':' is not allowed in an argument here";
        return false;
      }
    w = usnprintf(o, cap, "%s:%s:%s:%s:%s", a[0], a[1], a[2], strcmp(a[3], "-") ? a[3] : "", a[4]);
    break;
  case B_PEER_DEL:
    if (na > 0 && !all_digits(a[0])) {
      *why = "a peer is removed by its number in peer list";
      *hint = "peer del [#]";
      return false;
    }
    w = usnprintf(o, cap, "%s", na > 0 ? a[0] : "");
    break;
  case B_PEER_SET:
    if (strcasecmp(a[1], "key")) {
      *why = "unknown peer setting";
      *hint = "settings: key";
      return false;
    }
    if (strchr(a[0], ':') || strchr(a[2], ':')) {
      *why = "':' is not allowed in an argument here";
      return false;
    }
    w = usnprintf(o, cap, "%s:%s", a[0], a[2]);
    break;
  case B_CHAN_ADD:
    w = usnprintf(o, cap, "%s|%s", a[0], na > 1 ? a[1] : "");
    break;
  case B_CHAN_SET: {
    for (const char *p = a[1]; *p; p++)
      if (!(*p >= 'a' && *p <= 'z') && *p != '_') {
        *why = "a setting name is lowercase letters and _";
        *hint = "settings: key";
        return false;
      }
    if (strlen(a[2]) > 128) {
      *why = "a setting value is at most 128 bytes";
      return false;
    }
    w = usnprintf(o, cap, "set|%s|%s|%s", a[0], a[1], strcmp(a[2], "-") ? a[2] : "");
    break;
  }
  case B_CHAN_OP:
    w = usnprintf(o, cap, "%s|%s", a[1], a[0]);   /* the hub takes nick|chan */
    break;
  case B_OPT_SET:
    w = usnprintf(o, cap, "%s", strcmp(a[0], "-") ? a[0] : "");
    break;
  case B_LOG_SET: {
    if (!strcasecmp(a[0], "size")) {
      /* <n> MB, <n>k KiB or <n>b bytes, at most 1024 MB (the hub clamps it
       * to its own limits) */
      char num[16];
      size_t al = strlen(a[1]);
      unsigned long long mult = 1024ull * 1024ull;
      usnprintf(num, sizeof(num), "%s", a[1]);
      if (al > 1 && al < sizeof(num) && strchr("kKbB", a[1][al - 1])) {
        mult = (a[1][al - 1] == 'k' || a[1][al - 1] == 'K') ? 1024ull : 1ull;
        num[al - 1] = '\0';
      }
      unsigned long long v = all_digits(num) ? strtoull(num, NULL, 10) * mult : 0;
      if (v < 1 || v > 1024ull * 1024ull * 1024ull) {
        *why = "size: <MB>, <n>k or <n>b, at most 1024 MB";
        *hint = "log set size <MB|nk|nb>";
        return false;
      }
      uint32_t bytes = htonl((uint32_t)v);
      memcpy(out, &bytes, 4);
      *outlen = 4;
      *op = CMD_ADMIN_SET_LOG_SIZE;
      *confirm = CF_NONE;
      return true;
    }
    /* <target><level>: target 0 = the log file, 1 = the console log */
    int target;
    if (!strcasecmp(a[0], "file")) target = 0;
    else if (!strcasecmp(a[0], "console")) target = 1;
    else {
      *why = "say file, console or size";
      return false;
    }
    int lvl = level_arg(a[1]);
    if (lvl < 0) {
      *why = "level: none, error, warning, info, debug or 0-4";
      return false;
    }
    out[0] = (unsigned char)target;
    out[1] = (unsigned char)lvl;
    *outlen = 2;
    *op = CMD_ADMIN_SET_LOG_LEVEL;
    *confirm = CF_YN;
    return true;
  }
  case B_PURGE:
    if (!strcasecmp(a[0], "now")) w = usnprintf(o, cap, "immediate");
    else if (all_digits(a[0]) && atol(a[0]) > 0) w = usnprintf(o, cap, "%s", a[0]);
    else {
      *why = "purge now, or purge <days>";
      return false;
    }
    break;
  case B_HUB_SET: {
    if (na == 0) {
      /* the settings table: hub show's record, laid out as one */
      *op = CMD_ADMIN_GET_PUBKEY;
      *mode = FMT_MODE_HUB_SETTINGS;
      *outlen = 0;
      return true;
    }
    static const struct { const char *name; uint8_t op; } HS[] = {
      {"name", CMD_ADMIN_SET_HUB_NAME}, {"bindip", CMD_ADMIN_SET_BIND_IP},
      {"port", CMD_ADMIN_SET_BIND_PORT}, {"pubkey", CMD_ADMIN_SET_PUBKEY},
      {"autopurge", CMD_ADMIN_SET_PURGE_DAYS}};
    int k = -1;
    for (int i = 0; i < 5; i++)
      if (!strcasecmp(a[0], HS[i].name)) k = i;
    if (k < 0) {
      static char m[96];
      usnprintf(m, sizeof(m), "unknown hub setting \"%.*s\"", uprec(a[0], 40), a[0]);
      *why = m;
      *hint = "name, bindip, port, pubkey, autopurge";
      return false;
    }
    if (na < 2) {
      *why = "say the new value";
      return false;
    }
    *op = HS[k].op;
    w = usnprintf(o, cap, "%s", a[1]);
    break;
  }
  case B_ACL: {
    bool add = !strcmp(c->sub, "add");
    if (!strcasecmp(a[0], "allow")) *op = add ? CMD_ADMIN_ADD_ALLOWLIST : CMD_ADMIN_DEL_ALLOWLIST;
    else if (!strcasecmp(a[0], "deny")) *op = add ? CMD_ADMIN_ADD_DENYLIST : CMD_ADMIN_DEL_DENYLIST;
    else {
      *why = "say which list";
      return false;
    }
    w = usnprintf(o, cap, "%s", a[1]);
    break;
  }
  case B_USER_LIST:
    if (na == 0) {
      *op = CMD_ADMIN_LIST_ADMINS;
      w = usnprintf(o, cap, "*");
    } else if (!strcasecmp(a[0], "admin")) {
      *op = CMD_ADMIN_LIST_ADMINS;
      w = 0;
      o[0] = '\0';
    } else if (!strcasecmp(a[0], "oper")) {
      *op = CMD_ADMIN_LIST_OPERS_V2;
      w = 0;
      o[0] = '\0';
    } else {
      *why = "role is admin or oper";
      return false;
    }
    break;
  case B_USER_ADD:
    if (!strcasecmp(a[0], "admin")) *op = CMD_ADMIN_ADD_ADMIN;
    else if (!strcasecmp(a[0], "oper")) *op = CMD_ADMIN_ADD_OPER_RECORD;
    else {
      *why = "role is admin or oper";
      return false;
    }
    w = usnprintf(o, cap, "%s|%s|%s", a[1], a[2], a[3]);
    break;
  case B_USER_SET:
    if (strcasecmp(a[1], "key")) {
      *why = "unknown user setting";
      *hint = "settings: key";
      return false;
    }
    w = usnprintf(o, cap, "%s|%s", a[0], a[2]);
    break;
  case B_USER_MASK:
    if (!strcasecmp(a[0], "add")) {
      *op = CMD_ADMIN_ADD_USERMASK;
      *confirm = CF_NONE;
    } else if (!strcasecmp(a[0], "del")) {
      *op = CMD_ADMIN_DEL_USERMASK;
      *confirm = CF_YN;
    } else {
      *why = "say add or del";
      return false;
    }
    w = usnprintf(o, cap, "%s|%s", a[1], a[2]);
    break;
  case B_UPG_RELEASES: {
    const char *bot = "", *hub = "";
    for (int i = 0; i < na; i++) {
      const char *v;
      if ((v = kv_opt(a[i], "bot"))) bot = v;
      else if ((v = kv_opt(a[i], "hub"))) hub = v;
      else {
        *why = "options: bot=<base> hub=<base>";
        return false;
      }
    }
    w = (*bot || *hub) ? usnprintf(o, cap, "releases|%s|%s", bot, hub)
                       : usnprintf(o, cap, "releases");
    break;
  }
  case B_UPG_START: {
    const char *hubv = "", *nodes = "", *bb = "", *hb = "";
    for (int i = 1; i < na; i++) {
      const char *v;
      if ((v = kv_opt(a[i], "hub"))) hubv = strcmp(v, "-") ? v : "";
      else if ((v = kv_opt(a[i], "nodes"))) nodes = v;
      else if ((v = kv_opt(a[i], "botbase"))) bb = v;
      else if ((v = kv_opt(a[i], "hubbase"))) hb = v;
      else {
        *why = "options: hub=<ver> nodes=<list> botbase=<url> hubbase=<url>";
        return false;
      }
    }
    /* ver|variant|kind|min_from|base|hub_ver|hub_base|sel — variant, kind
     * and min_from are left to each node, as hub_admin always did. */
    w = usnprintf(o, cap, "%s||||%s|%s|%s|%s", a[0], bb, hubv, *hubv ? hb : "", nodes);
    break;
  }
  }
  if (w < 0 || (size_t)w >= cap) {
    *why = "arguments too long";
    return false;
  }
  *outlen = (size_t)w;
  return true;
}

/* Enter a confirmation: the question as [confirm #N] (line mode) or a
 * highlighted line, and the next input line answers it. */
static void ask_confirm(console_ui_t *ui, confirm_t kind, const char *want, int pick_max,
                        const char *question) {
  ui->confirming = kind;
  usnprintf(ui->confirm_want, sizeof(ui->confirm_want), "%s", want ? want : "");
  ui->confirm_pick_max = pick_max;
  if (ui->line_mode) {
    char m[CONSOLE_INPUT_MAX];
    usnprintf(m, sizeof(m), "[confirm #%d] %s", ui->confirm_seq, question);
    lm_line(ui, m);
  } else {
    fs_timestamped(ui, V_CONSOLE, question, RL_WARN);
  }
}

static void stage_confirm(console_ui_t *ui, int seq, uint8_t op, const unsigned char *p,
                          size_t n, const pending_rq_t *rq) {
  ui->confirm_seq = seq;
  ui->confirm_op = op;
  memcpy(ui->confirm_payload, p, n);
  ui->confirm_len = n;
  ui->confirm_rq = *rq;
}

/* Warning lines above a question (hub rekey). */
static void warn_lines(console_ui_t *ui, const char *const *lines, int n) {
  if (ui->raw) return;
  fmt_ctx_t c;
  char slog[128];
  ctx_init(ui, &c, FMT_MODE_NORMAL, slog, sizeof(slog));
  flines_t f = {0};
  char l[300];
  for (int i = 0; i < n; i++) {
    if (i == 0) usnprintf(l, sizeof(l), " %s %s", fmt_glyph(&c, G_WARN), lines[i]);
    else usnprintf(l, sizeof(l), "   %s", lines[i]);
    flines_add(&f, RL_WARN, l);
  }
  emit_flines(ui, &f);
  flines_free(&f);
}

static const char *opt_meaning(char f) {
  return f == 'h' ? "hub-only mutation" : f == 'F' ? "config frozen" : "unknown flag";
}

/* A pre-read came back: the question names the object, or the command ends
 * here with what the read found (D2). */
static void pre_reply(console_ui_t *ui, const pending_rq_t *rq, const char *text, size_t len) {
  pend_cmd_t *pc = &ui->pend;
  creply_t rep;
  creply_parse(text, len, &rep);
  if (rep.err || !rep.ok) {
    show_reply(ui, text, len, rq->words, FMT_MODE_NORMAL, true);
    char code[64], msg[320];
    usnprintf(code, sizeof(code), "%s", rep.code ? rep.code : "");
    usnprintf(msg, sizeof(msg), "%s", rv(&rep.res, "msg") ? rv(&rep.res, "msg") : "failed");
    marker_err(ui, rq->seq, code, msg);
    audit(ui, rq->audit_level, "[CONSOLE] %s@%s #%d %s -> err: %s", ui->admin, ui->ip, rq->seq,
          pc->rq.audit, code);
    creply_free(&rep);
    command_done(ui, true);
    return;
  }
  fmt_ctx_t c;
  char slog[128];
  ctx_init(ui, &c, FMT_MODE_NORMAL, slog, sizeof(slog));
  const char *dot = fmt_glyph(&c, G_DOT), *arrow = fmt_glyph(&c, G_ARROW);
  char q[CONSOLE_INPUT_MAX - 64];
  confirm_t kind = CF_YN;
  char want[128] = "";
  int pick = 0;
  const crec_t *r0 = NULL;
  for (int i = 0; i < rep.n && !r0; i++) r0 = &rep.r[i];
  stage_confirm(ui, rq->seq, pc->op, pc->payload, pc->len, &pc->rq);
  bool ok = true;
  const char *fail_code = NULL;
  char fail_msg[256] = "", fail_hint[256] = "";
  switch (pc->pre) {
  case PRE_BOT_DEL:
  case PRE_BOT_KICK: {
    const crec_t *b = NULL;
    for (int i = 0; i < rep.n && !b; i++)
      if (!strcmp(rep.r[i].type, "bot")) b = &rep.r[i];
    const char *nick = b && rvs(b, "nick") ? rv(b, "nick") : pc->arg;
    bool on = b && rvb(b, "online");
    bool local = on && rv(b, "hub") && !strcmp(rv(b, "hub"), "local");
    char u8[16];
    const char *id = b && rv(b, "uuid") ? rv(b, "uuid") : pc->arg;
    usnprintf(u8, sizeof(u8), "%.*s%s", uprec(id, 8), id,
              fmt_glyph(&c, G_ELL));
    if (pc->pre == PRE_BOT_DEL) {
      if (local)
        usnprintf(q, sizeof(q), "Delete bot %s (%s)? It is online on this hub and will be disconnected. (y/N)", nick, u8);
      else if (on)
        usnprintf(q, sizeof(q), "Delete bot %s (%s)? It is online on %s and is dropped everywhere. (y/N)", nick, u8,
                  rvs(b, "hub_name") ? rv(b, "hub_name") : "another hub");
      else
        usnprintf(q, sizeof(q), "Delete bot %s (%s)? It is offline. (y/N)", nick, u8);
    } else if (!local) {
      ok = false;
      fail_code = "bot.not_local";
      usnprintf(fail_msg, sizeof(fail_msg), "%s is not connected to this hub", nick);
      if (on) usnprintf(fail_hint, sizeof(fail_hint), "it is on %s: kick it there",
                        rvs(b, "hub_name") ? rv(b, "hub_name") : "another hub");
      else usnprintf(fail_hint, sizeof(fail_hint), "bot list");
    } else {
      usnprintf(q, sizeof(q), "Disconnect bot %s from this hub? It will reconnect on its own. (y/N)", nick);
    }
    break;
  }
  case PRE_PEER_DEL: {
    int n = 0;
    const crec_t *hit = NULL;
    for (int i = 0; i < rep.n; i++) {
      if (strcmp(rep.r[i].type, "peer")) continue;
      n++;
      if (pc->arg[0] && rvi(&rep.r[i], "n", 0) == atoll(pc->arg)) hit = &rep.r[i];
    }
    if (!n) {
      ok = false;
      fail_code = "peer.none";
      usnprintf(fail_msg, sizeof(fail_msg), "no peer hubs are configured");
      usnprintf(fail_hint, sizeof(fail_hint), "peer list");
      break;
    }
    if (pc->arg[0]) {
      if (!hit) {
        ok = false;
        fail_code = "peer.not_found";
        usnprintf(fail_msg, sizeof(fail_msg), "no peer #%s (%d configured)", pc->arg, n);
        usnprintf(fail_hint, sizeof(fail_hint), "peer list");
        break;
      }
      kind = CF_TYPE;
      usnprintf(want, sizeof(want), "%s", pc->arg);
      usnprintf(q, sizeof(q), "Type %s to remove peer %s (%s:%lld):", pc->arg,
                rvs(hit, "name") ? rv(hit, "name") : rv(hit, "ip") ? rv(hit, "ip") : "?",
                rv(hit, "ip") ? rv(hit, "ip") : "?", rvi(hit, "port", 0));
    } else {
      /* no number: the configured peers, then the number is the answer */
      if (ui->raw) {
        show_reply(ui, text, len, rq->words, FMT_MODE_NORMAL, false);
      } else {
        flines_t f = {0};
        char right[48];
        usnprintf(right, sizeof(right), "%d configured", n);
        fmt_title(&c, &f, "Peer hubs", right);
        int nw = 4, aw = 7;
        for (int i = 0; i < rep.n; i++) {
          const crec_t *p = &rep.r[i];
          if (strcmp(p->type, "peer")) continue;
          char ad[96];
          usnprintf(ad, sizeof(ad), "%s:%lld", rv(p, "ip") ? rv(p, "ip") : "?", rvi(p, "port", 0));
          const char *nm = rvs(p, "name") ? rv(p, "name") : fmt_glyph(&c, G_DASH);
          if (console_str_width(nm) > nw) nw = console_str_width(nm);
          if (console_str_width(ad) > aw) aw = console_str_width(ad);
        }
        char l[512];
        usnprintf(l, sizeof(l), "   #  %-*s  %-*s  LINK", nw, "NAME", aw, "ADDRESS");
        flines_add(&f, RL_HEAD, l);
        for (int i = 0; i < rep.n; i++) {
          const crec_t *p = &rep.r[i];
          if (strcmp(p->type, "peer")) continue;
          char ad[96];
          usnprintf(ad, sizeof(ad), "%s:%lld", rv(p, "ip") ? rv(p, "ip") : "?", rvi(p, "port", 0));
          const char *nm = rvs(p, "name") ? rv(p, "name") : fmt_glyph(&c, G_DASH);
          bool up = rvb(p, "up");
          usnprintf(l, sizeof(l), "  %2lld  %s%*s  %s%*s  %s %s", rvi(p, "n", 0), nm,
                    nw - console_str_width(nm), "", ad, aw - console_str_width(ad), "",
                    fmt_glyph(&c, up ? G_ON : G_ERR), up ? "up" : "down");
          flines_add(&f, up ? RL_NORMAL : RL_WARN, l);
        }
        emit_flines(ui, &f);
        flines_free(&f);
      }
      kind = CF_PICK;
      pick = n;
      usnprintf(q, sizeof(q), "Type the number of the peer to remove:");
    }
    break;
  }
  case PRE_OPT: {
    const char *cur = rv(&rep.res, "flags") ? rv(&rep.res, "flags") : "";
    /* what the hub will store: letters and digits, each once */
    char nf[64] = "";
    size_t o = 0;
    for (const char *p = pc->arg; *p && o + 1 < sizeof(nf); p++)
      if (isalnum((unsigned char)*p) && !strchr(nf, *p)) {
        nf[o++] = *p;
        nf[o] = '\0';
      }
    char changes[256] = "";
    size_t co = 0;
    /* co counts what usnprintf wanted: once it reaches the end nothing more
     * is appended (sizeof - co would wrap) */
    for (const char *p = nf; *p; p++)
      if (!strchr(cur, *p) && co + 1 < sizeof(changes))
        co += (size_t)usnprintf(changes + co, sizeof(changes) - co, "%sadds %c: %s", co ? "; " : "", *p,
                                opt_meaning(*p));
    for (const char *p = cur; *p; p++)
      if (!strchr(nf, *p) && co + 1 < sizeof(changes))
        co += (size_t)usnprintf(changes + co, sizeof(changes) - co, "%sremoves %c: %s", co ? "; " : "",
                                *p, opt_meaning(*p));
    usnprintf(q, sizeof(q), "Change flags %s %s %s%s%s%s? (y/N)", cur[0] ? cur : "none", arrow,
              nf[0] ? nf : "none", co ? " (" : "", changes, co ? ")" : "");
    break;
  }
  case PRE_USER_DEL:
  case PRE_USER_KEY: {
    /* the named user's record (MATCH sends only it), and its masks */
    const crec_t *u = NULL;
    int masks = 0;
    for (int i = 0; i < rep.n; i++) {
      if (!u && !strcmp(rep.r[i].type, "user") && rv(&rep.r[i], "name") &&
          !strcasecmp(rv(&rep.r[i], "name"), pc->arg))
        u = &rep.r[i];
      else if (u && !strcmp(rep.r[i].type, "mask")) masks++;
      else if (u && !strcmp(rep.r[i].type, "user")) break;
    }
    if (!u) {
      ok = false;
      fail_code = "user.not_found";
      usnprintf(fail_msg, sizeof(fail_msg), "no user called \"%s\"", pc->arg);
      usnprintf(fail_hint, sizeof(fail_hint), "user list");
      break;
    }
    const char *name = rv(u, "name") ? rv(u, "name") : pc->arg;
    bool admin = rv(u, "role") && !strcmp(rv(u, "role"), "admin");
    if (pc->pre == PRE_USER_DEL) {
      if (admin) {
        kind = CF_TYPE;
        usnprintf(want, sizeof(want), "%s", name);
        usnprintf(q, sizeof(q), "Type %s to remove admin %s and their %d mask%s:", name, name, masks,
                  masks == 1 ? "" : "s");
      } else {
        usnprintf(q, sizeof(q), "Remove oper %s and their %d mask%s? (y/N)", name, masks,
                  masks == 1 ? "" : "s");
      }
    } else {
      usnprintf(q, sizeof(q), "Replace %s's key %s with the new one?%s (y/N)", name,
                rvs(u, "fp") ? rv(u, "fp") : "(none)", admin ? " Their open consoles close." : "");
    }
    break;
  }
  case PRE_UPG_START: {
    /* the plan card: how many nodes already run the target (D2) */
    const char *bv = pc->arg, *hv = pc->extra[0];
    int b_on = 0, b_to = 0, h_on = 0, h_to = 0;
    for (int i = 0; i < rep.n; i++) {
      const crec_t *nd = &rep.r[i];
      if (strcmp(nd->type, "node")) continue;
      bool bot = rv(nd, "kind") && !strcmp(rv(nd, "kind"), "bot");
      const char *ver = rv(nd, "ver") ? rv(nd, "ver") : "";
      if (bot && !strcmp(ver, bv)) b_on++;
      else if (bot) b_to++;
      else if (hv[0] && !strcmp(ver, hv)) h_on++;
      else h_to++;
    }
    if (!ui->raw) {
      flines_t f = {0};
      fmt_title(&c, &f, "Upgrade plan", NULL);
      char v[512];
      usnprintf(v, sizeof(v), "%s %s   (%d already on it, %d to upgrade)", arrow, bv, b_on, b_to);
      fmt_card_line(&c, &f, 6, "bots", v, RL_NORMAL);
      if (hv[0]) usnprintf(v, sizeof(v), "%s %s   (%d already on it, %d to upgrade)", arrow, hv, h_on, h_to);
      else usnprintf(v, sizeof(v), "stay where they are");
      fmt_card_line(&c, &f, 6, "hubs", v, RL_NORMAL);
      fmt_card_line(&c, &f, 6, "nodes", pc->extra[1][0] ? pc->extra[1] : "whole network", RL_NORMAL);
      usnprintf(v, sizeof(v), "bots: %s %s hubs: %s", pc->extra[2][0] ? pc->extra[2] : "default", dot,
                pc->extra[3][0] ? pc->extra[3] : "default");
      fmt_card_line(&c, &f, 6, "bases", v, RL_NORMAL);
      emit_flines(ui, &f);
      flines_free(&f);
    }
    kind = CF_TYPE;
    usnprintf(want, sizeof(want), "%s", bv);
    usnprintf(q, sizeof(q), "Type %s to start the upgrade:", bv);
    break;
  }
  default:
    usnprintf(q, sizeof(q), "Go ahead? (y/N)");
  }
  creply_free(&rep);
  if (!ok) {
    refuse_hub(ui, rq->seq, fail_code, fail_msg, fail_hint[0] ? fail_hint : NULL);
    audit(ui, LOG_INFO, "[CONSOLE] %s@%s #%d %s -> err: %s", ui->admin, ui->ip, rq->seq,
          pc->rq.audit, fail_code);
    command_done(ui, true);
    return;
  }
  ask_confirm(ui, kind, want, pick, q);
  /* lines typed ahead answer it; then the prompt */
  command_done(ui, true);
}

static void run_line(console_ui_t *ui, const char *line) {
  while (*line == ' ') line++;
  if (!*line) return;
  if (ui->user_busy || ui->confirming) {
    if (ui->queued_n < MAX_QUEUED_LINES) ui->queued[ui->queued_n++] = strdup(line);
    else note(ui, "busy: line dropped", RL_ERR);
    return;
  }
  const char *l = line[0] == '/' ? line + 1 : line;
  int seq = ++ui->seq;
  ui->ncmds++;
  words_t ws;
  split_words(l, &ws);
  if (ws.n == 0) {
    refuse(ui, seq, "cmd.empty", "empty command", NULL);
    return;
  }
  if (!ui->line_mode) {
    char echo[CONSOLE_INPUT_MAX + 4];
    usnprintf(echo, sizeof(echo), "> %s", l);
    fs_timestamped(ui, V_CONSOLE, echo, RL_CMD);
  }
  int argi = 1;
  const cmd_def_t *c = find_cmd(&ws, &argi);
  if (!c) {
    if (cmd_known_word(ws.w[0])) {
      char m[128], h[64];
      if (ws.n >= 2) usnprintf(m, sizeof(m), "%s has no command %.*s", ws.w[0], uprec(ws.w[1], 40), ws.w[1]);
      else usnprintf(m, sizeof(m), "%s needs a command", ws.w[0]);
      usnprintf(h, sizeof(h), "help %s", ws.w[0]);
      refuse(ui, seq, "cmd.usage", m, h);
    } else {
      char m[128];
      usnprintf(m, sizeof(m), "unknown command \"%.*s\"", uprec(ws.w[0], 40), ws.w[0]);
      refuse(ui, seq, "cmd.unknown", m, "help");
    }
    return;
  }
  char words[32];
  usnprintf(words, sizeof(words), "%s%s%s", c->cmd, c->sub ? " " : "", c->sub ? c->sub : "");
  int na = ws.n - argi;
  bool rest_arg = c->build == B_LOCAL && c->sub && !strcmp(c->sub, "filter");
  if (na < c->nargs || (!rest_arg && na > c->nargs + c->optargs)) {
    char m[160];
    usnprintf(m, sizeof(m), "usage: %s", c->usage);
    refuse(ui, seq, "cmd.usage", m, NULL);
    return;
  }
  for (int i = argi; i < ws.n; i++)
    if (c->build != B_LOCAL && strchr(ws.w[i], '|')) {
      refuse(ui, seq, "cmd.bad_arg", "'|' is not allowed in an argument", NULL);
      return;
    }
  if (c->build == B_LOCAL) {
    local_command(ui, c, &ws, argi, l, seq, words);
    return;
  }

  unsigned char payload[1024];
  size_t plen = 0;
  const char *why = NULL, *hint = NULL;
  uint8_t op = c->op;
  confirm_t confirm = c->confirm;
  int mode = FMT_MODE_NORMAL;
  if (!build_payload(ui, c, &ws, argi, payload, &plen, &op, &confirm, &mode, &why, &hint)) {
    refuse(ui, seq, "cmd.bad_arg", why ? why : "bad arguments", hint);
    return;
  }

  pending_rq_t rq;
  memset(&rq, 0, sizeof(rq));
  rq.kind = RQ_USER;
  rq.seq = seq;
  rq.mode = mode;
  usnprintf(rq.words, sizeof(rq.words), "%s", words);
  usnprintf(rq.audit, sizeof(rq.audit), "%.*s", uprec(l, 300), l);
  rq.audit_level = (confirm != CF_NONE || op == CMD_ADMIN_SET_LOG_LEVEL) ? LOG_WARNING : LOG_INFO;

  const char *a1 = na > 0 ? ws.w[argi] : "";
  if (confirm == CF_NONE) {
    send_request(ui, op, payload, plen, &rq);
    return;
  }

  /* D2: read first, so the question names the object */
  if (c->pre != PRE_NONE) {
    pend_cmd_t *pc = &ui->pend;
    memset(pc, 0, sizeof(*pc));
    pc->pre = c->pre;
    pc->op = op;
    memcpy(pc->payload, payload, plen);
    pc->len = plen;
    pc->rq = rq;
    usnprintf(pc->arg, sizeof(pc->arg), "%s", a1);
    uint8_t pop = 0;
    char pp[600] = "";
    switch (c->pre) {
    case PRE_BOT_DEL:
    case PRE_BOT_KICK:
      pop = CMD_ADMIN_LIST_FULL;
      usnprintf(pp, sizeof(pp), "%s", a1);
      break;
    case PRE_PEER_DEL:
      pop = CMD_ADMIN_LIST_PEERS;
      break;
    case PRE_OPT:
      pop = CMD_ADMIN_GET_OPT_FLAGS;
      usnprintf(pc->arg, sizeof(pc->arg), "%s", strcmp(a1, "-") ? a1 : "");
      break;
    case PRE_USER_DEL:
    case PRE_USER_KEY:
      pop = CMD_ADMIN_MATCH;
      usnprintf(pp, sizeof(pp), "%s", a1);
      break;
    case PRE_UPG_START: {
      pop = CMD_ADMIN_UPGRADE_STATUS;
      const char *bb = "", *hb = "";
      for (int i = argi + 1; i < ws.n; i++) {
        const char *v;
        if ((v = kv_opt(ws.w[i], "hub"))) usnprintf(pc->extra[0], sizeof(pc->extra[0]), "%s", strcmp(v, "-") ? v : "");
        else if ((v = kv_opt(ws.w[i], "nodes"))) usnprintf(pc->extra[1], sizeof(pc->extra[1]), "%s", v);
        else if ((v = kv_opt(ws.w[i], "botbase"))) bb = v;
        else if ((v = kv_opt(ws.w[i], "hubbase"))) hb = v;
      }
      usnprintf(pc->extra[2], sizeof(pc->extra[2]), "%s", bb);
      usnprintf(pc->extra[3], sizeof(pc->extra[3]), "%s", hb);
      if (*bb || *hb) usnprintf(pp, sizeof(pp), "releases|%s|%s", bb, hb);
      else usnprintf(pp, sizeof(pp), "releases");
      break;
    }
    }
    pending_rq_t pr = rq;
    pr.kind = RQ_PRE;
    send_request(ui, pop, pp, strlen(pp), &pr);
    return;
  }

  /* Ask first; the next line answers. */
  stage_confirm(ui, seq, op, payload, plen, &rq);
  char q[CONSOLE_INPUT_MAX - 64];
  char want[128] = "";
  confirm_t kind = CF_YN;
  const char *a2 = na > 1 ? ws.w[argi + 1] : "";
  if (op == CMD_ADMIN_REGEN_KEYS) {
    const char *hn = ui->hubname[0] ? ui->hubname : "hub";
    char l1[160];
    usnprintf(l1, sizeof(l1), "hub rekey makes a new identity for %s.", hn);
    const char *lines[3] = {l1,
                            "Every peer and bot link drops now; each peer runs peer set <uuid> key, each bot +hub with the new key.",
                            "Back up .irchub.cnf first: the old key is overwritten."};
    warn_lines(ui, lines, 3);
    kind = CF_TYPE;
    usnprintf(want, sizeof(want), "%s", hn);
    usnprintf(q, sizeof(q), "Type %s to go ahead:", hn);
  } else if (op == CMD_ADMIN_PURGE_TOMBSTONES) {
    if (!strcasecmp(a1, "now")) usnprintf(q, sizeof(q), "Purge every tombstone now, here and on all peers? (y/N)");
    else usnprintf(q, sizeof(q), "Purge tombstones older than %s days, here and on all peers? (y/N)", a1);
  } else if (op == CMD_ADMIN_DEL_ALLOWLIST || op == CMD_ADMIN_DEL_DENYLIST) {
    usnprintf(q, sizeof(q), "Remove %s from the %s list? (y/N)", a2,
              op == CMD_ADMIN_DEL_ALLOWLIST ? "allow" : "deny");
  } else if (op == CMD_ADMIN_SET_LOG_LEVEL) {
    int lvl = level_arg(a2);
    usnprintf(q, sizeof(q), "Set the %s log level to %s? (y/N)", payload[0] ? "console" : "file",
              lvl >= 0 && lvl <= 4 ? LEVEL_WORD[lvl] : a2);
  } else if (op == CMD_ADMIN_DEL_USERMASK) {
    usnprintf(q, sizeof(q), "Remove mask %s from %s? (y/N)", na > 2 ? ws.w[argi + 2] : "", a2);
  } else if (op == CMD_ADMIN_DEL_CHANNEL) {
    usnprintf(q, sizeof(q), "Remove %s from every bot? They part it. (y/N)", a1);
  } else if (op == CMD_ADMIN_UPGRADE_STATUS && !strcmp(c->sub, "abort")) {
    usnprintf(q, sizeof(q), "Abort the running upgrade and roll back what it moved? (y/N)");
  } else if (op == CMD_ADMIN_UPGRADE_STATUS && !strcmp(c->sub, "forget")) {
    usnprintf(q, sizeof(q), "Forget the roll-up plan here and on every hub? (y/N)");
  } else {
    usnprintf(q, sizeof(q), "Really %s? (y/N)", words);
  }
  ask_confirm(ui, kind, want, 0, q);
}

static void confirm_answer(console_ui_t *ui, const char *answer, bool cancelled) {
  confirm_t kind = ui->confirming;
  ui->confirming = CF_NONE;
  bool ok = !cancelled;
  if (ok) {
    if (kind == CF_YN) {
      ok = !strcasecmp(answer, "y") || !strcasecmp(answer, "yes");
    } else if (kind == CF_PICK) {
      ok = all_digits(answer) && atoi(answer) >= 1 && atoi(answer) <= ui->confirm_pick_max;
      if (ok) ui->confirm_len = (size_t)usnprintf((char *)ui->confirm_payload,
                                                  sizeof(ui->confirm_payload), "%d", atoi(answer));
    } else {
      ok = !strcmp(answer, ui->confirm_want);
    }
  }
  if (!ok) {
    refuse(ui, ui->confirm_seq, "cmd.cancelled", "cancelled", NULL);
    audit(ui, LOG_INFO, "[CONSOLE] %s@%s #%d %s -> cancelled", ui->admin, ui->ip,
          ui->confirm_seq, ui->confirm_rq.audit);
    secure_wipe(ui->confirm_payload, sizeof(ui->confirm_payload));
    command_done(ui, false);
    return;
  }
  send_request(ui, ui->confirm_op, ui->confirm_payload, ui->confirm_len,
               &ui->confirm_rq);
  secure_wipe(ui->confirm_payload, sizeof(ui->confirm_payload));
}

/* ==========================================================================
 * Input line
 * ========================================================================== */
static void hist_add(console_ui_t *ui, const char *line) {
  if (!*line) return;
  if (ui->hist_n > 0 && !strcmp(ui->hist[ui->hist_n - 1], line)) return;
  if (ui->hist_n == CONSOLE_HISTORY) {
    free(ui->hist[0]);
    memmove(ui->hist, ui->hist + 1, sizeof(char *) * (CONSOLE_HISTORY - 1));
    ui->hist_n--;
  }
  ui->hist[ui->hist_n++] = strdup(line);
}

static void in_set(console_ui_t *ui, const char *s) {
  usnprintf(ui->in, sizeof(ui->in), "%s", s);
  ui->in_len = (int)strlen(ui->in);
  ui->in_cur = ui->in_len;
}

static void in_insert(console_ui_t *ui, const char *bytes, int n) {
  if (ui->in_len + n >= (int)sizeof(ui->in)) return;
  memmove(ui->in + ui->in_cur + n, ui->in + ui->in_cur, (size_t)(ui->in_len - ui->in_cur));
  memcpy(ui->in + ui->in_cur, bytes, (size_t)n);
  ui->in_len += n;
  ui->in_cur += n;
  ui->in[ui->in_len] = '\0';
  if (ui->line_mode) cbuf_add(&ui->term, bytes, (size_t)n);   /* echo */
}

/* Start of the character before byte offset `at`. */
static int prev_char(const char *s, int at) {
  int i = at - 1;
  while (i > 0 && ((unsigned char)s[i] & 0xC0) == 0x80) i--;
  return i < 0 ? 0 : i;
}

static int next_char_off(const char *s, int len, int at) {
  int i = at + 1;
  while (i < len && ((unsigned char)s[i] & 0xC0) == 0x80) i++;
  return i > len ? len : i;
}

static void in_delete(console_ui_t *ui, int from, int to) {
  if (from >= to) return;
  memmove(ui->in + from, ui->in + to, (size_t)(ui->in_len - to));
  ui->in_len -= to - from;
  ui->in[ui->in_len] = '\0';
  if (ui->in_cur > to) ui->in_cur -= to - from;
  else if (ui->in_cur > from) ui->in_cur = from;
}

static void in_backspace(console_ui_t *ui) {
  if (ui->in_cur == 0) return;
  int p = prev_char(ui->in, ui->in_cur);
  in_delete(ui, p, ui->in_cur);
  if (ui->line_mode) cbuf_adds(&ui->term, "\b \b");
}

/* What Tab offers for one argument of a command (docs/console.md §2). */
enum ck { CK_NONE, CK_GROUP, CK_WORDS, CK_BOT, CK_BOT_ON, CK_BOT_NICK, CK_HUB_NAME };

typedef struct {
  const char *cmd, *sub;
  int         pos;   /* argument index after cmd [sub]; -1 = any */
  enum ck     kind;
  const char *words; /* CK_WORDS: space separated */
} arg_comp_t;

#define LEVEL_WORDS "none error warning info debug"
static const arg_comp_t ARG_COMP[] = {
  {"help", NULL, 0, CK_GROUP, NULL},
  {"bot", "show", 0, CK_BOT_NICK, NULL},
  {"bot", "del", 0, CK_BOT, NULL},
  {"bot", "kick", 0, CK_BOT_ON, NULL},
  {"bot", "rekey", 0, CK_BOT, NULL},
  {"peer", "show", 0, CK_HUB_NAME, NULL},
  {"peer", "set", 0, CK_HUB_NAME, NULL},
  {"peer", "set", 1, CK_WORDS, "key"},
  {"hub", "set", 0, CK_WORDS, "name bindip port pubkey autopurge"},
  {"hub", "purge", 0, CK_WORDS, "now"},
  {"log", "set", 0, CK_WORDS, "file console size"},
  {"log", "set", 1, CK_WORDS, LEVEL_WORDS}, /* after file|console */
  {"log", "on", 0, CK_WORDS, LEVEL_WORDS},
  {"log", "filter", 0, CK_WORDS, "clear"},
  {"acl", "add", 0, CK_WORDS, "allow deny"},
  {"acl", "del", 0, CK_WORDS, "allow deny"},
  {"user", "list", 0, CK_WORDS, "admin oper"},
  {"user", "add", 0, CK_WORDS, "admin oper"},
  {"user", "set", 1, CK_WORDS, "key"},
  {"user", "mask", 0, CK_WORDS, "add del"},
  {"channel", "set", 1, CK_WORDS, "key"},
  {"upgrade", "releases", -1, CK_WORDS, "bot= hub="},
  {"upgrade", "start", -1, CK_WORDS, "hub= nodes= botbase= hubbase="},
  {"display", "view", 0, CK_WORDS, "1 2 3 4 5"},
  {"display", "format", 0, CK_WORDS, "pretty raw"},
  {"display", "width", 0, CK_WORDS, "auto"},
  {"display", "events", 0, CK_WORDS, "on off"},
};
#define NARGCOMP ((int)(sizeof(ARG_COMP) / sizeof(ARG_COMP[0])))

static bool cmd_has_subs(const char *cmd) {
  for (int i = 0; i < NCMDS; i++)
    if (CMDS[i].sub && !strcasecmp(CMDS[i].cmd, cmd)) return true;
  return false;
}

/* Tab candidates for the word at word_idx; w[0..word_idx-1] are the words
 * before it (w[0] without its '/').  Arguments only complete where a command
 * takes a known kind of value: never a bot or hub name in place of an ip, a
 * pubkey or an admin name. */
static int completions(console_ui_t *ui, int word_idx, char w[][64],
                       const char *prefix, const char **out, int max,
                       char pool[][72], int *pooln) {
  int n = 0;
  size_t pl = strlen(prefix);
#define ADD_CAND(s)                                                         \
  do {                                                                      \
    bool dup_ = false;                                                      \
    for (int k_ = 0; k_ < n; k_++) dup_ |= !strcmp(out[k_], (s));           \
    if (!dup_ && n < max && !strncasecmp((s), prefix, pl)) out[n++] = (s);  \
  } while (0)
  if (word_idx == 0) {
    for (int i = 0; i < NCMDS; i++) ADD_CAND(CMDS[i].cmd);
    return n;
  }
  if (!strcmp(w[0], "?")) usnprintf(w[0], 64, "help");
  /* help <group> <command> */
  if (!strcasecmp(w[0], "help") && word_idx == 2) {
    for (int i = 0; i < NCMDS; i++)
      if (CMDS[i].sub && !strcasecmp(CMDS[i].cmd, w[1])) ADD_CAND(CMDS[i].sub);
    return n;
  }
  bool subs = cmd_has_subs(w[0]);
  if (word_idx == 1 && subs) {
    for (int i = 0; i < NCMDS; i++)
      if (CMDS[i].sub && !strcasecmp(CMDS[i].cmd, w[0])) ADD_CAND(CMDS[i].sub);
    return n;
  }
  /* which command, and which of its arguments */
  const char *sub = NULL;
  int pos = word_idx - 1;
  if (subs) {
    for (int i = 0; i < NCMDS; i++)
      if (CMDS[i].sub && !strcasecmp(CMDS[i].cmd, w[0]) && !strcasecmp(CMDS[i].sub, w[1]))
        sub = CMDS[i].sub;
    if (!sub) return 0;
    pos--;
  }
  if (!strcasecmp(w[0], "log") && sub && !strcmp(sub, "set") && pos == 1 &&
      strcasecmp(w[2], "file") && strcasecmp(w[2], "console"))
    return 0;
  const arg_comp_t *ac = NULL;
  for (int i = 0; i < NARGCOMP && !ac; i++)
    if (!strcasecmp(ARG_COMP[i].cmd, w[0]) &&
        (ARG_COMP[i].sub ? sub && !strcmp(ARG_COMP[i].sub, sub) : !sub) &&
        (ARG_COMP[i].pos < 0 || ARG_COMP[i].pos == pos))
      ac = &ARG_COMP[i];
  if (!ac) return 0;
  if (ac->kind == CK_GROUP) {
    for (int i = 0; i < NGROUPS; i++) ADD_CAND(GROUPS[i].name);
    return n;
  }
  if (ac->kind == CK_WORDS) {
    for (const char *p = ac->words; *p && *pooln < 128;) {
      size_t l = strcspn(p, " ");
      usnprintf(pool[*pooln], 72, "%.*s", (int)l, p);
      size_t before = (size_t)n;
      ADD_CAND(pool[*pooln]);
      if ((size_t)n > before) (*pooln)++;
      p += l;
      while (*p == ' ') p++;
    }
    return n;
  }
  /* uuids (and for show / peer set, names) from the tree rows:
   * H|depth|name|uuid|..., B|depth|nick|uuid|..., D|nick|uuid|... (offline) */
  for (const char *p = ui->tree; p && *p && n < max && *pooln < 128;) {
    const char *nl = strchr(p, '\n');
    size_t ll = nl ? (size_t)(nl - p) : strlen(p);
    char row[TREE_ROW_MAX + 1];
    if (ll < sizeof(row)) {
      memcpy(row, p, ll);
      row[ll] = '\0';
      char *f[10];
      int nf = 0;
      char *save = NULL;
      for (char *t = strtok_r(row, "|", &save); t && nf < 10; t = strtok_r(NULL, "|", &save))
        f[nf++] = t;
      const char *cand[2] = {NULL, NULL};
      char ty = nf ? f[0][0] : 0;
      if (ac->kind == CK_HUB_NAME && ty == 'H' && nf >= 4 && strcmp(f[1], "0")) {
        cand[0] = f[2];
        cand[1] = f[3];
      } else if ((ac->kind == CK_BOT || ac->kind == CK_BOT_ON || ac->kind == CK_BOT_NICK) &&
                 ty == 'B' && nf >= 4) {
        cand[0] = f[3];
        if (ac->kind == CK_BOT_NICK) cand[1] = f[2];
      } else if ((ac->kind == CK_BOT || ac->kind == CK_BOT_NICK) && ty == 'D' && nf >= 3) {
        cand[0] = f[2];
        if (ac->kind == CK_BOT_NICK) cand[1] = f[1];
      }
      for (int k = 0; k < 2 && *pooln < 128; k++) {
        if (!cand[k] || !strcmp(cand[k], "-")) continue;
        usnprintf(pool[*pooln], 72, "%s", cand[k]);
        size_t before = (size_t)n;
        ADD_CAND(pool[*pooln]);
        if ((size_t)n > before) (*pooln)++;
      }
    }
    p = nl ? nl + 1 : NULL;
  }
  return n;
#undef ADD_CAND
}

static void complete(console_ui_t *ui) {
  int ws = ui->in_cur;
  while (ws > 0 && ui->in[ws - 1] != ' ') ws--;
  char prefix[CONSOLE_INPUT_MAX];
  usnprintf(prefix, sizeof(prefix), "%.*s", ui->in_cur - ws, ui->in + ws);
  /* the words before this one (the first without its '/') */
  char w[3][64] = {"", "", ""};
  int idx = 0;
  for (int i = 0; i < ws;) {
    while (i < ws && ui->in[i] == ' ') i++;
    if (i >= ws) break;
    int s = i;
    while (i < ws && ui->in[i] != ' ') i++;
    if (idx < 3) {
      int skip = (idx == 0 && ui->in[s] == '/') ? 1 : 0;
      usnprintf(w[idx], sizeof(w[0]), "%.*s", i - s - skip, ui->in + s + skip);
    }
    idx++;
  }
  const char *pfx = (idx == 0 && prefix[0] == '/') ? prefix + 1 : prefix;
  const char *out[64];
  char pool[128][72];
  int pooln = 0;
  int n = completions(ui, idx, w, pfx, out, 64, pool, &pooln);
  if (n == 0) return;
  size_t common = strlen(out[0]);
  for (int i = 1; i < n; i++) {
    size_t k = 0;
    while (k < common && out[i][k] && tolower((unsigned char)out[i][k]) ==
                                        tolower((unsigned char)out[0][k]))
      k++;
    common = k;
  }
  size_t have = strlen(pfx);
  if (common > have || n == 1) {
    /* a key= option takes its value right after the '=' */
    bool space = n == 1 && out[0][strlen(out[0]) - 1] != '=';
    char add[128];
    usnprintf(add, sizeof(add), "%.*s%s", (int)(common - have), out[0] + have,
             space ? " " : "");
    in_insert(ui, add, (int)strlen(add));
  } else if (!ui->line_mode) {
    char line[512] = "";
    size_t o = 0;
    for (int i = 0; i < n && o + 2 < sizeof(line); i++)
      o += (size_t)usnprintf(line + o, sizeof(line) - o, "%s%s", i ? "  " : "", out[i]);
    note(ui, line, RL_RULE);
  }
  ui->dirty = true;
}

static void on_enter(console_ui_t *ui) {
  char line[CONSOLE_INPUT_MAX];
  usnprintf(line, sizeof(line), "%s", ui->in);
  ui->in_len = ui->in_cur = ui->in_scroll = 0;
  ui->in[0] = '\0';
  ui->hist_pos = ui->hist_n;
  if (ui->line_mode) cbuf_add(&ui->term, "\r\n", 2);

  if (ui->searching) {
    ui->searching = false;
    usnprintf(ui->search, sizeof(ui->search), "%.*s", uprec(line, 127), line);
    ui->dirty = true;
    return;
  }
  if (ui->confirming) {
    confirm_answer(ui, line, false);
  } else {
    const char *l = line;
    while (*l == ' ') l++;
    if (!*l) {
      if (ui->line_mode) lm_prompt(ui);
      return;
    }
    hist_add(ui, line);
    ui->hist_pos = ui->hist_n; /* after the add: Up must land on this line */
    run_line(ui, line);
  }
  if (ui->line_mode && !ui->closing) {
    if (!ui->user_busy && !ui->confirming) flush_held(ui);
    if (!ui->user_busy) lm_prompt(ui);
  }
  ui->dirty = true;
}

static void cancel_input(console_ui_t *ui) {
  if (ui->line_mode) cbuf_adds(&ui->term, "^C\r\n");
  ui->in_len = ui->in_cur = ui->in_scroll = 0;
  ui->in[0] = '\0';
  if (ui->searching) {
    ui->searching = false;
  } else if (ui->confirming) {
    confirm_answer(ui, "", true);
  }
  if (ui->line_mode && !ui->user_busy) {
    flush_held(ui);
    lm_prompt(ui);
  }
  ui->dirty = true;
}

/* Log view search: move the anchor to the next/previous line containing the
 * search text. */
static bool log_line_visible(const console_ui_t *ui, const sline_t *l);

static void search_step(console_ui_t *ui, int dir) {
  if (!ui->search[0]) return;
  sback_t *sb = &ui->sb[V_LOG];
  long long cur = ui->anchor[V_LOG] < 0 ? sb->next - 1 : ui->anchor[V_LOG];
  for (long long s = cur + dir; s >= sb->first && s < sb->next; s += dir) {
    const sline_t *l = sb_get(sb, s);
    if (l && l->text && log_line_visible(ui, l) && ci_contains(l->text, ui->search)) {
      ui->anchor[V_LOG] = s;
      ui->dirty = true;
      return;
    }
  }
}

static void scroll_view(console_ui_t *ui, int dir);

static void set_view(console_ui_t *ui, int v, long long now_ms) {
  ui->view = (v + V_COUNT) % V_COUNT;
  ui->act[ui->view] = false;
  if (ui->view == V_UPG) request_view(ui, RQ_VIEW_UPG, now_ms);
  if (ui->view == V_STATS) request_view(ui, RQ_VIEW_STATS, now_ms);
  ui->dirty = true;
}

static void net_rows_count(const console_ui_t *ui, int *n);

static void handle_key(console_ui_t *ui, ckey_t k, long long now_ms) {
  if (ui->line_mode) {
    switch (k.type) {
    case K_CHAR: {
      unsigned char b[4];
      int n = 0;
      unsigned cp = k.cp;
      if (cp < 0x80) b[n++] = (unsigned char)cp;
      else if (cp < 0x800) { b[n++] = (unsigned char)(0xC0 | (cp >> 6)); b[n++] = (unsigned char)(0x80 | (cp & 0x3F)); }
      else if (cp < 0x10000) { b[n++] = (unsigned char)(0xE0 | (cp >> 12)); b[n++] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F)); b[n++] = (unsigned char)(0x80 | (cp & 0x3F)); }
      else { b[n++] = (unsigned char)(0xF0 | (cp >> 18)); b[n++] = (unsigned char)(0x80 | ((cp >> 12) & 0x3F)); b[n++] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F)); b[n++] = (unsigned char)(0x80 | (cp & 0x3F)); }
      in_insert(ui, (const char *)b, n);
      break;
    }
    case K_ENTER: on_enter(ui); break;
    case K_BS: in_backspace(ui); break;
    case K_TAB: in_insert(ui, " ", 1); break;
    case K_CTRL:
      if (k.cp == 'c') cancel_input(ui);
      else if (k.cp == 'd' && ui->in_len == 0) {
        in_set(ui, "quit");
        cbuf_adds(&ui->term, "quit");
        on_enter(ui);
      }
      break;
    default: break;
    }
    return;
  }

  bool empty = ui->in_len == 0;
  ui->dirty = true;
  switch (k.type) {
  case K_CHAR: {
    if (empty && !ui->searching && !ui->confirming && ui->view == V_LOG) {
      if (k.cp == ' ') {
        ui->paused = !ui->paused;
        ui->paused_next = ui->sb[V_LOG].next;
        return;
      }
      if (k.cp == '/') {
        ui->searching = true;
        return;
      }
      if (k.cp == 'n' || k.cp == 'N') {
        search_step(ui, k.cp == 'n' ? -1 : 1);
        return;
      }
    }
    unsigned char b[4];
    int n = 0;
    unsigned cp = k.cp;
    if (cp < 0x80) b[n++] = (unsigned char)cp;
    else if (cp < 0x800) { b[n++] = (unsigned char)(0xC0 | (cp >> 6)); b[n++] = (unsigned char)(0x80 | (cp & 0x3F)); }
    else if (cp < 0x10000) { b[n++] = (unsigned char)(0xE0 | (cp >> 12)); b[n++] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F)); b[n++] = (unsigned char)(0x80 | (cp & 0x3F)); }
    else { b[n++] = (unsigned char)(0xF0 | (cp >> 18)); b[n++] = (unsigned char)(0x80 | ((cp >> 12) & 0x3F)); b[n++] = (unsigned char)(0x80 | ((cp >> 6) & 0x3F)); b[n++] = (unsigned char)(0x80 | (cp & 0x3F)); }
    in_insert(ui, (const char *)b, n);
    break;
  }
  case K_ENTER: on_enter(ui); break;
  case K_BS: in_backspace(ui); break;
  case K_DEL:
    if (ui->in_cur < ui->in_len)
      in_delete(ui, ui->in_cur, next_char_off(ui->in, ui->in_len, ui->in_cur));
    break;
  case K_LEFT: if (ui->in_cur > 0) ui->in_cur = prev_char(ui->in, ui->in_cur); break;
  case K_RIGHT: if (ui->in_cur < ui->in_len) ui->in_cur = next_char_off(ui->in, ui->in_len, ui->in_cur); break;
  case K_HOME: ui->in_cur = 0; break;
  case K_END:
    if (empty || ui->in_cur == ui->in_len) {
      ui->anchor[ui->view] = -1;
      if (ui->view == V_LOG) ui->paused = false;
    }
    ui->in_cur = ui->in_len;
    break;
  case K_UP:
  case K_DOWN:
    if (ui->view == V_NET && empty) {
      int n = 0;
      net_rows_count(ui, &n);
      ui->net_sel += k.type == K_UP ? -1 : 1;
      if (ui->net_sel >= n) ui->net_sel = n - 1;
      if (ui->net_sel < 0) ui->net_sel = 0;
      break;
    }
    if (k.type == K_UP && ui->hist_pos > 0) {
      if (ui->hist_pos == ui->hist_n) usnprintf(ui->hist_stash, sizeof(ui->hist_stash), "%s", ui->in);
      in_set(ui, ui->hist[--ui->hist_pos]);
    } else if (k.type == K_DOWN && ui->hist_pos < ui->hist_n) {
      ui->hist_pos++;
      in_set(ui, ui->hist_pos == ui->hist_n ? ui->hist_stash : ui->hist[ui->hist_pos]);
    }
    break;
  case K_PGUP: scroll_view(ui, -1); break;
  case K_PGDN: scroll_view(ui, 1); break;
  case K_TAB: complete(ui); break;
  case K_F:
    if (k.cp == 2) {
      ui->log_show = ui->log_show <= LOG_ERROR ? LOG_DEBUG : ui->log_show - 1;
    } else if (k.cp == 3) {
      if (ui->cols >= CONSOLE_PANE_MIN_COLS) ui->pane_user_off = !ui->pane_user_off;
      else ui->overlay = !ui->overlay;
    }
    break;
  case K_ALT:
    if (k.cp >= '1' && k.cp <= '5') set_view(ui, (int)(k.cp - '1'), now_ms);
    break;
  case K_ALT_LEFT: set_view(ui, ui->view - 1, now_ms); break;
  case K_ALT_RIGHT: set_view(ui, ui->view + 1, now_ms); break;
  case K_ESC:
    if (ui->searching) ui->searching = false;
    ui->overlay = false;
    break;
  case K_CTRL:
    switch (k.cp) {
    case 'c': cancel_input(ui); break;
    case 'l': ui->full_redraw = true; break;
    case 'u': in_delete(ui, 0, ui->in_cur); break;
    case 'a': ui->in_cur = 0; break;
    case 'e': ui->in_cur = ui->in_len; break;
    case 'w': {
      int p = ui->in_cur;
      while (p > 0 && ui->in[p - 1] == ' ') p--;
      while (p > 0 && ui->in[p - 1] != ' ') p--;
      in_delete(ui, p, ui->in_cur);
      break;
    }
    }
    break;
  default: break;
  }
}

static void feed_char(console_ui_t *ui, unsigned cp, long long now_ms) {
  ckey_t k = {K_CHAR, cp};
  if (ui->pasting && (cp == '\r' || cp == '\n' || cp == '\t')) k.cp = ' ';
  handle_key(ui, k, now_ms);
}

static void feed_seq(console_ui_t *ui, const unsigned char *s, size_t n, long long now_ms) {
  /* s[0] == ESC */
  ckey_t k = {K_NONE, 0};
  if (n == 2) {
    unsigned char c = s[1];
    k.type = K_ALT;
    k.cp = c;
  } else if (n >= 3 && s[1] == 0x1b) {        /* ESC ESC [ D: Alt+arrow */
    ckey_t in = decode_seq(s + 2, n - 2);
    if (in.type == K_LEFT) k.type = K_ALT_LEFT;
    else if (in.type == K_RIGHT) k.type = K_ALT_RIGHT;
    else k = in;
  } else {
    k = decode_seq(s + 1, n - 1);
  }
  if (k.type == K_PASTE_BEGIN) { ui->pasting = true; return; }
  if (k.type == K_PASTE_END) { ui->pasting = false; return; }
  if (k.type != K_NONE) handle_key(ui, k, now_ms);
}

void ui_input(console_ui_t *ui, const unsigned char *data, size_t n, long long now_ms) {
  ui->last_input_ms = now_ms;
  ui->now_ms = now_ms;
  for (size_t i = 0; i < n; i++) {
    unsigned char b = data[i];
    if (ui->esc_len > 0) {
      if (ui->esc_len < (int)sizeof(ui->esc)) ui->esc[ui->esc_len++] = b;
      int done;
      if (ui->esc_len >= 2 && ui->esc[1] == 0x1b) {
        /* ESC ESC ...: the inner sequence decides */
        int inner = ui->esc_len >= 3 ? seq_complete(ui->esc + 1, (size_t)ui->esc_len - 1) : 0;
        done = inner > 0 ? inner + 1 : inner;
        if (ui->esc_len == 2) done = 0;
      } else {
        done = seq_complete(ui->esc, (size_t)ui->esc_len);
      }
      if (done > 0) {
        feed_seq(ui, ui->esc, (size_t)done, now_ms);
        ui->esc_len = 0;
      } else if (done < 0 || ui->esc_len >= (int)sizeof(ui->esc)) {
        ui->esc_len = 0;               /* garbage: dropped */
      }
      continue;
    }
    if (ui->utf8_len > 0) {
      ui->utf8[ui->utf8_len++] = b;
      size_t need = (ui->utf8[0] >= 0xF0) ? 4 : (ui->utf8[0] >= 0xE0) ? 3 : 2;
      if ((size_t)ui->utf8_len == need) {
        size_t ul = console_utf8_len(ui->utf8, need);
        if (ul == need) {
          unsigned cp = utf8_cp(ui->utf8, need);
          if (!(cp >= 0x80 && cp <= 0x9F)) feed_char(ui, cp, now_ms);
        }
        ui->utf8_len = 0;
      }
      continue;
    }
    if (b == 0x1b) {
      ui->esc[0] = b;
      ui->esc_len = 1;
      ui->esc_ms = now_ms;
      continue;
    }
    bool was_cr = ui->last_cr;
    ui->last_cr = (b == '\r');
    if (b == '\r' || b == '\n') {
      if (b == '\n' && was_cr) continue;          /* CRLF = one Enter */
      if (ui->pasting) feed_char(ui, ' ', now_ms);
      else handle_key(ui, (ckey_t){K_ENTER, 0}, now_ms);
    } else if (b == 0x7f || b == 0x08) {
      handle_key(ui, (ckey_t){K_BS, 0}, now_ms);
    } else if (b == '\t') {
      if (ui->pasting) feed_char(ui, ' ', now_ms);
      else handle_key(ui, (ckey_t){K_TAB, 0}, now_ms);
    } else if (b < 0x20) {
      if (!ui->pasting) handle_key(ui, (ckey_t){K_CTRL, (unsigned)('a' + b - 1)}, now_ms);
    } else if (b < 0x80) {
      feed_char(ui, b, now_ms);
    } else if (b >= 0xC2 && b <= 0xF4) {
      ui->utf8[0] = b;
      ui->utf8_len = 1;
    }
    if (ui->closing) return;
  }
}

/* ==========================================================================
 * Full-screen renderer
 * ========================================================================== */
#define SGR_RESET  "0"
#define SGR_TITLE  "0;1;36"
#define SGR_LINE   "0;36"
#define SGR_STATUS "0;37;44"
#define SGR_ALERT  "0;1;37;41"
#define SGR_WARNBG "0;1;33;44"
#define SGR_SEL    "0;7"

static const char *kind_sgr(int kind) {
  switch (kind) {
  case RL_CMD:   return "0;1";
  case RL_ERR:   return "0;31";
  case RL_OK:    return "0;32";
  case RL_TITLE: return "0;1;36";
  case RL_RULE:  return "0;36";
  case RL_HEAD:  return "0;1";
  case RL_WARN:  return "0;33";
  case RL_DIM:   return "0;90";
  default:       return SGR_RESET;
  }
}

/* Box drawing, or its ASCII stand-in (/ascii). */
static const char *G(const console_ui_t *ui, const char *utf8) {
  if (!ui->ascii) return utf8;
  if (!strcmp(utf8, "│")) return "|";
  if (!strcmp(utf8, "─")) return "-";
  if (!strcmp(utf8, "┬")) return "+";
  if (!strcmp(utf8, "▾")) return "v";
  if (!strcmp(utf8, "├")) return "|";
  if (!strcmp(utf8, "└")) return "`";
  if (!strcmp(utf8, "●")) return "*";
  if (!strcmp(utf8, "○")) return "o";
  return "?";
}

typedef struct {
  cbuf_t b;
  int    w;        /* cells used */
  int    max;      /* cells allowed */
  bool   ascii;    /* display ascii: non-ASCII through fmt_ascii_char */
} rowb_t;

static void rb_start(rowb_t *r, int max) {
  r->b.len = 0;
  r->w = 0;
  r->max = max;
}

static void rb_sgr(rowb_t *r, const char *sgr) {
  cbuf_adds(&r->b, "\x1b[");
  cbuf_adds(&r->b, sgr);
  cbuf_add(&r->b, "m", 1);
}

/* Append sanitized text, at most `cells` cells (and never past the row). */
static void rb_text(rowb_t *r, const char *s, int cells) {
  size_t n = strlen(s);
  int lim = r->max - r->w;
  if (cells >= 0 && cells < lim) lim = cells;
  int used = 0;
  for (size_t i = 0; i < n;) {
    unsigned cp;
    int cw;
    size_t ul = next_char(s + i, n - i, &cp, &cw);
    const char *a = NULL;
    if (r->ascii && (unsigned char)s[i] >= 0x80) {
      size_t al;
      a = fmt_ascii_char(s + i, n - i, &al);
      if (a) cw = (int)strlen(a);
    }
    if (used + cw > lim) break;
    if (a) cbuf_adds(&r->b, a);
    else cbuf_add(&r->b, s + i, ul);
    used += cw;
    i += ul;
  }
  r->w += used;
}

static void rb_fill(rowb_t *r, const char *glyph, int n) {
  for (int i = 0; i < n && r->w < r->max; i++) {
    cbuf_adds(&r->b, glyph);
    r->w++;
  }
}

static void rb_pad(rowb_t *r, int upto) {
  if (upto > r->max) upto = r->max;
  while (r->w < upto) {
    cbuf_add(&r->b, " ", 1);
    r->w++;
  }
}

/* Text right-aligned in a field of `width` cells. */
static void rb_right(rowb_t *r, const char *s, int width) {
  int sw = str_width(s);
  if (sw > width) sw = width;
  rb_pad(r, r->w + (width - sw));
  rb_text(r, s, width);
}

/* Copy a (sanitized) field into dst[cap]: at most cap-1 bytes, never
 * splitting a UTF-8 character, so a cut field still renders cleanly. */
static void copy_field(char *dst, size_t cap, const char *src) {
  size_t n = strlen(src), o = 0;
  if (cap == 0) return;
  while (o < n) {
    size_t ul = console_utf8_len((const unsigned char *)src + o, n - o);
    if (!ul) ul = 1;
    if (o + ul > cap - 1) break;
    o += ul;
  }
  memcpy(dst, src, o);
  dst[o] = '\0';
}

static int parse_tree(const char *tree, trow_t *out, int max) {
  int n = 0;
  for (const char *p = tree; p && *p && n < max;) {
    const char *nl = strchr(p, '\n');
    size_t ll = nl ? (size_t)(nl - p) : strlen(p);
    char row[TREE_ROW_MAX + 1];
    if (ll < sizeof(row)) {
      memcpy(row, p, ll);
      row[ll] = '\0';
      char *f[10];
      int nf = 0;
      /* keep empty fields: split by hand */
      char *q = row;
      while (nf < 10) {
        f[nf++] = q;
        char *bar = strchr(q, '|');
        if (!bar) break;
        *bar = '\0';
        q = bar + 1;
      }
      trow_t t;
      memset(&t, 0, sizeof(t));
      t.type = f[0][0];
      if (t.type == 'H' && nf >= 9) {
        t.depth = atoi(f[1]);
        copy_field(t.name, sizeof(t.name), f[2]);
        copy_field(t.uuid, sizeof(t.uuid), f[3]);
        t.online = atoi(f[4]) != 0;
        copy_field(t.ver, sizeof(t.ver), f[6]);
        copy_field(t.var, sizeof(t.var), f[7]);
        t.started = atoll(f[8]);
        out[n++] = t;
      } else if (t.type == 'B' && nf >= 9) {
        t.depth = atoi(f[1]);
        copy_field(t.name, sizeof(t.name), f[2]);
        copy_field(t.uuid, sizeof(t.uuid), f[3]);
        copy_field(t.ver, sizeof(t.ver), f[4]);
        copy_field(t.server, sizeof(t.server), f[5]);
        copy_field(t.var, sizeof(t.var), f[7]);
        t.started = atoll(f[8]);
        t.online = true;
        out[n++] = t;
      } else if (t.type == 'D' && nf >= 4) {
        t.depth = 1;
        copy_field(t.name, sizeof(t.name), f[1]);
        copy_field(t.uuid, sizeof(t.uuid), f[2]);
        t.started = atoll(f[3]);
        out[n++] = t;
      }
    }
    p = nl ? nl + 1 : NULL;
  }
  return n;
}

static void fmt_age(long long since, char *out, size_t cap) {
  if (cap < 24) return;
  if (since <= 0) {
    usnprintf(out, cap, "--");
    return;
  }
  long long d = (long long)time(NULL) - since;
  if (d < 0) d = 0;
  if (d < 60) usnprintf(out, cap, "%llds", d);
  else if (d < 3600) usnprintf(out, cap, "%lldm", d / 60);
  else if (d < 86400) usnprintf(out, cap, "%lldh", d / 3600);
  else usnprintf(out, cap, "%lldd", d / 86400);
}

/* One pane line for tree row i. */
static void tree_line(const console_ui_t *ui, rowb_t *r, const trow_t *t, int i,
                      const trow_t *all, int n, int width) {
  int start = r->w;
  bool wide_ver = width >= 30, wide_var = width >= 26, wide_up = width >= 34;
  int right = (wide_ver ? 9 : 0) + 2 + (wide_var ? 3 : 0) + (wide_up ? 5 : 0);
  int indent = t->type == 'D' ? 0 : t->depth * 2;
  if (indent > width / 3) indent = width / 3;
  rb_pad(r, start + indent);
  if (t->type == 'H') {
    rb_sgr(r, "0;1");
    rb_text(r, G(ui, "▾"), 1);
    rb_text(r, " ", 1);
  } else if (t->type == 'B') {
    bool last = true;
    for (int k = i + 1; k < n; k++) {
      if (all[k].type == 'B' && all[k].depth == t->depth) { last = false; break; }
      if (all[k].type != 'B' || all[k].depth < t->depth) break;
    }
    rb_sgr(r, SGR_RESET);
    rb_text(r, G(ui, last ? "└" : "├"), 1);
    rb_text(r, " ", 1);
  } else {
    rb_sgr(r, "0;90");
    rb_text(r, "  ", 2);
  }
  int name_w = width - (r->w - start) - right;
  if (name_w < 1) name_w = 1;
  rb_text(r, t->name, name_w);
  rb_pad(r, start + width - right);
  if (wide_ver) {
    rb_sgr(r, "0;90");
    rb_right(r, t->type == 'D' ? "" : (strcmp(t->ver, "-") ? t->ver : ""), 8);
    rb_text(r, " ", 1);
  }
  rb_sgr(r, t->online ? "0;32" : "0;31");
  rb_text(r, G(ui, t->online ? "●" : "○"), 1);
  rb_text(r, " ", 1);
  if (wide_var) {
    rb_sgr(r, SGR_RESET);
    rb_text(r, strcmp(t->var, "-") ? t->var : "", 2);
    rb_pad(r, r->w + (2 - (int)strlen(strcmp(t->var, "-") ? t->var : "")));
    rb_text(r, " ", 1);
  }
  if (wide_up) {
    char age[24];
    fmt_age(t->type == 'D' ? 0 : t->started, age, sizeof(age));
    rb_sgr(r, "0;90");
    rb_right(r, age, 4);
    rb_text(r, " ", 1);
  }
  rb_sgr(r, SGR_RESET);
  rb_pad(r, start + width);
}

/* ---- scrollback views ---- */
static bool log_line_visible(const console_ui_t *ui, const sline_t *l) {
  if (l->level > ui->log_show) return false;
  if (ui->filter[0] && !ci_contains(l->text ? l->text : "", ui->filter)) return false;
  return true;
}

static bool sb_visible(const console_ui_t *ui, int view, const sline_t *l) {
  if (!l || !l->text) return false;
  return view != V_LOG || log_line_visible(ui, l);
}

static long long sb_bottom(const console_ui_t *ui, int view) {
  const sback_t *sb = &ui->sb[view];
  if (ui->anchor[view] >= 0) return ui->anchor[view];
  if (view == V_LOG && ui->paused) return ui->paused_next - 1;
  return sb->next - 1;
}

typedef struct {
  long long seq;
  size_t from, to;
} seg_t;

/* The rows a scrollback view shows, top to bottom, ending at its bottom line. */
static int sb_layout(const console_ui_t *ui, int view, int W, int H, seg_t *segs) {
  const sback_t *sb = &ui->sb[view];
  int filled = 0;
  for (long long s = sb_bottom(ui, view); s >= sb->first && filled < H; s--) {
    const sline_t *l = sb_get(sb, s);
    if (!sb_visible(ui, view, l)) continue;
    size_t len = strlen(l->text);
    seg_t tmp[256];
    int nt = 0;
    if (len == 0) tmp[nt++] = (seg_t){s, 0, 0};
    for (size_t i = 0; i < len && nt < 256;) {
      size_t e = wrap_end(l->text, len, i, W);
      tmp[nt++] = (seg_t){s, i, e};
      i = e;
    }
    for (int k = nt - 1; k >= 0 && filled < H; k--) segs[H - 1 - filled++] = tmp[k];
  }
  /* shift to the top when there are fewer rows than the pane */
  if (filled < H) {
    memmove(segs, segs + (H - filled), sizeof(seg_t) * (size_t)filled);
  }
  return filled;
}

static void scroll_view(console_ui_t *ui, int dir) {
  int v = ui->view;
  int H = ui->rows - 3;
  if (H < 1) return;
  if (v == V_CONSOLE || v == V_LOG) {
    const sback_t *sb = &ui->sb[v];
    int W = ui->cols;   /* close enough for paging */
    long long s = sb_bottom(ui, v);
    int moved = 0;
    while (moved < H - 1) {
      long long ns = s + dir;
      if (ns < sb->first) break;
      if (ns >= sb->next) {
        ui->anchor[v] = -1;
        if (v == V_LOG) ui->paused = false;
        ui->dirty = true;
        return;
      }
      s = ns;
      const sline_t *l = sb_get(sb, s);
      if (sb_visible(ui, v, l)) moved += wrap_rows(l->text, W);
    }
    ui->anchor[v] = s;
  } else {
    long long top = ui->anchor[v] < 0 ? 0 : ui->anchor[v];
    top += dir * (H - 1);
    if (top <= 0) top = -1;
    ui->anchor[v] = top;
  }
  ui->dirty = true;
}

/* Views 4 and 5: the upgrade status / statistics reply, laid out by the
 * same renderer as the commands (no result line), from line anchor[view]. */
static void view_rows(const console_ui_t *ui, int view, const char *text, int W,
                      int H, rowb_t *rows, int col0) {
  flines_t f = {0};
  if (!text) {
    flines_add(&f, RL_DIM, "(asking the hub...)");
  } else {
    creply_t rep;
    creply_parse(text, strlen(text), &rep);
    fmt_ctx_t c;
    char slog[128];
    ctx_init(ui, &c, FMT_MODE_VIEW, slog, sizeof(slog));
    c.ascii = ui->ascii;
    c.width = W;
    fmt_reply(&c, &rep, view == V_UPG ? "upgrade status" : "hub stats", &f);
    creply_free(&rep);
  }
  long long top = ui->anchor[view] < 0 ? 0 : ui->anchor[view];
  int y = 0;
  for (int i = (int)(top < f.n ? top : f.n); i < f.n && y < H; i++, y++) {
    rb_sgr(&rows[y], kind_sgr(f.v[i].role));
    rb_text(&rows[y], f.v[i].text, W);
    rb_sgr(&rows[y], SGR_RESET);
    rb_pad(&rows[y], col0 + W);
  }
  flines_free(&f);
}

static void net_rows_count(const console_ui_t *ui, int *n) {
  static trow_t tr[MAX_TROWS];
  *n = parse_tree(ui->tree, tr, MAX_TROWS);
}

/* View 3: every tree column, and the selected node's details. */
static void net_view(console_ui_t *ui, int W, int H, rowb_t *rows, int col0) {
  static trow_t tr[MAX_TROWS];
  int n = parse_tree(ui->tree, tr, MAX_TROWS);
  if (ui->net_sel >= n) ui->net_sel = n ? n - 1 : 0;
  int detail = n ? 5 : 0;
  int list_h = H - detail;
  if (list_h < 1) list_h = H, detail = 0;
  int top = 0;
  if (ui->net_sel >= list_h) top = ui->net_sel - list_h + 1;
  rb_sgr(&rows[0], "0;1");
  rb_text(&rows[0], n ? "node                            version   base  up     server / uuid"
                      : "(no tree yet)", W);
  rb_pad(&rows[0], col0 + W);
  for (int y = 1; y < list_h && top + y - 1 < n; y++) {
    int i = top + y - 1;
    const trow_t *t = &tr[i];
    rowb_t *r = &rows[y];
    rb_sgr(r, i == ui->net_sel ? SGR_SEL : SGR_RESET);
    char name[128];
    usnprintf(name, sizeof(name), "%*s%s %s", t->type == 'D' ? 0 : t->depth * 2, "",
             t->type == 'H' ? "hub" : t->type == 'B' ? "bot" : "off", t->name);
    rb_text(r, name, 32);
    rb_pad(r, col0 + 32);
    char age[24];
    fmt_age(t->type == 'D' ? 0 : t->started, age, sizeof(age));
    char rest[256];
    usnprintf(rest, sizeof(rest), "%-9s %-5s %-6s %s", strcmp(t->ver, "-") ? t->ver : "",
             strcmp(t->var, "-") ? t->var : "", age,
             t->type == 'B' ? t->server : t->uuid);
    rb_text(r, rest, W - 32);
    rb_pad(r, col0 + W);
  }
  if (detail && n) {
    const trow_t *t = &tr[ui->net_sel];
    char line[256], when[64] = "--";
    if (t->started > 0) fmt_when(t->started, now_s(), when, sizeof(when));
    const char *kind = t->type == 'H' ? "hub" : t->type == 'B' ? "bot" : "bot (not connected)";
    int y0 = H - detail;
    rb_sgr(&rows[y0], SGR_LINE);
    rb_fill(&rows[y0], G(ui, "─"), W);
    usnprintf(line, sizeof(line), "%s %s  %s", kind, t->name, t->online ? "online" : "offline");
    rb_sgr(&rows[y0 + 1], "0;1"); rb_text(&rows[y0 + 1], line, W); rb_pad(&rows[y0 + 1], col0 + W);
    usnprintf(line, sizeof(line), "uuid     %s", t->uuid);
    rb_sgr(&rows[y0 + 2], SGR_RESET); rb_text(&rows[y0 + 2], line, W); rb_pad(&rows[y0 + 2], col0 + W);
    usnprintf(line, sizeof(line), "version  %s %s   server %s", t->ver, t->var,
             t->server[0] ? t->server : "-");
    rb_text(&rows[y0 + 3], line, W); rb_pad(&rows[y0 + 3], col0 + W);
    usnprintf(line, sizeof(line), "%s  %s", t->type == 'D' ? "last seen" : "started  ", when);
    rb_text(&rows[y0 + 4], line, W); rb_pad(&rows[y0 + 4], col0 + W);
  }
}

static void status_bar(console_ui_t *ui, rowb_t *r, long long now_ms, bool pane_hidden) {
  typedef struct { char text[96]; int prio; const char *sgr; } seg;
  seg s[16];
  int n = 0;
  char clk[16];
  clock_utc(clk, sizeof(clk), false);
#define SEG(p, sg, ...) do { if (n < 16) { usnprintf(s[n].text, sizeof(s[n].text), __VA_ARGS__); s[n].prio = p; s[n].sgr = sg; n++; } } while (0)
  const char *hn = ui->hubname[0] ? ui->hubname : "hub";
  SEG(1, SGR_STATUS, "%s %.*s %.*s", clk, uprec(hn, 40), hn, uprec(ui->admin, 40), ui->admin);
  if (ui->st.have) {
    SEG(2, SGR_STATUS, "peers %d/%d", ui->st.peers_up, ui->st.peers_total);
    SEG(2, SGR_STATUS, "bots %d/%d", ui->st.bots_on, ui->st.bots_total);
    if (strcmp(ui->st.upg, "-")) SEG(3, SGR_WARNBG, "UPG %s", ui->st.upg);
    if (ui->st.frozen) SEG(3, SGR_ALERT, "FROZEN");
    if (ui->st.rollup) SEG(3, SGR_WARNBG, "ROLLUP");
    if (ui->st.split) SEG(3, SGR_ALERT, "SPLIT");
  }
  if (pane_hidden) SEG(3, SGR_STATUS, "F3:tree");
  if (ui->view == V_LOG)
    SEG(4, SGR_STATUS, "%s%s%.*s show:%s", VIEW_NAME[ui->view], ui->filter[0] ? " /" : "",
        uprec(ui->filter, 40), ui->filter, LEVEL_WORD[ui->log_show]);
  else
    SEG(4, SGR_STATUS, "%s", VIEW_NAME[ui->view]);
  if (ui->st.have && ui->st.loglevel >= 0 && ui->st.loglevel <= LOG_DEBUG &&
      ui->st.consolelevel >= 0 && ui->st.consolelevel <= LOG_DEBUG)
    SEG(4, SGR_STATUS, "log file:%s console:%s", LEVEL_WORD[ui->st.loglevel],
        LEVEL_WORD[ui->st.consolelevel]);
  if (ui->paused) SEG(4, SGR_WARNBG, "PAUSED");
  {
    char act[32] = "";
    size_t o = 0;
    for (int v = 0; v < V_COUNT; v++)
      if (ui->act[v] && o + 3 < sizeof(act))
        o += (size_t)usnprintf(act + o, sizeof(act) - o, "%s%d", o ? "," : "", v + 1);
    if (o) SEG(5, SGR_STATUS, "[Act: %s]", act);
  }
  long long idle_left = CONSOLE_IDLE_TIMEOUT - (now_ms - ui->last_input_ms) / 1000;
  if (idle_left <= 60) SEG(6, SGR_ALERT, "idle %llds", idle_left < 0 ? 0 : idle_left);
#undef SEG
  /* drop the lowest priority until it fits */
  for (;;) {
    int w = 1;
    for (int i = 0; i < n; i++) w += str_width(s[i].text) + 3;
    if (w <= r->max || n <= 1) break;
    int worst = 0;
    for (int i = 1; i < n; i++)
      if (s[i].prio >= s[worst].prio) worst = i;
    memmove(&s[worst], &s[worst + 1], sizeof(seg) * (size_t)(n - worst - 1));
    n--;
  }
  rb_sgr(r, SGR_STATUS);
  rb_text(r, " ", 1);
  for (int i = 0; i < n; i++) {
    if (i) {
      rb_sgr(r, SGR_STATUS);
      rb_text(r, " ", 1);
      rb_text(r, G(ui, "│"), 1);
      rb_text(r, " ", 1);
    }
    rb_sgr(r, s[i].sgr);
    rb_text(r, s[i].text, -1);
  }
  rb_sgr(r, SGR_STATUS);
  rb_pad(r, r->max);
  rb_sgr(r, SGR_RESET);
}

/* The output pane's width (the terminal minus the tree pane). */
static int main_width(const console_ui_t *ui) {
  int C = ui->cols;
  bool wide = C >= CONSOLE_PANE_MIN_COLS;
  int pane_w = 0;
  if (wide && !ui->pane_user_off) {
    pane_w = C * 30 / 100;
    if (pane_w < CONSOLE_PANE_MIN) pane_w = CONSOLE_PANE_MIN;
    if (pane_w > CONSOLE_PANE_MAX) pane_w = CONSOLE_PANE_MAX;
  }
  if (!wide && ui->overlay) pane_w = C - 20 < CONSOLE_PANE_MIN ? C - 20 : CONSOLE_PANE_MIN;
  if (pane_w < 0) pane_w = 0;
  return pane_w ? C - pane_w - 1 : C;
}

/* D5: the console view laid out again for a new width — every reply it
 * holds is rendered anew from its records. */
static void relayout(console_ui_t *ui) {
  int w = main_width(ui);
  if (ui->render_w == w || !ui->ent) return;
  ui->render_w = w;
  sb_clear(&ui->sb[V_CONSOLE]);
  for (long long e = ui->ent_first; e < ui->ent_next; e++) {
    const centry_t *x = &ui->ent[e % CONSOLE_SCROLLBACK];
    if (x->text) {
      char *a = ui->ascii ? fmt_ascii(x->text) : NULL;
      sb_add(&ui->sb[V_CONSOLE], a ? a : x->text, x->kind, LOG_INFO);
      free(a);
    } else if (x->reply) {
      flines_t f = {0};
      render_reply(ui, x->reply, strlen(x->reply), x->words, x->mode, &f);
      for (int i = 0; i < f.n; i++) sb_add(&ui->sb[V_CONSOLE], f.v[i].text, f.v[i].role, LOG_INFO);
      flines_free(&f);
    }
  }
  ui->anchor[V_CONSOLE] = -1;
}

static void compose(console_ui_t *ui, rowb_t *rows, int *cur_row, int *cur_col,
                    long long now_ms) {
  int C = ui->cols, R = ui->rows;
  for (int y = 0; y < R; y++) {
    rb_start(&rows[y], y == R - 1 ? C - 1 : C);
    rows[y].ascii = ui->ascii;
  }
  if (C < CONSOLE_MIN_COLS || R < CONSOLE_MIN_ROWS) {
    rb_text(&rows[0], "terminal too small (40x10 at least)", -1);
    for (int y = 0; y < R; y++) rb_pad(&rows[y], rows[y].max);
    *cur_row = 0;
    *cur_col = 0;
    return;
  }
  bool wide = C >= CONSOLE_PANE_MIN_COLS;
  int pane_w = 0;
  if (wide && !ui->pane_user_off) {
    pane_w = C * 30 / 100;
    if (pane_w < CONSOLE_PANE_MIN) pane_w = CONSOLE_PANE_MIN;
    if (pane_w > CONSOLE_PANE_MAX) pane_w = CONSOLE_PANE_MAX;
  }
  /* On a narrow terminal F3 lays the tree over the right of the screen,
   * squeezing the output pane while it is shown. */
  bool overlay = !wide && ui->overlay;
  if (overlay) pane_w = C - 20 < CONSOLE_PANE_MIN ? C - 20 : CONSOLE_PANE_MIN;
  if (pane_w < 0) pane_w = 0;
  int main_w = pane_w ? C - pane_w - 1 : C;
  int H = R - 3;

  /* title row */
  {
    rowb_t *r = &rows[0];
    rb_sgr(r, SGR_LINE);
    rb_text(r, G(ui, "─"), 1);
    rb_text(r, " ", 1);
    char label[64];
    usnprintf(label, sizeof(label), "[%d:%s]", ui->view + 1, VIEW_NAME[ui->view]);
    rb_sgr(r, SGR_TITLE);
    rb_text(r, label, -1);
    rb_sgr(r, SGR_LINE);
    rb_text(r, " ", 1);
    rb_fill(r, G(ui, "─"), main_w - r->w);
    if (pane_w) {
      rb_text(r, G(ui, "┬"), 1);
      rb_text(r, G(ui, "─"), 1);
      rb_sgr(r, SGR_TITLE);
      rb_text(r, " network ", -1);
      rb_sgr(r, SGR_LINE);
      rb_fill(r, G(ui, "─"), C - r->w);
    }
    rb_sgr(r, SGR_RESET);
  }

  /* main pane */
  rowb_t *body = &rows[1];
  if (ui->view == V_CONSOLE || ui->view == V_LOG) {
    seg_t *segs = calloc((size_t)H, sizeof(seg_t));
    int filled = segs ? sb_layout(ui, ui->view, main_w, H, segs) : 0;
    for (int y = 0; y < filled; y++) {
      const sline_t *l = sb_get(&ui->sb[ui->view], segs[y].seq);
      if (!l || !l->text) continue;
      char buf[CONSOLE_INPUT_MAX * 2];
      size_t n = segs[y].to - segs[y].from;
      /* a row of 3-byte glyphs (or zero-width marks) can outgrow buf: cut
       * where no character is split, or the terminal gets half of one */
      if (n >= sizeof(buf)) n = utf8_cut(l->text + segs[y].from, sizeof(buf) - 1);
      memcpy(buf, l->text + segs[y].from, n);
      buf[n] = '\0';
      bool hit = ui->view == V_LOG && ui->search[0] && ci_contains(l->text, ui->search) &&
                 ui->anchor[V_LOG] == segs[y].seq;
      rb_sgr(&body[y], hit ? SGR_SEL : kind_sgr(l->kind));
      rb_text(&body[y], buf, main_w);
      rb_sgr(&body[y], SGR_RESET);
    }
    free(segs);
  } else if (ui->view == V_NET) {
    net_view(ui, main_w, H, body, 0);
  } else {
    const char *text = ui->view == V_UPG ? ui->upg_text : ui->stats_text;
    view_rows(ui, ui->view, text, main_w, H, body, 0);
  }
  for (int y = 0; y < H; y++) {
    rb_sgr(&body[y], SGR_RESET);
    rb_pad(&body[y], main_w);
  }

  /* tree pane */
  if (pane_w > 0) {
    static trow_t tr[MAX_TROWS];
    int n = parse_tree(ui->tree, tr, MAX_TROWS);
    for (int y = 0; y < H; y++) {
      rowb_t *r = &body[y];
      rb_sgr(r, SGR_LINE);
      rb_text(r, G(ui, "│"), 1);
      rb_sgr(r, SGR_RESET);
      if (y < n) tree_line(ui, r, &tr[y], y, tr, n, pane_w);
      else rb_pad(r, r->w + pane_w);
    }
  }

  /* status bar + input */
  status_bar(ui, &rows[R - 2], now_ms, !wide && !overlay);
  {
    rowb_t *r = &rows[R - 1];
    const char *prompt = ui->searching ? "search: " : ui->confirming ? "confirm> " : "> ";
    rb_sgr(r, ui->confirming ? "0;1;33" : "0;1");
    rb_text(r, prompt, -1);
    rb_sgr(r, SGR_RESET);
    int pw = r->w;
    int avail = r->max - pw;
    char before[CONSOLE_INPUT_MAX];
    usnprintf(before, sizeof(before), "%.*s", ui->in_cur, ui->in);
    int cw = str_width(before);
    if (cw < ui->in_scroll) ui->in_scroll = cw;
    if (cw >= ui->in_scroll + avail) ui->in_scroll = cw - avail + 1;
    /* skip in_scroll cells */
    size_t len = (size_t)ui->in_len, i = 0;
    int skipped = 0;
    while (i < len && skipped < ui->in_scroll) {
      unsigned cp;
      int w;
      i += next_char(ui->in + i, len - i, &cp, &w);
      skipped += w;
    }
    rb_text(r, ui->in + i, avail);
    rb_pad(r, r->max);
    *cur_row = R - 1;
    *cur_col = pw + cw - ui->in_scroll;
  }
}

static void draw(console_ui_t *ui, long long now_ms) {
  if (ui->line_mode) return;
  relayout(ui);
  int R = ui->rows;
  rowb_t *rows = calloc((size_t)R, sizeof(rowb_t));
  if (!rows) return;
  int cr = 0, cc = 0;
  compose(ui, rows, &cr, &cc, now_ms);
  if (ui->prev_n != R) {
    for (int i = 0; i < ui->prev_n; i++) free(ui->prev_rows[i]);
    free(ui->prev_rows);
    ui->prev_rows = calloc((size_t)R, sizeof(char *));
    ui->prev_n = ui->prev_rows ? R : 0;
    ui->full_redraw = true;
  }
  cbuf_adds(&ui->term, "\x1b[?25l");
  if (ui->full_redraw) cbuf_adds(&ui->term, "\x1b[0m\x1b[H\x1b[2J");
  for (int y = 0; y < R; y++) {
    cbuf_add(&rows[y].b, "", 1);           /* NUL-terminate for compare */
    const char *txt = (const char *)rows[y].b.p;
    if (!txt) txt = "";
    if (!ui->full_redraw && ui->prev_rows && ui->prev_rows[y] &&
        !strcmp(ui->prev_rows[y], txt))
      continue;
    cbuf_addf(&ui->term, "\x1b[%d;1H", y + 1);
    cbuf_adds(&ui->term, txt);
    cbuf_adds(&ui->term, "\x1b[0m");
    if (ui->prev_rows) {
      free(ui->prev_rows[y]);
      ui->prev_rows[y] = strdup(txt);
    }
  }
  cbuf_addf(&ui->term, "\x1b[%d;%dH\x1b[?25h", cr + 1, cc + 1);
  for (int y = 0; y < R; y++) cbuf_free(&rows[y].b);
  free(rows);
  ui->full_redraw = false;
  ui->dirty = false;
  ui->last_draw_ms = now_ms;
}

/* ==========================================================================
 * Lifecycle
 * ========================================================================== */
console_ui_t *ui_new(bool line_mode, int cols, int rows, const char *admin,
                     const char *ip, const char *hubname) {
  console_ui_t *ui = calloc(1, sizeof(*ui));
  if (!ui) return NULL;
  ui->line_mode = line_mode;
  ui->cols = cols > 0 && cols < 1000 ? cols : 80;
  ui->rows = rows > 0 && rows < 1000 ? rows : 24;
  console_sanitize(admin, strlen(admin), ui->admin, sizeof(ui->admin));
  console_sanitize(ip, strlen(ip), ui->ip, sizeof(ui->ip));
  console_sanitize(hubname, strlen(hubname), ui->hubname, sizeof(ui->hubname));
  if (!line_mode) {
    sb_init(&ui->sb[V_CONSOLE], CONSOLE_SCROLLBACK);
    sb_init(&ui->sb[V_LOG], CONSOLE_LOG_SCROLLBACK);
    ui->ent = calloc(CONSOLE_SCROLLBACK, sizeof(centry_t));
  }
  ui->render_w = -1;
  for (int v = 0; v < V_COUNT; v++) ui->anchor[v] = -1;
  ui->log_show = LOG_DEBUG;
  ui->log_sub_level = LOG_INFO;
  ui->st.loglevel = -1;
  ui->st.consolelevel = -1;
  ui->full_redraw = true;
  return ui;
}

void ui_free(console_ui_t *ui) {
  if (!ui) return;
  for (int v = 0; v < V_COUNT; v++) sb_free(&ui->sb[v]);
  for (int i = 0; i < ui->hist_n; i++) free(ui->hist[i]);
  for (int i = 0; i < ui->queued_n; i++) free(ui->queued[i]);
  for (int i = 0; i < ui->prev_n; i++) free(ui->prev_rows[i]);
  free(ui->prev_rows);
  for (int i = 0; ui->ent && i < CONSOLE_SCROLLBACK; i++) {
    free(ui->ent[i].text);
    free(ui->ent[i].reply);
  }
  free(ui->ent);
  free(ui->tree);
  free(ui->upg_text);
  free(ui->stats_text);
  cbuf_free(&ui->term);
  cbuf_free(&ui->core);
  cbuf_free(&ui->held);
  secure_wipe(ui, sizeof(*ui));
  free(ui);
}

void ui_start(console_ui_t *ui, long long now_ms) {
  ui->last_input_ms = now_ms;
  ui->now_ms = ui->start_ms = now_ms;
  ui->started = true;
  subscribe(ui);
  /* §2.1: "irchub console" stays the first words (scripts look for it); the
   * mesh summary follows once the first status event is in */
  char hello[320];
  usnprintf(hello, sizeof(hello), "irchub console %s (%s) %s %s %s admin %s from %s",
            HUB_VERSION, HUB_UPDATE_VARIANT, "·",
            ui->hubname[0] ? ui->hubname : "hub", "·", ui->admin, ui->ip);
  if (ui->line_mode) {
    lm_line(ui, hello);
    lm_prompt(ui);
    return;
  }
  /* alternate screen, bracketed paste */
  cbuf_adds(&ui->term, "\x1b[?1049h\x1b[?2004h\x1b[H\x1b[2J");
  fs_line(ui, hello, RL_TITLE);
  ui->dirty = true;
}

void ui_resize(console_ui_t *ui, int cols, int rows, long long now_ms) {
  if (cols > 0 && cols < 1000) ui->cols = cols;
  if (rows > 0 && rows < 1000) ui->rows = rows;
  ui->resize_ms = now_ms;
  ui->dirty = true;
  ui->full_redraw = true;
  if (ui->cols >= CONSOLE_PANE_MIN_COLS) ui->overlay = false;
}

void ui_tick(console_ui_t *ui, long long now_ms) {
  if (!ui->started) return;
  ui->now_ms = now_ms;
  if (ui->esc_len > 0 && now_ms - ui->esc_ms >= CONSOLE_ESC_MS) {
    if (ui->esc_len == 1) handle_key(ui, (ckey_t){K_ESC, 0}, now_ms);
    ui->esc_len = 0;
  }
  if (now_ms - ui->last_input_ms >= (long long)CONSOLE_IDLE_TIMEOUT * 1000 && !ui->closing) {
    ui->closing = true;
    usnprintf(ui->close_why, sizeof(ui->close_why), "idle timeout");
    return;
  }
  if (ui->dropped && ui->term.len < CONSOLE_TERM_OUTQ_MAX / 2) {
    char m[64];
    unsigned long n = ui->dropped;
    ui->dropped = 0;
    if (ui->line_mode) {
      usnprintf(m, sizeof(m), "[evt drop] %lu", n);
      lm_async(ui, m);
    } else {
      usnprintf(m, sizeof(m), "[%lu lines dropped]", n);
      fs_add(ui, V_LOG, m, RL_WARN, LOG_ERROR);
    }
  }
  if (ui->line_mode) return;

  if (ui->view == V_UPG && now_ms - ui->upg_at >= CONSOLE_UPG_REFRESH_MS)
    request_view(ui, RQ_VIEW_UPG, now_ms);
  if (ui->view == V_STATS && now_ms - ui->stats_at >= CONSOLE_STATS_REFRESH_MS)
    request_view(ui, RQ_VIEW_STATS, now_ms);
  /* the clock, and the idle countdown in its last minute */
  long long idle_left = CONSOLE_IDLE_TIMEOUT - (now_ms - ui->last_input_ms) / 1000;
  long long tick = idle_left <= 60 ? 1000 : 60000;
  if (now_ms / tick != ui->last_clock_ms / tick) {
    ui->last_clock_ms = now_ms;
    ui->dirty = true;
  }
  if ((ui->dirty || ui->full_redraw) && now_ms - ui->resize_ms >= CONSOLE_RESIZE_MS &&
      now_ms - ui->last_draw_ms >= 30 && ui->term.len < CONSOLE_TERM_OUTQ_MAX)
    draw(ui, now_ms);
}

bool ui_busy(const console_ui_t *ui) {
  return ui->user_busy || ui->queued_n > 0 || ui->confirming;
}

cbuf_t *ui_term_out(console_ui_t *ui) { return &ui->term; }
cbuf_t *ui_core_out(console_ui_t *ui) { return &ui->core; }

bool ui_closing(const console_ui_t *ui, const char **why) {
  if (why) *why = ui->close_why;
  return ui->closing;
}

void ui_goodbye(console_ui_t *ui, const char *why) {
  if (ui->line_mode) {
    char m[128];
    usnprintf(m, sizeof(m), "\r\n[closed] %s\r\n", why ? why : "");
    cbuf_adds(&ui->term, m);
    return;
  }
  cbuf_adds(&ui->term, "\x1b[0m\x1b[?2004l\x1b[?25h\x1b[?1049l");
  cbuf_addf(&ui->term, "irchub console closed: %s\r\n", why ? why : "");
}
