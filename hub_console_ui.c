/* SSH admin console — one session's user interface.  docs/console.md.
 *
 * Runs on the console thread only.  Everything the admin sees is built here:
 * the line-mode transcript (TERM=dumb, the testnet's interface) and the
 * full-screen irssi-style console (output pane, network tree, status bar,
 * input line), with the key parser, the command language and the sanitizer
 * that keeps text from bots, peers and logs from reaching the terminal as
 * escape sequences.  No libssh, no hub_state_t. */
#include "hub_console_ui.h"
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
enum {
  L_NORMAL = 0, L_CMD, L_ERR, L_OK, L_INFO, L_WARN, L_DIM
};

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

typedef enum { CF_NONE = 0, CF_YN, CF_TYPE_ARG, CF_TYPE_HUB, CF_TYPE_VER } confirm_t;

/* What a request in flight was for: replies come back in order. */
enum { RQ_USER = 0, RQ_VIEW_UPG, RQ_VIEW_STATS, RQ_TREE_SYNC };

typedef struct {
  int  kind;
  int  seq;              /* RQ_USER: the command number */
  char words[32];        /* "bot list" */
  char audit[320];       /* what the audit line says was asked */
  int  audit_level;
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
  bool user_busy;               /* a user command is in flight */
  pending_rq_t rq[MAX_PENDING_RQ];
  int  rq_n;
  char *queued[MAX_QUEUED_LINES];
  int  queued_n;
  confirm_t confirming;
  int  confirm_seq;
  char confirm_want[128];
  char confirm_q[256];
  uint8_t confirm_op;
  unsigned char confirm_payload[1024];
  size_t confirm_len;
  pending_rq_t confirm_rq;
  /* line mode: events held back while a command's output is pending */
  cbuf_t held;
  unsigned long dropped;

  /* data from the core */
  status_t st;
  char *tree;                   /* rows, '\n'-separated */
  char *upg_text, *stats_text;
  long long upg_at, stats_at;
  bool log_on;                  /* line mode: "log on" */
  int  log_sub_level;

  /* full screen */
  int  view;
  sback_t sb[V_COUNT];          /* V_CONSOLE and V_LOG are used */
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
 * Command table (docs/console.md §2)
 * ========================================================================== */
enum bk {
  B_NONE, B_ARG, B_OPTARG, B_PIPE, B_COLON, B_PEER_ADD, B_CHAN_ADD, B_OPT_SET,
  B_LOGLEVEL, B_LOGSIZE, B_PURGE, B_UPG_RELEASES, B_UPG_START, B_FIXED,
  B_LOCAL
};

typedef struct {
  const char *cmd, *sub;
  uint8_t     op;
  enum bk     build;
  int         nargs, optargs;
  confirm_t   confirm;
  const char *fixed;
  const char *usage;
  const char *help;
} cmd_def_t;

static const cmd_def_t CMDS[] = {
  {"help", NULL, 0, B_LOCAL, 0, 1, CF_NONE, NULL, "help [command]", "list commands, or show one"},
  {"quit", NULL, 0, B_LOCAL, 0, 0, CF_NONE, NULL, "quit", "close this console"},
  {"bot", "list", CMD_ADMIN_LIST_FULL, B_NONE, 0, 0, CF_NONE, NULL, "bot list", "every bot the hub knows, with its fields"},
  {"bot", "summary", CMD_ADMIN_LIST_SUMMARY, B_NONE, 0, 0, CF_NONE, NULL, "bot summary", "bots, one line each"},
  {"bot", "pending", CMD_ADMIN_GET_PENDING, B_NONE, 0, 0, CF_NONE, NULL, "bot pending", "bots waiting for approval"},
  {"bot", "approve", CMD_ADMIN_APPROVE, B_ARG, 1, 0, CF_NONE, NULL, "bot approve <index|uuid>", "approve a pending bot"},
  {"bot", "authorize", CMD_ADMIN_ADD, B_ARG, 1, 0, CF_NONE, NULL, "bot authorize <uuid>", "authorize a bot uuid"},
  {"bot", "add", CMD_ADMIN_CREATE_BOT, B_PIPE, 3, 0, CF_NONE, NULL, "bot add <nick> <uuid> <pubkey>", "register a bot by the identity its setup printed"},
  {"bot", "del", CMD_ADMIN_DEL, B_ARG, 1, 0, CF_YN, NULL, "bot del <uuid>", "delete a bot (disconnects it)"},
  {"bot", "kick", CMD_ADMIN_DISCONNECT_BOT, B_ARG, 1, 0, CF_YN, NULL, "bot kick <uuid>", "disconnect a bot"},
  {"bot", "rekey", CMD_ADMIN_REKEY_BOT, B_ARG, 1, 0, CF_NONE, NULL, "bot rekey <uuid>", "how to rekey a bot"},
  {"peer", "list", CMD_ADMIN_LIST_PEERS, B_NONE, 0, 0, CF_NONE, NULL, "peer list", "peer hubs and the mesh matrix"},
  {"peer", "add", CMD_ADMIN_ADD_PEER, B_PEER_ADD, 5, 0, CF_NONE, NULL, "peer add <ip> <port> <uuid> <name|-> <pubkey>", "add a peer hub"},
  {"peer", "del", CMD_ADMIN_DEL_PEER, B_OPTARG, 0, 1, CF_TYPE_ARG, NULL, "peer del [index]", "remove a peer hub (no index: list the configured peers)"},
  {"peer", "setkey", CMD_ADMIN_SET_PEER_PUBKEY, B_COLON, 2, 0, CF_NONE, NULL, "peer setkey <uuid> <pubkey>", "set a peer's public key"},
  {"peer", "sync", CMD_ADMIN_SYNC_MESH, B_NONE, 0, 0, CF_NONE, NULL, "peer sync", "send a full sync to every peer"},
  {"hub", "pubkey", CMD_ADMIN_GET_PUBKEY, B_NONE, 0, 0, CF_NONE, NULL, "hub pubkey", "this hub's public key"},
  {"hub", "setpub", CMD_ADMIN_SET_PUBKEY, B_ARG, 1, 0, CF_NONE, NULL, "hub setpub <pubkey>", "re-store the public key (must match the private key)"},
  {"hub", "rekey", CMD_ADMIN_REGEN_KEYS, B_NONE, 0, 0, CF_TYPE_HUB, NULL, "hub rekey", "new hub keypair; every peer and bot must re-learn it"},
  {"hub", "name", CMD_ADMIN_SET_HUB_NAME, B_ARG, 1, 0, CF_NONE, NULL, "hub name <name>", "set this hub's name"},
  {"hub", "bindip", CMD_ADMIN_SET_BIND_IP, B_ARG, 1, 0, CF_NONE, NULL, "hub bindip <ip>", "set the bind address (restart)"},
  {"hub", "port", CMD_ADMIN_SET_BIND_PORT, B_ARG, 1, 0, CF_NONE, NULL, "hub port <port>", "set the listening port (restart)"},
  {"hub", "logsize", CMD_ADMIN_SET_LOG_SIZE, B_LOGSIZE, 1, 0, CF_NONE, NULL, "hub logsize <MB|nk|nb>", "log file size limit (MB, or k/b suffix), at most 1024 MB"},
  {"hub", "purge", CMD_ADMIN_PURGE_TOMBSTONES, B_PURGE, 1, 0, CF_YN, NULL, "hub purge <now|days>", "purge tombstones now, or older than <days>"},
  {"hub", "autopurge", CMD_ADMIN_SET_PURGE_DAYS, B_ARG, 1, 0, CF_NONE, NULL, "hub autopurge <days>", "daily purge of tombstones older than <days> (0 = off)"},
  {"loglevel", NULL, CMD_ADMIN_SET_LOG_LEVEL, B_LOGLEVEL, 1, 1, CF_YN, NULL, "loglevel [file|console] <none|error|warning|info|debug>", "set the log file's (default) or the console log's level"},
  {"stats", NULL, CMD_ADMIN_STATS, B_NONE, 0, 0, CF_NONE, NULL, "stats", "traffic counters since the hub started"},
  {"allow", "list", CMD_ADMIN_LIST_ALLOWLIST, B_NONE, 0, 0, CF_NONE, NULL, "allow list", "the IP allowlist"},
  {"allow", "add", CMD_ADMIN_ADD_ALLOWLIST, B_ARG, 1, 0, CF_NONE, NULL, "allow add <ip[/n]>", "add to the allowlist"},
  {"allow", "del", CMD_ADMIN_DEL_ALLOWLIST, B_ARG, 1, 0, CF_YN, NULL, "allow del <ip[/n]>", "remove from the allowlist"},
  {"deny", "list", CMD_ADMIN_LIST_DENYLIST, B_NONE, 0, 0, CF_NONE, NULL, "deny list", "the IP denylist"},
  {"deny", "add", CMD_ADMIN_ADD_DENYLIST, B_ARG, 1, 0, CF_NONE, NULL, "deny add <ip[/n]>", "add to the denylist"},
  {"deny", "del", CMD_ADMIN_DEL_DENYLIST, B_ARG, 1, 0, CF_YN, NULL, "deny del <ip[/n]>", "remove from the denylist"},
  {"opt", "set", CMD_ADMIN_SET_OPT_FLAGS, B_OPT_SET, 1, 0, CF_YN, NULL, "opt set <flags|->", "set the network opt flags (- clears)"},
  {"opt", NULL, CMD_ADMIN_GET_OPT_FLAGS, B_NONE, 0, 0, CF_NONE, NULL, "opt", "the network opt flags"},
  {"admin", "list", CMD_ADMIN_LIST_ADMINS, B_NONE, 0, 0, CF_NONE, NULL, "admin list", "admin records"},
  {"admin", "add", CMD_ADMIN_ADD_ADMIN, B_PIPE, 3, 0, CF_NONE, NULL, "admin add <name> <pubkey> <mask>", "add an admin"},
  {"admin", "del", CMD_ADMIN_DEL_ADMIN, B_ARG, 1, 0, CF_TYPE_ARG, NULL, "admin del <name>", "remove an admin and their masks"},
  {"oper", "list", CMD_ADMIN_LIST_OPERS_V2, B_NONE, 0, 0, CF_NONE, NULL, "oper list", "oper records"},
  {"oper", "add", CMD_ADMIN_ADD_OPER_RECORD, B_PIPE, 3, 0, CF_NONE, NULL, "oper add <name> <pubkey> <mask>", "add an oper"},
  {"oper", "del", CMD_ADMIN_DEL_OPER_RECORD, B_ARG, 1, 0, CF_YN, NULL, "oper del <name>", "remove an oper and their masks"},
  {"mask", "add", CMD_ADMIN_ADD_USERMASK, B_PIPE, 2, 0, CF_NONE, NULL, "mask add <name> <mask>", "add a usermask to an admin or oper"},
  {"mask", "del", CMD_ADMIN_DEL_USERMASK, B_PIPE, 2, 0, CF_YN, NULL, "mask del <name> <mask>", "remove a usermask"},
  {"userkey", NULL, CMD_ADMIN_SET_USERKEY, B_PIPE, 2, 0, CF_YN, NULL, "userkey <name> <pubkey>", "replace an admin's or oper's key"},
  {"match", NULL, CMD_ADMIN_MATCH, B_ARG, 1, 0, CF_NONE, NULL, "match <name|*>", "a user's records, or everyone's"},
  {"chan", "list", CMD_ADMIN_LIST_CHANNELS, B_NONE, 0, 0, CF_NONE, NULL, "chan list", "managed channels"},
  {"chan", "add", CMD_ADMIN_ADD_CHANNEL, B_CHAN_ADD, 1, 1, CF_NONE, NULL, "chan add <#chan> [key]", "add a channel"},
  {"chan", "del", CMD_ADMIN_DEL_CHANNEL, B_ARG, 1, 0, CF_YN, NULL, "chan del <#chan>", "remove a channel from every bot"},
  {"op", NULL, CMD_ADMIN_OP_USER, B_PIPE, 2, 0, CF_NONE, NULL, "op <nick> <#chan>", "have the bots op a user"},
  {"upgrade", "status", CMD_ADMIN_UPGRADE_STATUS, B_FIXED, 0, 0, CF_NONE, "", "upgrade status", "the upgrade run on this hub"},
  {"upgrade", "releases", CMD_ADMIN_UPGRADE_STATUS, B_UPG_RELEASES, 0, 2, CF_NONE, NULL, "upgrade releases [bot=<base>] [hub=<base>]", "releases both products offer, and the nodes"},
  {"upgrade", "start", CMD_ADMIN_UPGRADE_NET, B_UPG_START, 1, 4, CF_TYPE_VER, NULL, "upgrade start <botver> [hub=<ver>] [nodes=<a,b=c>] [botbase=<url>] [hubbase=<url>]", "start a rolling network upgrade"},
  {"upgrade", "abort", CMD_ADMIN_UPGRADE_STATUS, B_FIXED, 0, 0, CF_YN, "abort", "upgrade abort", "stop the run and roll back"},
  {"upgrade", "forget", CMD_ADMIN_UPGRADE_STATUS, B_FIXED, 0, 0, CF_YN, "forget", "upgrade forget", "drop the roll-up plan on every hub"},
  {"tree", NULL, CMD_CONSOLE, B_FIXED, 0, 0, CF_NONE, "get|tree", "tree", "the network tree rows"},
  {"status", NULL, CMD_CONSOLE, B_FIXED, 0, 0, CF_NONE, "get|status", "status", "the status fields"},
  {"log", "on", 0, B_LOCAL, 0, 1, CF_NONE, NULL, "log on [level]", "line mode: show hub log lines"},
  {"log", "off", 0, B_LOCAL, 0, 0, CF_NONE, NULL, "log off", "line mode: stop log lines"},
  {"view", NULL, 0, B_LOCAL, 1, 0, CF_NONE, NULL, "view <1-5>", "console, log, network, upgrades, stats"},
  {"pane", NULL, 0, B_LOCAL, 0, 0, CF_NONE, NULL, "pane", "show or hide the tree pane (F3)"},
  {"ascii", NULL, 0, B_LOCAL, 0, 0, CF_NONE, NULL, "ascii", "plain ASCII lines for this session"},
  {"filter", NULL, 0, B_LOCAL, 1, 64, CF_NONE, NULL, "filter <text|clear>", "log view: only lines containing <text>"},
  {"clear", NULL, 0, B_LOCAL, 0, 0, CF_NONE, NULL, "clear", "clear the current view"},
};
#define NCMDS ((int)(sizeof(CMDS) / sizeof(CMDS[0])))

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
  cbuf_adds(&ui->term, s);
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
  for (const char *p = text; *p;) {           /* one CRLF line per '\n' */
    const char *nl = strchr(p, '\n');
    size_t n = nl ? (size_t)(nl - p) : strlen(p);
    cbuf_add(b, p, n);
    cbuf_add(b, "\r\n", 2);
    p = nl ? nl + 1 : p + n;
  }
  if (!hold) lm_prompt(ui);
}

/* Full screen: add a line to a view's scrollback. */
static void fs_add(console_ui_t *ui, int view, const char *text, int kind, int level) {
  sb_add(&ui->sb[view], text, kind, level);
  if (view != ui->view && (view != V_LOG || level <= LOG_WARNING)) ui->act[view] = true;
  ui->dirty = true;
}

static void fs_timestamped(console_ui_t *ui, int view, const char *text, int kind) {
  char buf[CONSOLE_INPUT_MAX + 32];
  time_t now = time(NULL);
  struct tm tmv;
  localtime_r(&now, &tmv);
  usnprintf(buf, sizeof(buf), "%02d:%02d:%02d %s", tmv.tm_hour, tmv.tm_min,
           tmv.tm_sec, text);
  fs_add(ui, view, buf, kind, LOG_INFO);
}

/* A console-side message (help, a refused command) in either mode. */
static void note(console_ui_t *ui, const char *text, int kind) {
  if (ui->line_mode) lm_line(ui, text);
  else fs_timestamped(ui, V_CONSOLE, text, kind);
}

/* ==========================================================================
 * Replies and events from the core
 * ========================================================================== */
/* docs/console.md §3.2: an error reply starts with "ERR" (any case) or is
 * exactly "Buffer overflow". */
static bool reply_is_error(const char *r, size_t len) {
  static const char BO[] = "Buffer overflow";
  return (len >= 3 && strncasecmp(r, "ERR", 3) == 0) ||
         (len == sizeof(BO) - 1 && memcmp(r, BO, len) == 0);
}

/* Split a reply into sanitized lines, dropping empty trailing ones.  Calls
 * fn for each line.  Returns the first line in first (if given). */
static void each_line(const char *text, size_t len,
                      void (*fn)(console_ui_t *, const char *, int), console_ui_t *ui,
                      int kind, char *first, size_t first_cap) {
  size_t end = len;
  while (end > 0 && (text[end - 1] == '\n' || text[end - 1] == '\r' ||
                     text[end - 1] == ' '))
    end--;
  if (first && first_cap) first[0] = '\0';
  bool got_first = false;
  for (size_t i = 0; i < end;) {
    size_t j = i;
    while (j < end && text[j] != '\n') j++;
    size_t n = j - i;
    if (n > 0 && text[i + n - 1] == '\r') n--;
    char *clean = malloc(n * 1 + 2);
    if (clean) {
      console_sanitize(text + i, n, clean, n + 2);
      if (!got_first && first) {
        usnprintf(first, first_cap, "%s", clean);
        got_first = true;
      }
      fn(ui, clean, kind);
      free(clean);
    }
    i = j + 1;
  }
}

static void emit_reply_line(console_ui_t *ui, const char *line, int kind) {
  if (ui->line_mode) lm_line(ui, line);
  else fs_add(ui, V_CONSOLE, line, kind, LOG_INFO);
}

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

static void marker_err(console_ui_t *ui, int seq, const char *why) {
  if (ui->line_mode) {
    char m[CONSOLE_INPUT_MAX + 32];
    usnprintf(m, sizeof(m), "[err #%d] %s", seq, why);
    lm_line(ui, m);
  } else {
    fs_timestamped(ui, V_CONSOLE, why, L_ERR);
  }
}

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
      /* keep the newlines, clean each line */
      size_t o = 0;
      for (size_t i = 0; i < len;) {
        size_t j = i;
        while (j < len && text[j] != '\n') j++;
        o += console_sanitize(text + i, j - i, *dst + o, len + 1 - o);
        if (j < len && o + 1 < len + 1) (*dst)[o++] = '\n';
        i = j + 1;
      }
      (*dst)[o] = '\0';
    }
    ui->dirty = true;
    return;
  }
  if (rq.kind != RQ_USER) return;

  char first[256];
  bool err = len > 0 && reply_is_error(text, len);
  each_line(text, len, emit_reply_line, ui, err ? L_ERR : L_NORMAL, first,
            sizeof(first));
  if (err) {
    if (ui->line_mode) {
      char m[320];
      usnprintf(m, sizeof(m), "[err #%d] %s", rq.seq, first);
      lm_line(ui, m);
    }
  } else {
    marker_ok(ui, rq.seq, rq.words);
  }
  audit(ui, rq.audit_level, "[CONSOLE] %s@%s #%d %s -> %s%.120s", ui->admin,
        ui->ip, rq.seq, rq.audit, err ? "err: " : "ok", err ? first : "");
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
    ui->dirty = true;
  } else if (!strcmp(topic, "tree")) {
    free(ui->tree);
    /* each row keeps its newline, and a last row without one gains it:
     * at most dl + 1 bytes of rows, then the NUL */
    ui->tree = malloc(dl + 2);
    if (!ui->tree) return;
    /* sanitize each row, keep the newlines */
    size_t o = 0;
    int rows = 0;
    for (size_t i = 0; i < dl;) {
      size_t j = i;
      while (j < dl && data[j] != '\n') j++;
      if (j > i) {
        o += console_sanitize(data + i, j - i, ui->tree + o, dl + 2 - o);
        ui->tree[o++] = '\n';
        rows++;
      }
      i = j + 1;
    }
    ui->tree[o] = '\0';
    if (ui->line_mode) {
      size_t cap = o + (size_t)rows * 12 + 64;
      char *blk = malloc(cap);
      if (blk) {
        size_t b = (size_t)usnprintf(blk, cap, "[evt tree] begin %d\n", rows);
        for (const char *p = ui->tree; *p;) {
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
      char line[CONSOLE_LOG_LINE_MAX + 32];
      usnprintf(line, sizeof(line), "[log %s] %s", LEVEL_WORD[level], clean);
      lm_async(ui, line);
    } else {
      int kind = level == LOG_ERROR ? L_ERR : level == LOG_WARNING ? L_WARN
               : level == LOG_DEBUG ? L_DIM : L_NORMAL;
      fs_add(ui, V_LOG, clean, kind, level);
    }
  } else if (!strcmp(topic, "drop")) {
    unsigned long n = strtoul(data, NULL, 10);
    ui->dropped += n;
  }
}

void ui_core_frame(console_ui_t *ui, uint8_t op, const char *payload, size_t len,
                   long long now_ms) {
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

static const cmd_def_t *find_cmd(const words_t *ws, int *argi) {
  const char *c = ws->w[0];
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

static void show_help(console_ui_t *ui, const char *topic) {
  char line[256];
  for (int i = 0; i < NCMDS; i++) {
    if (topic && strcasecmp(CMDS[i].cmd, topic) != 0) continue;
    usnprintf(line, sizeof(line), "%-44s %s", CMDS[i].usage, CMDS[i].help);
    note(ui, line, L_INFO);
  }
  if (!topic && !ui->line_mode) {
    note(ui, "Alt+1..5 views, Alt+Left/Right cycle, F2 log level, F3 tree pane, "
             "PgUp/PgDn/End scroll, Tab completes, Ctrl-C cancels", L_INFO);
  }
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
    marker_err(ui, rq->seq, "too many requests in flight");
    return;
  }
  ui->rq[ui->rq_n++] = *rq;
  core_frame(ui, op, payload, len);
  ui->user_busy = true;
}

static void local_command(console_ui_t *ui, const cmd_def_t *c, const words_t *ws,
                          int argi, const char *line, int seq, const char *words) {
  const char *a1 = ws->n > argi ? ws->w[argi] : NULL;
  if (!strcmp(c->cmd, "help")) {
    if (a1 && !cmd_known_word(a1)) {
      marker_err(ui, seq, "unknown command");
      return;
    }
    show_help(ui, a1);
  } else if (!strcmp(c->cmd, "quit")) {
    marker_ok(ui, seq, words);
    ui->closing = true;
    usnprintf(ui->close_why, sizeof(ui->close_why), "quit");
    return;
  } else if (!strcmp(c->cmd, "log")) {
    if (!ui->line_mode) {
      marker_err(ui, seq, "the log is the Alt+2 view in the full-screen console");
      return;
    }
    if (!strcmp(c->sub, "on")) {
      int lvl = a1 ? level_arg(a1) : LOG_INFO;
      if (lvl <= 0) {
        marker_err(ui, seq, "level: error, warning, info or debug");
        return;
      }
      ui->log_on = true;
      ui->log_sub_level = lvl;
    } else {
      ui->log_on = false;
    }
    subscribe(ui);
  } else {
    if (ui->line_mode) {
      marker_err(ui, seq, "not available in line mode");
      return;
    }
    if (!strcmp(c->cmd, "view")) {
      if (!a1 || strlen(a1) != 1 || a1[0] < '1' || a1[0] > '5') {
        marker_err(ui, seq, "view 1-5");
        return;
      }
      ui->view = a1[0] - '1';
      ui->act[ui->view] = false;
    } else if (!strcmp(c->cmd, "pane")) {
      if (ui->cols >= CONSOLE_PANE_MIN_COLS) ui->pane_user_off = !ui->pane_user_off;
      else ui->overlay = !ui->overlay;
    } else if (!strcmp(c->cmd, "ascii")) {
      ui->ascii = !ui->ascii;
      ui->full_redraw = true;
    } else if (!strcmp(c->cmd, "filter")) {
      const char *rest = line + ws->off[argi];
      if (!strcasecmp(rest, "clear")) ui->filter[0] = '\0';
      else usnprintf(ui->filter, sizeof(ui->filter), "%s", rest);
    } else if (!strcmp(c->cmd, "clear")) {
      if (ui->view == V_CONSOLE || ui->view == V_LOG) sb_clear(&ui->sb[ui->view]);
      ui->anchor[ui->view] = -1;
    }
    ui->dirty = true;
  }
  marker_ok(ui, seq, words);
}

/* Build the request payload; false (with *why) when the arguments are bad. */
static bool build_payload(console_ui_t *ui, const cmd_def_t *c, const words_t *ws,
                          int argi, unsigned char *out, size_t *outlen,
                          const char **why) {
  (void)ui;
  int na = ws->n - argi;
  const char *const *a = (const char *const *)&ws->w[argi];
  char *o = (char *)out;
  size_t cap = 1024;
  int w = 0;
  switch (c->build) {
  case B_NONE:
    *outlen = 0;
    return true;
  case B_FIXED:
    *outlen = (size_t)usnprintf(o, cap, "%s", c->fixed);
    return true;
  case B_ARG:
    w = usnprintf(o, cap, "%s", a[0]);
    break;
  case B_OPTARG:
    w = usnprintf(o, cap, "%s", na > 0 ? a[0] : "");
    break;
  case B_PIPE:
  case B_COLON: {
    char sep = c->build == B_PIPE ? '|' : ':';
    size_t off = 0;
    for (int i = 0; i < na; i++) {
      if (c->build == B_COLON && strchr(a[i], ':')) {
        *why = "':' is not allowed in an argument here";
        return false;
      }
      int k = usnprintf(o + off, cap - off, "%s%s", i ? (char[2]){sep, 0} : "", a[i]);
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
    w = usnprintf(o, cap, "%s:%s:%s:%s:%s", a[0], a[1], a[2],
                 strcmp(a[3], "-") ? a[3] : "", a[4]);
    break;
  case B_CHAN_ADD:
    w = usnprintf(o, cap, "%s|%s", a[0], na > 1 ? a[1] : "");
    break;
  case B_OPT_SET:
    w = usnprintf(o, cap, "%s", strcmp(a[0], "-") ? a[0] : "");
    break;
  case B_LOGLEVEL: {
    /* <target><level>: target 0 = the log file, 1 = the console log. */
    int target = 0;
    if (na == 2) {
      if (strcasecmp(a[0], "file") == 0) target = 0;
      else if (strcasecmp(a[0], "console") == 0) target = 1;
      else {
        *why = "target: file or console";
        return false;
      }
    }
    int lvl = level_arg(a[na - 1]);
    if (lvl < 0) {
      *why = "level: none, error, warning, info, debug or 0-4";
      return false;
    }
    out[0] = (unsigned char)target;
    out[1] = (unsigned char)lvl;
    *outlen = 2;
    return true;
  }
  case B_LOGSIZE: {
    /* <n> MB, <n>k KiB or <n>b bytes, at most 1024 MB (the hub clamps it
     * to its own limits). */
    char num[16];
    size_t al = strlen(a[0]);
    unsigned long long mult = 1024ull * 1024ull;
    usnprintf(num, sizeof(num), "%s", a[0]);
    if (al > 1 && al < sizeof(num) && strchr("kKbB", a[0][al - 1])) {
      mult = (a[0][al - 1] == 'k' || a[0][al - 1] == 'K') ? 1024ull : 1ull;
      num[al - 1] = '\0';
    }
    unsigned long long v = all_digits(num) ? strtoull(num, NULL, 10) * mult : 0;
    if (v < 1 || v > 1024ull * 1024ull * 1024ull) {
      *why = "size: <MB>, <n>k or <n>b, at most 1024 MB";
      return false;
    }
    uint32_t bytes = htonl((uint32_t)v);
    memcpy(out, &bytes, 4);
    *outlen = 4;
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
    w = usnprintf(o, cap, "%s||||%s|%s|%s|%s", a[0], bb, hubv, *hubv ? hb : "",
                 nodes);
    break;
  }
  case B_LOCAL:
    *outlen = 0;
    return true;
  }
  if (w < 0 || (size_t)w >= cap) {
    *why = "arguments too long";
    return false;
  }
  *outlen = (size_t)w;
  return true;
}

static void run_line(console_ui_t *ui, const char *line) {
  while (*line == ' ') line++;
  if (!*line) return;
  if (ui->user_busy || ui->confirming) {
    if (ui->queued_n < MAX_QUEUED_LINES) ui->queued[ui->queued_n++] = strdup(line);
    else note(ui, "busy: line dropped", L_ERR);
    return;
  }
  const char *l = line[0] == '/' ? line + 1 : line;
  int seq = ++ui->seq;
  words_t ws;
  split_words(l, &ws);
  if (ws.n == 0) {
    marker_err(ui, seq, "empty command");
    return;
  }
  int argi = 1;
  const cmd_def_t *c = find_cmd(&ws, &argi);
  if (!c) {
    if (cmd_known_word(ws.w[0])) {
      char why[128];
      usnprintf(why, sizeof(why), "usage: see help %s", ws.w[0]);
      marker_err(ui, seq, why);
    } else {
      marker_err(ui, seq, "unknown command (help lists them)");
    }
    return;
  }
  char words[32];
  usnprintf(words, sizeof(words), "%s%s%s", c->cmd, c->sub ? " " : "",
           c->sub ? c->sub : "");
  int na = ws.n - argi;
  if (na < c->nargs || (c->build != B_LOCAL && na > c->nargs + c->optargs) ||
      (c->build == B_LOCAL && strcmp(c->cmd, "filter") && na > c->nargs + c->optargs)) {
    char why[160];
    usnprintf(why, sizeof(why), "usage: %s", c->usage);
    marker_err(ui, seq, why);
    return;
  }
  for (int i = argi; i < ws.n; i++)
    if (c->build != B_LOCAL && strchr(ws.w[i], '|')) {
      marker_err(ui, seq, "'|' is not allowed in an argument");
      return;
    }
  if (!ui->line_mode) {
    char echo[CONSOLE_INPUT_MAX + 4];
    usnprintf(echo, sizeof(echo), "> %s", l);
    fs_timestamped(ui, V_CONSOLE, echo, L_CMD);
  }
  if (c->build == B_LOCAL) {
    local_command(ui, c, &ws, argi, l, seq, words);
    return;
  }

  unsigned char payload[1024];
  size_t plen = 0;
  const char *why = NULL;
  if (!build_payload(ui, c, &ws, argi, payload, &plen, &why)) {
    marker_err(ui, seq, why ? why : "bad arguments");
    return;
  }

  pending_rq_t rq;
  memset(&rq, 0, sizeof(rq));
  rq.kind = RQ_USER;
  rq.seq = seq;
  usnprintf(rq.words, sizeof(rq.words), "%s", words);
  usnprintf(rq.audit, sizeof(rq.audit), "%.300s", l);
  rq.audit_level = (c->confirm != CF_NONE || c->op == CMD_ADMIN_SET_LOG_LEVEL)
                       ? LOG_WARNING : LOG_INFO;

  /* An optional argument that was left out asks nothing (peer del alone
   * lists what could be deleted). */
  if (c->confirm == CF_NONE || (c->build == B_OPTARG && na == 0)) {
    send_request(ui, c->op, payload, plen, &rq);
    return;
  }
  /* Ask first; the next line answers. */
  ui->confirming = c->confirm;
  ui->confirm_seq = seq;
  ui->confirm_op = c->op;
  memcpy(ui->confirm_payload, payload, plen);
  ui->confirm_len = plen;
  ui->confirm_rq = rq;
  const char *a1 = na > 0 ? ws.w[argi] : "";
  switch (c->confirm) {
  case CF_YN: {
    /* every argument: "Really loglevel console debug?" */
    char all[256] = "";
    size_t o = 0;
    for (int i = argi; i < ws.n && o < sizeof(all); i++)
      o += (size_t)usnprintf(all + o, sizeof(all) - o, "%s%s", i > argi ? " " : "", ws.w[i]);
    ui->confirm_want[0] = '\0';
    usnprintf(ui->confirm_q, sizeof(ui->confirm_q), "Really %s %s? (y/N)", words, all);
    break;
  }
  case CF_TYPE_ARG:
    usnprintf(ui->confirm_want, sizeof(ui->confirm_want), "%s", a1);
    usnprintf(ui->confirm_q, sizeof(ui->confirm_q), "Type '%s' to confirm %s:", a1, words);
    break;
  case CF_TYPE_HUB:
    usnprintf(ui->confirm_want, sizeof(ui->confirm_want), "%s",
             ui->hubname[0] ? ui->hubname : "hub");
    usnprintf(ui->confirm_q, sizeof(ui->confirm_q),
             "Type the hub name '%s' to confirm %s:", ui->confirm_want, words);
    break;
  case CF_TYPE_VER:
    usnprintf(ui->confirm_want, sizeof(ui->confirm_want), "%s", a1);
    usnprintf(ui->confirm_q, sizeof(ui->confirm_q),
             "Type the bot version '%s' to start the upgrade:", a1);
    break;
  case CF_NONE:
    break;
  }
  if (ui->line_mode) {
    char m[320];
    usnprintf(m, sizeof(m), "[confirm #%d] %s", seq, ui->confirm_q);
    lm_line(ui, m);
  } else {
    fs_timestamped(ui, V_CONSOLE, ui->confirm_q, L_WARN);
  }
}

static void confirm_answer(console_ui_t *ui, const char *answer, bool cancelled) {
  confirm_t kind = ui->confirming;
  ui->confirming = CF_NONE;
  bool ok = !cancelled &&
            (kind == CF_YN ? (!strcasecmp(answer, "y") || !strcasecmp(answer, "yes"))
                           : !strcmp(answer, ui->confirm_want));
  if (!ok) {
    marker_err(ui, ui->confirm_seq, "cancelled");
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
enum ck { CK_NONE, CK_CMD, CK_WORDS, CK_BOT, CK_BOT_ON, CK_HUB };

typedef struct {
  const char *cmd, *sub;
  int         pos;   /* argument index after cmd [sub]; -1 = any */
  enum ck     kind;
  const char *words; /* CK_WORDS: space separated */
} arg_comp_t;

#define LEVEL_WORDS "none error warning info debug"
static const arg_comp_t ARG_COMP[] = {
  {"help", NULL, 0, CK_CMD, NULL},
  {"bot", "del", 0, CK_BOT, NULL},
  {"bot", "kick", 0, CK_BOT_ON, NULL},
  {"bot", "rekey", 0, CK_BOT, NULL},
  {"peer", "setkey", 0, CK_HUB, NULL},
  {"hub", "purge", 0, CK_WORDS, "now"},
  {"loglevel", NULL, 0, CK_WORDS, "file console " LEVEL_WORDS},
  {"loglevel", NULL, 1, CK_WORDS, LEVEL_WORDS}, /* after file|console */
  {"log", "on", 0, CK_WORDS, LEVEL_WORDS},
  {"view", NULL, 0, CK_WORDS, "1 2 3 4 5"},
  {"filter", NULL, 0, CK_WORDS, "clear"},
  {"upgrade", "releases", -1, CK_WORDS, "bot= hub="},
  {"upgrade", "start", -1, CK_WORDS, "hub= nodes= botbase= hubbase="},
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
  if (!strcasecmp(w[0], "loglevel") && pos == 1 &&
      strcasecmp(w[1], "file") && strcasecmp(w[1], "console"))
    return 0;
  const arg_comp_t *ac = NULL;
  for (int i = 0; i < NARGCOMP && !ac; i++)
    if (!strcasecmp(ARG_COMP[i].cmd, w[0]) &&
        (ARG_COMP[i].sub ? sub && !strcmp(ARG_COMP[i].sub, sub) : !sub) &&
        (ARG_COMP[i].pos < 0 || ARG_COMP[i].pos == pos))
      ac = &ARG_COMP[i];
  if (!ac) return 0;
  if (ac->kind == CK_CMD) {
    for (int i = 0; i < NCMDS; i++) ADD_CAND(CMDS[i].cmd);
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
  /* uuids from the tree rows: H|depth|name|uuid|..., B|depth|nick|uuid|...,
   * D|nick|uuid|... (a bot that is offline) */
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
      const char *uuid = NULL;
      char ty = nf ? f[0][0] : 0;
      if (ac->kind == CK_HUB && ty == 'H' && nf >= 4) uuid = f[3];
      else if ((ac->kind == CK_BOT || ac->kind == CK_BOT_ON) && ty == 'B' && nf >= 4) uuid = f[3];
      else if (ac->kind == CK_BOT && ty == 'D' && nf >= 3) uuid = f[2];
      if (uuid && strcmp(uuid, "-")) {
        usnprintf(pool[*pooln], 72, "%s", uuid);
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
    note(ui, line, L_INFO);
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
  case L_CMD:  return "0;1";
  case L_ERR:  return "0;31";
  case L_OK:   return "0;32";
  case L_INFO: return "0;36";
  case L_WARN: return "0;33";
  case L_DIM:  return "0;90";
  default:     return SGR_RESET;
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
    if (used + cw > lim) break;
    cbuf_add(&r->b, s + i, ul);
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

/* ---- tree rows ---- */
typedef struct {
  char type;          /* H B D */
  int  depth;
  char name[64], uuid[64], ver[24], var[8], server[72];
  bool online;
  long long started;  /* H/B: start time, D: last seen */
} trow_t;

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

#define MAX_TROWS 1400

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

/* A text blob (upgrade status, stats) shown from line anchor[view] on. */
static void blob_rows(const console_ui_t *ui, int view, const char *text, int W,
                      int H, rowb_t *rows, int col0) {
  long long top = ui->anchor[view] < 0 ? 0 : ui->anchor[view];
  long long line = 0;
  int y = 0;
  for (const char *p = text; p && *p && y < H;) {
    const char *nl = strchr(p, '\n');
    size_t ll = nl ? (size_t)(nl - p) : strlen(p);
    if (line++ >= top) {
      char buf[1024];
      usnprintf(buf, sizeof(buf), "%.*s", (int)(ll < sizeof(buf) - 1 ? ll : sizeof(buf) - 1), p);
      rb_sgr(&rows[y], SGR_RESET);
      rb_text(&rows[y], buf, W);
      rb_pad(&rows[y], col0 + W);
      y++;
    }
    p = nl ? nl + 1 : NULL;
  }
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
    if (t->started > 0) {
      time_t ts = (time_t)t->started;
      struct tm tmv;
      localtime_r(&ts, &tmv);
      strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S", &tmv);
    }
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
  time_t now = time(NULL);
  struct tm tmv;
  localtime_r(&now, &tmv);
#define SEG(p, sg, ...) do { if (n < 16) { usnprintf(s[n].text, sizeof(s[n].text), __VA_ARGS__); s[n].prio = p; s[n].sgr = sg; n++; } } while (0)
  const char *hn = ui->hubname[0] ? ui->hubname : "hub";
  SEG(1, SGR_STATUS, "%02d:%02d %.*s %.*s", tmv.tm_hour, tmv.tm_min, uprec(hn, 40), hn,
      uprec(ui->admin, 40), ui->admin);
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

static void compose(console_ui_t *ui, rowb_t *rows, int *cur_row, int *cur_col,
                    long long now_ms) {
  int C = ui->cols, R = ui->rows;
  for (int y = 0; y < R; y++) rb_start(&rows[y], y == R - 1 ? C - 1 : C);
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
      if (n >= sizeof(buf)) n = sizeof(buf) - 1;
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
    blob_rows(ui, ui->view, text ? text : "(asking the hub...)", main_w, H, body, 0);
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
  }
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
  ui->started = true;
  subscribe(ui);
  char hello[256];
  usnprintf(hello, sizeof(hello), "irchub console %s on %s - logged in as %s",
           HUB_VERSION, ui->hubname[0] ? ui->hubname : "hub", ui->admin);
  if (ui->line_mode) {
    lm_line(ui, hello);
    lm_prompt(ui);
    return;
  }
  /* alternate screen, bracketed paste */
  cbuf_adds(&ui->term, "\x1b[?1049h\x1b[?2004h\x1b[H\x1b[2J");
  fs_timestamped(ui, V_CONSOLE, hello, L_INFO);
  fs_timestamped(ui, V_CONSOLE, "help lists the commands; Alt+1..5 switch views "
                 "(or: view <n>)", L_INFO);
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
      fs_add(ui, V_LOG, m, L_WARN, LOG_ERROR);
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
