/* SSH admin console — one session's user interface (hub_console_ui.c).
 * Pure state machine: bytes from the terminal and frames from the core go
 * in; bytes for the terminal, frames for the core and audit lines come out.
 * It knows nothing about SSH (hub_console.c drives it) and nothing about
 * hub_state_t (the core answers its frames).  docs/console.md. */
#ifndef HUB_CONSOLE_UI_H
#define HUB_CONSOLE_UI_H

#include "hub_console.h"

/* Bytes waiting for the terminal above this: line mode drops events and log
 * lines (and says so), the full-screen console skips redraws. */
#define CONSOLE_TERM_OUTQ_MAX (256 * 1024)
#define CONSOLE_SCROLLBACK    2000   /* lines kept per output view         */
#define CONSOLE_LOG_SCROLLBACK 5000  /* lines kept by the log view         */
#define CONSOLE_HISTORY       100    /* input lines remembered (session)   */
#define CONSOLE_INPUT_MAX     1024   /* bytes on the input line            */
#define CONSOLE_ESC_MS        50     /* a lone ESC after this long         */
#define CONSOLE_RESIZE_MS     50     /* window-change bursts coalesce      */
#define CONSOLE_MIN_COLS      40
#define CONSOLE_MIN_ROWS      10
#define CONSOLE_PANE_MIN_COLS 80     /* narrower: the tree becomes an overlay */
#define CONSOLE_PANE_MIN      24
#define CONSOLE_PANE_MAX      40
#define CONSOLE_STATS_REFRESH_MS 5000
#define CONSOLE_UPG_REFRESH_MS   10000

typedef struct {
  unsigned char *p;
  size_t len, cap;
} cbuf_t;

void cbuf_add(cbuf_t *b, const void *data, size_t n);
void cbuf_adds(cbuf_t *b, const char *s);
void cbuf_consume(cbuf_t *b, size_t n);
void cbuf_free(cbuf_t *b);

typedef struct console_ui console_ui_t;

console_ui_t *ui_new(bool line_mode, int cols, int rows, const char *admin,
                     const char *ip, const char *hubname);
void ui_free(console_ui_t *ui);
/* Greeting, first draw, subscriptions. */
void ui_start(console_ui_t *ui, long long now_ms);
void ui_input(console_ui_t *ui, const unsigned char *data, size_t n,
              long long now_ms);
void ui_resize(console_ui_t *ui, int cols, int rows, long long now_ms);
void ui_core_frame(console_ui_t *ui, uint8_t op, const char *payload,
                   size_t len, long long now_ms);
/* Timers: ESC timeout, coalesced redraws, view refreshes, idle timeout. */
void ui_tick(console_ui_t *ui, long long now_ms);
cbuf_t *ui_term_out(console_ui_t *ui);
cbuf_t *ui_core_out(console_ui_t *ui);
/* True once the session should end; *why says why (shown / logged). */
bool ui_closing(const console_ui_t *ui, const char **why);
/* Next audit line, if any: returns false when there is none. */
bool ui_take_audit(console_ui_t *ui, int *level, char *buf, size_t cap);
/* True while a command is in flight, queued or waiting for confirmation. */
bool ui_busy(const console_ui_t *ui);
/* Text for the terminal on the way out (restores the screen). */
void ui_goodbye(console_ui_t *ui, const char *why);

#endif
