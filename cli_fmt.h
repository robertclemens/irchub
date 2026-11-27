#ifndef CLI_FMT_H
#define CLI_FMT_H

/* The command-line screens (-setup, -id, -p): one layout for the bot and
 * the hub, C and Rust byte-identical (cli_fmt.rs).  Unicode rules and
 * marks, or an ASCII set when the locale is not UTF-8 (LC_ALL, LC_CTYPE,
 * LANG); never ANSI colors, so a pasted or logged screen stays clean.
 *
 *    ircbot 2.5.4 · setup
 *    ────────────────────────────────────────────────────────────────────
 *
 *    1  Config password
 *       password     ········
 *       confirm      ········
 *       ✓ the passwords match
 *
 *    ─ Summary ──────────────────────────────────────────────────────────
 *      mode          hub-managed · 2 hubs
 */

#include <stdbool.h>
#include <stddef.h>

#define CLI_W        72 /* the rule's width, and where notes wrap          */
#define CLI_LABEL_W  12 /* a step's answer labels                          */
#define CLI_SLABEL_W 12 /* the summary's labels                            */

typedef enum { CLI_G_RULE, CLI_G_DOT, CLI_G_OK, CLI_G_FAIL, CLI_G_MORE, CLI_G_SECRET } cli_glyph_t;

const char *cli_g(cli_glyph_t g);
void cli_header(const char *prog, const char *version, const char *what);
void cli_step(int n, const char *title);
void cli_note(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void cli_kv(const char *label, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void cli_ok(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void cli_err(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void cli_ask(const char *label, char *buf, size_t len);
void cli_ask_secret(const char *label, char *buf, size_t len);
bool cli_ask_yes(const char *label, bool dflt);
void cli_summary(const char *title);
void cli_skv(const char *label, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void cli_rule(void);
/* "abcdefgh…wxyz=": a long key shortened for a summary line */
const char *cli_short(const char *s, char *out, size_t cap);

#endif
