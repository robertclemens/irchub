#include "cli_fmt.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static int g_utf8 = -1; /* -1 = not looked at yet */

/* UTF-8 when the first set of LC_ALL, LC_CTYPE, LANG names it (the order
 * the C library itself uses); setlocale() is never called. */
static bool utf8(void) {
  if (g_utf8 < 0) {
    const char *v = getenv("LC_ALL");
    if (!v || !*v) v = getenv("LC_CTYPE");
    if (!v || !*v) v = getenv("LANG");
    char low[64] = "";
    for (size_t i = 0; v && v[i] && i < sizeof(low) - 1; i++)
      low[i] = (char)tolower((unsigned char)v[i]);
    g_utf8 = strstr(low, "utf-8") || strstr(low, "utf8");
  }
  return g_utf8 == 1;
}

const char *cli_g(cli_glyph_t g) {
  static const char *const U[] = {"─", "·", "✓", "✗", "…", "·"};
  static const char *const A[] = {"-", "-", "ok", "x", "...", "*"};
  if ((int)g < 0 || g > CLI_G_SECRET) return "?";
  return utf8() ? U[g] : A[g];
}

static void rep(const char *s, int n) {
  for (int i = 0; i < n; i++) fputs(s, stdout);
}

void cli_rule(void) {
  fputs(" ", stdout);
  rep(cli_g(CLI_G_RULE), CLI_W);
  fputs("\n", stdout);
}

void cli_header(const char *prog, const char *version, const char *what) {
  printf("\n %s %s %s %s\n", prog, version, cli_g(CLI_G_DOT), what);
  cli_rule();
}

void cli_step(int n, const char *title) { printf("\n %d  %s\n", n, title); }

/* Text wrapped at CLI_W, indented to the answers' column. */
static void wrap(const char *indent, const char *text) {
  size_t ind = strlen(indent);
  const char *p = text;
  while (*p) {
    while (*p == ' ') p++;
    if (!*p) break;
    size_t room = CLI_W > ind ? CLI_W - ind : 20, take = 0, last_space = 0;
    while (p[take] && p[take] != '\n' && take < room) {
      if (p[take] == ' ') last_space = take;
      take++;
    }
    if (p[take] && p[take] != '\n' && last_space) take = last_space;
    size_t show = take;
    while (show && p[show - 1] == ' ') show--; /* no trailing blanks */
    printf("%s%.*s\n", indent, (int)show, p);
    p += take;
    if (*p == '\n') p++;
  }
}

void cli_note(const char *fmt, ...) {
  char buf[1024];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  wrap("    ", buf);
}

void cli_kv(const char *label, const char *fmt, ...) {
  char buf[1024];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  printf("    %-*s %s\n", CLI_LABEL_W, label, buf);
}

static void mark(cli_glyph_t g, const char *fmt, va_list ap) {
  char buf[1024];
  vsnprintf(buf, sizeof(buf), fmt, ap);
  printf("    %s %s\n", cli_g(g), buf);
}

void cli_ok(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  mark(CLI_G_OK, fmt, ap);
  va_end(ap);
}

void cli_err(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  mark(CLI_G_FAIL, fmt, ap);
  va_end(ap);
}

static void read_line(char *buf, size_t len) {
  if (!fgets(buf, (int)len, stdin)) {
    buf[0] = '\0';
    return;
  }
  if (strlen(buf) == len - 1 && !strchr(buf, '\n')) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF)
      ;
  }
  buf[strcspn(buf, "\r\n")] = '\0';
}

void cli_ask(const char *label, char *buf, size_t len) {
  printf("    %-*s ", CLI_LABEL_W, label);
  fflush(stdout);
  read_line(buf, len);
}

/* No echo; the line then shows a fixed run of dots, never the length. */
void cli_ask_secret(const char *label, char *buf, size_t len) {
  printf("    %-*s ", CLI_LABEL_W, label);
  fflush(stdout);
  struct termios oldt, newt;
  bool tty = tcgetattr(STDIN_FILENO, &oldt) == 0;
  if (tty) {
    newt = oldt;
    newt.c_lflag &= ~(tcflag_t)ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  }
  read_line(buf, len);
  if (tty) tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  rep(cli_g(CLI_G_SECRET), 8);
  fputs("\n", stdout);
}

bool cli_ask_yes(const char *label, bool dflt) {
  char q[128], a[16];
  snprintf(q, sizeof(q), "%s %s", label, dflt ? "(Y/n)" : "(y/N)");
  printf("    %s ", q);
  fflush(stdout);
  read_line(a, sizeof(a));
  if (!a[0]) return dflt;
  return a[0] == 'y' || a[0] == 'Y';
}

void cli_summary(const char *title) {
  printf("\n %s %s ", cli_g(CLI_G_RULE), title);
  int used = 3 + (int)strlen(title) + 1; /* " ─ title " */
  rep(cli_g(CLI_G_RULE), CLI_W + 1 - used > 0 ? CLI_W + 1 - used : 3);
  fputs("\n", stdout);
}

void cli_skv(const char *label, const char *fmt, ...) {
  char buf[1024];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  printf("   %-*s %s\n", CLI_SLABEL_W, label, buf);
}

const char *cli_short(const char *s, char *out, size_t cap) {
  size_t n = s ? strlen(s) : 0;
  if (n <= 16) snprintf(out, cap, "%s", s ? s : "");
  else snprintf(out, cap, "%.8s%s%s", s, cli_g(CLI_G_MORE), s + n - 4);
  return out;
}
