#include "glob_overlap.h"

#include <stddef.h>
#include <string.h>

/* ASCII-only fold: a locale must never change what a ban mask protects. */
static unsigned char gfold(unsigned char c) {
  return (c >= 'A' && c <= 'Z') ? (unsigned char)(c + 32) : c;
}

bool glob_overlap(const char *a, const char *b) {
  if (!a || !b)
    return true;
  size_t la = strlen(a), lb = strlen(b);
  if (la > GLOB_OVERLAP_MAX || lb > GLOB_OVERLAP_MAX)
    return true;

  /* ov[i][j]: do a[i..] and b[j..] share a string?  Filled from the ends
   * backwards; only the row below (i+1) and the current row are needed. */
  unsigned char row_a[GLOB_OVERLAP_MAX + 2], row_b[GLOB_OVERLAP_MAX + 2];
  unsigned char *next = row_a, *cur = row_b;

  for (size_t i = la + 1; i-- > 0;) {
    for (size_t j = lb + 1; j-- > 0;) {
      unsigned char r;
      if (i == la && j == lb) {
        r = 1;
      } else {
        bool sa = (i < la && a[i] == '*');
        bool sb = (j < lb && b[j] == '*');
        r = 0;
        if (sa) {
          /* a's star takes nothing, or swallows b[j] (any element of b). */
          if (next[j])
            r = 1;
          else if (j < lb && cur[j + 1])
            r = 1;
        }
        if (!r && sb) {
          if (cur[j + 1])
            r = 1;
          else if (i < la && next[j])
            r = 1;
        }
        if (!r && i < la && j < lb && !sa && !sb) {
          unsigned char x = (unsigned char)a[i], y = (unsigned char)b[j];
          if ((x == '?' || y == '?' || gfold(x) == gfold(y)) && next[j + 1])
            r = 1;
        }
      }
      cur[j] = r;
    }
    unsigned char *t = next;
    next = cur;
    cur = t;
  }
  /* The last row filled (i == 0) was swapped into `next`. */
  return next[0] != 0;
}

/* Split "nick!user@host" into its three parts (each at most GLOB_OVERLAP_MAX
 * bytes, which a whole pattern within the limit always satisfies). */
static bool hm_split(const char *m, char nick[], char user[], char host[]) {
  const char *bang = strchr(m, '!');
  const char *at = bang ? strchr(bang + 1, '@') : NULL;
  if (!at || strlen(m) > GLOB_OVERLAP_MAX)
    return false;
  memcpy(nick, m, (size_t)(bang - m));
  nick[bang - m] = '\0';
  memcpy(user, bang + 1, (size_t)(at - bang - 1));
  user[at - bang - 1] = '\0';
  strcpy(host, at + 1);
  return true;
}

/* Host pattern kind: 'i' address, 'n' name, 'a' wildcards only (either). */
static char host_kind(const char *h) {
  bool digit = false, other = false;
  for (; *h; h++) {
    unsigned char c = (unsigned char)*h;
    if (c == ':')
      return 'i';
    if (c >= '0' && c <= '9')
      digit = true;
    else if (c != '.' && c != '*' && c != '?')
      other = true;
  }
  return other ? 'n' : digit ? 'i' : 'a';
}

bool hostmask_overlap(const char *a, const char *b) {
  if (!a || !b)
    return true;
  char an[GLOB_OVERLAP_MAX + 1], au[GLOB_OVERLAP_MAX + 1], ah[GLOB_OVERLAP_MAX + 1];
  char bn[GLOB_OVERLAP_MAX + 1], bu[GLOB_OVERLAP_MAX + 1], bh[GLOB_OVERLAP_MAX + 1];
  if (!hm_split(a, an, au, ah) || !hm_split(b, bn, bu, bh))
    return glob_overlap(a, b);
  char ka = host_kind(ah), kb = host_kind(bh);
  if (ka != 'a' && kb != 'a' && ka != kb)
    return false;
  return glob_overlap(an, bn) && glob_overlap(au, bu) && glob_overlap(ah, bh);
}
