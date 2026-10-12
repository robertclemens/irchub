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
