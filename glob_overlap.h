#ifndef GLOB_OVERLAP_H
#define GLOB_OVERLAP_H

#include <stdbool.h>

/* Longest pattern glob_overlap() examines.  A longer one is reported as
 * overlapping (fail closed: it is only ever used to REFUSE a ban). */
#define GLOB_OVERLAP_MAX 256

/* Pattern-vs-pattern glob overlap: true when at least one string exists that
 * BOTH patterns match.  '*' matches any run (possibly empty), '?' exactly one
 * character, everything else compares ASCII case-insensitively.  Pure: no
 * allocation, no state, O(len(a) * len(b)) time, stack use bounded by
 * GLOB_OVERLAP_MAX.  NULL or over-long input -> true (fail closed).
 * Must stay identical with the ircbot / ircbot.rs copy (docs/modes.md §6.2). */
bool glob_overlap(const char *a, const char *b);

#endif
