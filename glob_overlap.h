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

/* glob_overlap() for nick!user@host ban masks: each pattern is split at its
 * first '!' and the first '@' after it, and the masks overlap only when the
 * nick, user and host parts all do.  A plain glob_overlap() lets a '*' run
 * across '!' and '@' (so "*!*@aol.com" and "*!*@149.76.*.*" share
 * "a!b@149.76.x!y@aol.com"), which no real hostmask can be.  A pattern not
 * of that shape falls back to glob_overlap() of the whole string.
 * Host parts are typed first: one with a ':' (IPv6), or of only digits, '.',
 * '*' and '?' with at least one digit (IPv4), is an address; one with any
 * other symbol (a letter, '-', '/') is a name; an address pattern never
 * overlaps a name pattern ("*aol.com" vs "149.76.*.*"), since no admin
 * writes a name host as bare digits.  Wildcards-only ("*") overlap both. */
bool hostmask_overlap(const char *a, const char *b);

#endif
