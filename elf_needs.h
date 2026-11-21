/* elf_needs.h — can this host run a gnu artifact?  Checked before anything is
 * downloaded (2.5.4, irchub docs/plans/2026-11-20_artifact_choice_plan.md §4a).
 *
 * Byte-identical in irchub and ircbot (like cfg_delta.[ch]); the Rust trees
 * carry the same rules in elf_needs.rs.  A manifest row's column 13 lists the
 * libraries a gnu binary needs and the symbol versions it requires from each:
 *     libssl.so.3@OPENSSL_3.0.0,libcurl.so.4@CURL_OPENSSL_4,libc.so.6@GLIBC_2.43+GLIBC_ABI_DT_RELR
 * Each library is looked up where the loader would look ($LD_LIBRARY_PATH,
 * /etc/ld.so.conf and its includes, the standard and multiarch directories)
 * and its own ELF version-definition table (SHT_GNU_verdef) read: every
 * required version must be defined.  Reads only, bounded, fail closed —
 * anything that cannot be parsed counts as "not provided". */
#ifndef ELF_NEEDS_H
#define ELF_NEEDS_H

#include <stdbool.h>
#include <stddef.h>

#define EN_NAME_MAX 63     /* a library or version name                 */
#define EN_DEFS_MAX 512    /* version definitions read from one library */

/* True when every library and version `needs` names is present here (or
 * `needs` is empty / "-", or cannot be parsed: then -selftest decides).
 * False with `why` set ("libcurl.so.4 with CURL_OPENSSL_4 (not provided by
 * /usr/lib/x86_64-linux-gnu/libcurl.so.4)") at the first miss. */
bool en_check(const char *needs, char *why, size_t why_size);

/* Where the loader would find `soname`, into `out`; false when nowhere. */
bool en_find_lib(const char *soname, char *out, size_t out_size);

/* The version names `path` defines (its SHT_GNU_verdef, the base entry left
 * out) into names[0..max); their number, or -1 when the file cannot be read
 * as a little-endian ELF. */
int en_verdefs(const char *path, char names[][EN_NAME_MAX + 1], int max);

/* The highest GLIBC_x.y the host's libc.so.6 defines, into `out`; false when
 * there is none (no glibc, or it cannot be read). */
bool en_glibc(char *out, size_t out_size);

#endif
