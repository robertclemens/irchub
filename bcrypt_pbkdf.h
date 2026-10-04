/*
 * bcrypt_pbkdf.h — OpenBSD's bcrypt_pbkdf, vendored for keygen (see
 * bcrypt_pbkdf.c).  SHARED FILE: byte-identical in irchub and ircbot/utils.
 */
#ifndef KEYGEN_BCRYPT_PBKDF_H
#define KEYGEN_BCRYPT_PBKDF_H

#include <stddef.h>
#include <stdint.h>

/* Derives keylen bytes (at most 1024) from pass/salt with `rounds` rounds.
 * Returns 0 on success, -1 on bad arguments or an allocation/digest failure. */
int bcrypt_pbkdf(const char *pass, size_t passlen, const uint8_t *salt,
                 size_t saltlen, uint8_t *key, size_t keylen, unsigned int rounds);

#endif
