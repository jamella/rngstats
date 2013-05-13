/*  Cipher dispatch structures.
 *
 *  Copyright (C) 2013 Zack Weinberg <zackw@panix.com>
 *  Portions originally part of PolarSSL (http://www.polarssl.org)
 *  Copyright (C) 2006-2010, Brainspark B.V.
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef CIPHERS_H__
#define CIPHERS_H__

#include <stddef.h>
#include <stdint.h>

/* This is a highly specialized interface to various cryptographic
   primitives, which makes them all look like simple stream ciphers.
   Due to the larger context, there is no "hardening" -- we don't
   worry about any sort of side-channel or data leak attacks.
   Furthermore, the only error-reporting mechanism is to print
   something on stderr and then crash the program.

   Each cipher defines one of these dispatch structures. */
typedef struct
{
    const char *name;  /* human-readable name of the cipher */
    size_t ctxsize;    /* context size in bytes */
    size_t keysize;    /* key size in bytes */

    /* Initialize a cipher context.  CTX must point to CTXSIZE bytes
       of storage, and KEY must point to KEYSIZE bytes of key material.  */
    void (*init)(void *ctx, const uint8_t *key);

    /* Generate keystream beginning at byte offset OFFSET, into OBUF,
       which is OLEN bytes long.  Some ciphers do not implement
       arbitrary seeking within the keystream efficiently.  Some
       ciphers will crash the program if you attempt to seek backward. */
    void (*gen_keystream)(void *ctx, size_t offset,
                          uint8_t *obuf, size_t olen);

    /* Perform some sort of self-test.  If it fails, print a descriptive
       message to stderr and crash.  Produce no output on success.  */
    void (*selftest)(void);
} cipher;

/* The AES128 cipher dispatch table is special because it's used to
   generate key material for all the other modes.  This allows us to
   parcel out work units by simple offset from zero, while still using
   random keys.  */
extern const cipher aes128_cipher;

/* In general, ciphers are looked up by name in this table. */
extern const cipher *all_ciphers[];

/* This macro defines an entry in all_ciphers. */
#define DEFINE_CIPHER(name, prefix, keysize)                    \
    const cipher name##_cipher =                                \
    { #name, sizeof(prefix##_context), keysize,                 \
      name##_init,                                              \
      prefix##_gen_keystream,                                   \
      prefix##_selftest                                         \
    } /* deliberate absence of semicolon */

#endif
/*
 * Local Variables:
 * indent-tabs-mode: nil
 * c-basic-offset: 4
 * c-file-offsets: ((substatement-open . 0))
 * End:
 */
