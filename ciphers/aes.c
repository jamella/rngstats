/*
 *  FIPS-197 compliant AES implementation
 *
 *  Copyright 2013 Zack Weinberg <zackw@panix.com>
 *  Based on code from PolarSSL (http://www.polarssl.org)
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
/*
 *  The AES block cipher was designed by Vincent Rijmen and Joan Daemen.
 *
 *  http://csrc.nist.gov/encryption/aes/rijndael/Rijndael.pdf
 *  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 */

#include "config.h"
#include "ciphers.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
    int nr;                     /*!<  number of rounds  */
    uint32_t *rk;               /*!<  AES round keys    */
    uint32_t buf[68];           /*!<  unaligned data    */
}
aes_context;

/*
 * Forward S-box
 */
static const uint8_t FSb[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

/*
 * Forward tables
 */
#define FT \
    V(A5,63,63,C6), V(84,7C,7C,F8), V(99,77,77,EE), V(8D,7B,7B,F6), \
    V(0D,F2,F2,FF), V(BD,6B,6B,D6), V(B1,6F,6F,DE), V(54,C5,C5,91), \
    V(50,30,30,60), V(03,01,01,02), V(A9,67,67,CE), V(7D,2B,2B,56), \
    V(19,FE,FE,E7), V(62,D7,D7,B5), V(E6,AB,AB,4D), V(9A,76,76,EC), \
    V(45,CA,CA,8F), V(9D,82,82,1F), V(40,C9,C9,89), V(87,7D,7D,FA), \
    V(15,FA,FA,EF), V(EB,59,59,B2), V(C9,47,47,8E), V(0B,F0,F0,FB), \
    V(EC,AD,AD,41), V(67,D4,D4,B3), V(FD,A2,A2,5F), V(EA,AF,AF,45), \
    V(BF,9C,9C,23), V(F7,A4,A4,53), V(96,72,72,E4), V(5B,C0,C0,9B), \
    V(C2,B7,B7,75), V(1C,FD,FD,E1), V(AE,93,93,3D), V(6A,26,26,4C), \
    V(5A,36,36,6C), V(41,3F,3F,7E), V(02,F7,F7,F5), V(4F,CC,CC,83), \
    V(5C,34,34,68), V(F4,A5,A5,51), V(34,E5,E5,D1), V(08,F1,F1,F9), \
    V(93,71,71,E2), V(73,D8,D8,AB), V(53,31,31,62), V(3F,15,15,2A), \
    V(0C,04,04,08), V(52,C7,C7,95), V(65,23,23,46), V(5E,C3,C3,9D), \
    V(28,18,18,30), V(A1,96,96,37), V(0F,05,05,0A), V(B5,9A,9A,2F), \
    V(09,07,07,0E), V(36,12,12,24), V(9B,80,80,1B), V(3D,E2,E2,DF), \
    V(26,EB,EB,CD), V(69,27,27,4E), V(CD,B2,B2,7F), V(9F,75,75,EA), \
    V(1B,09,09,12), V(9E,83,83,1D), V(74,2C,2C,58), V(2E,1A,1A,34), \
    V(2D,1B,1B,36), V(B2,6E,6E,DC), V(EE,5A,5A,B4), V(FB,A0,A0,5B), \
    V(F6,52,52,A4), V(4D,3B,3B,76), V(61,D6,D6,B7), V(CE,B3,B3,7D), \
    V(7B,29,29,52), V(3E,E3,E3,DD), V(71,2F,2F,5E), V(97,84,84,13), \
    V(F5,53,53,A6), V(68,D1,D1,B9), V(00,00,00,00), V(2C,ED,ED,C1), \
    V(60,20,20,40), V(1F,FC,FC,E3), V(C8,B1,B1,79), V(ED,5B,5B,B6), \
    V(BE,6A,6A,D4), V(46,CB,CB,8D), V(D9,BE,BE,67), V(4B,39,39,72), \
    V(DE,4A,4A,94), V(D4,4C,4C,98), V(E8,58,58,B0), V(4A,CF,CF,85), \
    V(6B,D0,D0,BB), V(2A,EF,EF,C5), V(E5,AA,AA,4F), V(16,FB,FB,ED), \
    V(C5,43,43,86), V(D7,4D,4D,9A), V(55,33,33,66), V(94,85,85,11), \
    V(CF,45,45,8A), V(10,F9,F9,E9), V(06,02,02,04), V(81,7F,7F,FE), \
    V(F0,50,50,A0), V(44,3C,3C,78), V(BA,9F,9F,25), V(E3,A8,A8,4B), \
    V(F3,51,51,A2), V(FE,A3,A3,5D), V(C0,40,40,80), V(8A,8F,8F,05), \
    V(AD,92,92,3F), V(BC,9D,9D,21), V(48,38,38,70), V(04,F5,F5,F1), \
    V(DF,BC,BC,63), V(C1,B6,B6,77), V(75,DA,DA,AF), V(63,21,21,42), \
    V(30,10,10,20), V(1A,FF,FF,E5), V(0E,F3,F3,FD), V(6D,D2,D2,BF), \
    V(4C,CD,CD,81), V(14,0C,0C,18), V(35,13,13,26), V(2F,EC,EC,C3), \
    V(E1,5F,5F,BE), V(A2,97,97,35), V(CC,44,44,88), V(39,17,17,2E), \
    V(57,C4,C4,93), V(F2,A7,A7,55), V(82,7E,7E,FC), V(47,3D,3D,7A), \
    V(AC,64,64,C8), V(E7,5D,5D,BA), V(2B,19,19,32), V(95,73,73,E6), \
    V(A0,60,60,C0), V(98,81,81,19), V(D1,4F,4F,9E), V(7F,DC,DC,A3), \
    V(66,22,22,44), V(7E,2A,2A,54), V(AB,90,90,3B), V(83,88,88,0B), \
    V(CA,46,46,8C), V(29,EE,EE,C7), V(D3,B8,B8,6B), V(3C,14,14,28), \
    V(79,DE,DE,A7), V(E2,5E,5E,BC), V(1D,0B,0B,16), V(76,DB,DB,AD), \
    V(3B,E0,E0,DB), V(56,32,32,64), V(4E,3A,3A,74), V(1E,0A,0A,14), \
    V(DB,49,49,92), V(0A,06,06,0C), V(6C,24,24,48), V(E4,5C,5C,B8), \
    V(5D,C2,C2,9F), V(6E,D3,D3,BD), V(EF,AC,AC,43), V(A6,62,62,C4), \
    V(A8,91,91,39), V(A4,95,95,31), V(37,E4,E4,D3), V(8B,79,79,F2), \
    V(32,E7,E7,D5), V(43,C8,C8,8B), V(59,37,37,6E), V(B7,6D,6D,DA), \
    V(8C,8D,8D,01), V(64,D5,D5,B1), V(D2,4E,4E,9C), V(E0,A9,A9,49), \
    V(B4,6C,6C,D8), V(FA,56,56,AC), V(07,F4,F4,F3), V(25,EA,EA,CF), \
    V(AF,65,65,CA), V(8E,7A,7A,F4), V(E9,AE,AE,47), V(18,08,08,10), \
    V(D5,BA,BA,6F), V(88,78,78,F0), V(6F,25,25,4A), V(72,2E,2E,5C), \
    V(24,1C,1C,38), V(F1,A6,A6,57), V(C7,B4,B4,73), V(51,C6,C6,97), \
    V(23,E8,E8,CB), V(7C,DD,DD,A1), V(9C,74,74,E8), V(21,1F,1F,3E), \
    V(DD,4B,4B,96), V(DC,BD,BD,61), V(86,8B,8B,0D), V(85,8A,8A,0F), \
    V(90,70,70,E0), V(42,3E,3E,7C), V(C4,B5,B5,71), V(AA,66,66,CC), \
    V(D8,48,48,90), V(05,03,03,06), V(01,F6,F6,F7), V(12,0E,0E,1C), \
    V(A3,61,61,C2), V(5F,35,35,6A), V(F9,57,57,AE), V(D0,B9,B9,69), \
    V(91,86,86,17), V(58,C1,C1,99), V(27,1D,1D,3A), V(B9,9E,9E,27), \
    V(38,E1,E1,D9), V(13,F8,F8,EB), V(B3,98,98,2B), V(33,11,11,22), \
    V(BB,69,69,D2), V(70,D9,D9,A9), V(89,8E,8E,07), V(A7,94,94,33), \
    V(B6,9B,9B,2D), V(22,1E,1E,3C), V(92,87,87,15), V(20,E9,E9,C9), \
    V(49,CE,CE,87), V(FF,55,55,AA), V(78,28,28,50), V(7A,DF,DF,A5), \
    V(8F,8C,8C,03), V(F8,A1,A1,59), V(80,89,89,09), V(17,0D,0D,1A), \
    V(DA,BF,BF,65), V(31,E6,E6,D7), V(C6,42,42,84), V(B8,68,68,D0), \
    V(C3,41,41,82), V(B0,99,99,29), V(77,2D,2D,5A), V(11,0F,0F,1E), \
    V(CB,B0,B0,7B), V(FC,54,54,A8), V(D6,BB,BB,6D), V(3A,16,16,2C)

#define V(a,b,c,d) 0x##a##b##c##d
static const uint32_t FT0[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##b##c##d##a
static const uint32_t FT1[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##c##d##a##b
static const uint32_t FT2[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##d##a##b##c
static const uint32_t FT3[256] = { FT };
#undef V

#undef FT

/*
 * Round constants
 */
static const uint32_t RCON[10] = {
    0x00000001, 0x00000002, 0x00000004, 0x00000008,
    0x00000010, 0x00000020, 0x00000040, 0x00000080,
    0x0000001B, 0x00000036
};

#define POLARSSL_ERR_AES_INVALID_KEY_LENGTH -1

/*
 * 32-bit integer manipulation macros (little endian)
 */
#define GET_UINT32_LE(n,b,i) do {                       \
        (n) = ( (uint32_t) (b)[(i)    ]       )         \
            | ( (uint32_t) (b)[(i) + 1] <<  8 )         \
            | ( (uint32_t) (b)[(i) + 2] << 16 )         \
            | ( (uint32_t) (b)[(i) + 3] << 24 );        \
    } while (0)

#define PUT_UINT32_LE(n,b,i) do {                       \
        (b)[(i)    ] = (uint8_t) ( (n)       );   \
        (b)[(i) + 1] = (uint8_t) ( (n) >>  8 );   \
        (b)[(i) + 2] = (uint8_t) ( (n) >> 16 );   \
        (b)[(i) + 3] = (uint8_t) ( (n) >> 24 );   \
    } while (0)

/*
 * AES key schedule (encryption)
 */
static void
aes128_init(void *ctx_, const uint8_t *key)
{
    aes_context *ctx = ctx_;
    unsigned int i;
    uint32_t *RK;

    ctx->nr = 10;
    ctx->rk = RK = ctx->buf;

    for (i = 0; i < 4; i++)
        GET_UINT32_LE(RK[i], key, i*4);

    for (i = 0; i < 10; i++, RK += 4)
    {
        RK[4] = RK[0] ^ RCON[i] ^
            ((uint32_t) FSb[(RK[3] >> 8) & 0xFF]) ^
            ((uint32_t) FSb[(RK[3] >> 16) & 0xFF] << 8) ^
            ((uint32_t) FSb[(RK[3] >> 24) & 0xFF] << 16) ^
            ((uint32_t) FSb[(RK[3]) & 0xFF] << 24);

        RK[5] = RK[1] ^ RK[4];
        RK[6] = RK[2] ^ RK[5];
        RK[7] = RK[3] ^ RK[6];
    }
}

static void
aes192_init(void *ctx_, const uint8_t *key)
{
    aes_context *ctx = ctx_;
    unsigned int i;
    uint32_t *RK;

    ctx->nr = 12;
    ctx->rk = RK = ctx->buf;

    for (i = 0; i < 6; i++)
        GET_UINT32_LE(RK[i], key, i*4);

    for (i = 0; i < 8; i++, RK += 6)
    {
        RK[6] = RK[0] ^ RCON[i] ^
            ((uint32_t) FSb[(RK[5] >> 8) & 0xFF]) ^
            ((uint32_t) FSb[(RK[5] >> 16) & 0xFF] << 8) ^
            ((uint32_t) FSb[(RK[5] >> 24) & 0xFF] << 16) ^
            ((uint32_t) FSb[(RK[5]) & 0xFF] << 24);

        RK[7] = RK[1] ^ RK[6];
        RK[8] = RK[2] ^ RK[7];
        RK[9] = RK[3] ^ RK[8];
        RK[10] = RK[4] ^ RK[9];
        RK[11] = RK[5] ^ RK[10];
    }
}

static void
aes256_init(void *ctx_, const uint8_t *key)
{
    aes_context *ctx = ctx_;
    unsigned int i;
    uint32_t *RK;
    ctx->nr = 14;
    ctx->rk = RK = ctx->buf;

    for (i = 0; i < 8; i++)
        GET_UINT32_LE(RK[i], key, i << 2);

    for (i = 0; i < 7; i++, RK += 8)
    {
        RK[8] = RK[0] ^ RCON[i] ^
            ((uint32_t) FSb[(RK[7] >> 8) & 0xFF]) ^
            ((uint32_t) FSb[(RK[7] >> 16) & 0xFF] << 8) ^
            ((uint32_t) FSb[(RK[7] >> 24) & 0xFF] << 16) ^
            ((uint32_t) FSb[(RK[7]) & 0xFF] << 24);

        RK[9] = RK[1] ^ RK[8];
        RK[10] = RK[2] ^ RK[9];
        RK[11] = RK[3] ^ RK[10];

        RK[12] = RK[4] ^
            ((uint32_t) FSb[(RK[11]) & 0xFF]) ^
            ((uint32_t) FSb[(RK[11] >> 8) & 0xFF] << 8) ^
            ((uint32_t) FSb[(RK[11] >> 16) & 0xFF] << 16) ^
            ((uint32_t) FSb[(RK[11] >> 24) & 0xFF] << 24);

        RK[13] = RK[5] ^ RK[12];
        RK[14] = RK[6] ^ RK[13];
        RK[15] = RK[7] ^ RK[14];
    }
}

/*
 * AES block encryption primitive
 */

#define AES_FROUND(X0,X1,X2,X3,Y0,Y1,Y2,Y3) do {        \
        X0 = *RK++ ^ FT0[ ( Y0       ) & 0xFF ] ^       \
             FT1[ ( Y1 >>  8 ) & 0xFF ] ^               \
             FT2[ ( Y2 >> 16 ) & 0xFF ] ^               \
             FT3[ ( Y3 >> 24 ) & 0xFF ];                \
                                                        \
        X1 = *RK++ ^ FT0[ ( Y1       ) & 0xFF ] ^       \
             FT1[ ( Y2 >>  8 ) & 0xFF ] ^               \
             FT2[ ( Y3 >> 16 ) & 0xFF ] ^               \
             FT3[ ( Y0 >> 24 ) & 0xFF ];                \
                                                        \
        X2 = *RK++ ^ FT0[ ( Y2       ) & 0xFF ] ^       \
             FT1[ ( Y3 >>  8 ) & 0xFF ] ^               \
             FT2[ ( Y0 >> 16 ) & 0xFF ] ^               \
             FT3[ ( Y1 >> 24 ) & 0xFF ];                \
                                                        \
        X3 = *RK++ ^ FT0[ ( Y3       ) & 0xFF ] ^       \
             FT1[ ( Y0 >>  8 ) & 0xFF ] ^               \
             FT2[ ( Y1 >> 16 ) & 0xFF ] ^               \
             FT3[ ( Y2 >> 24 ) & 0xFF ];                \
    } while (0)

static int
aes_encrypt_block(void *ctx_,
                  const uint8_t input[16],
                  uint8_t output[16])
{
    aes_context *ctx = ctx_;
    int i;
    uint32_t *RK, X0, X1, X2, X3, Y0, Y1, Y2, Y3;

    RK = ctx->rk;

    GET_UINT32_LE(X0, input, 0);
    X0 ^= *RK++;
    GET_UINT32_LE(X1, input, 4);
    X1 ^= *RK++;
    GET_UINT32_LE(X2, input, 8);
    X2 ^= *RK++;
    GET_UINT32_LE(X3, input, 12);
    X3 ^= *RK++;

    for (i = (ctx->nr >> 1) - 1; i > 0; i--)
    {
        AES_FROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);
        AES_FROUND(X0, X1, X2, X3, Y0, Y1, Y2, Y3);
    }

    AES_FROUND(Y0, Y1, Y2, Y3, X0, X1, X2, X3);

    X0 = *RK++ ^
         ((uint32_t) FSb[(Y0) & 0xFF]) ^
         ((uint32_t) FSb[(Y1 >> 8) & 0xFF] << 8) ^
         ((uint32_t) FSb[(Y2 >> 16) & 0xFF] << 16) ^
         ((uint32_t) FSb[(Y3 >> 24) & 0xFF] << 24);

    X1 = *RK++ ^
         ((uint32_t) FSb[(Y1) & 0xFF]) ^
         ((uint32_t) FSb[(Y2 >> 8) & 0xFF] << 8) ^
         ((uint32_t) FSb[(Y3 >> 16) & 0xFF] << 16) ^
         ((uint32_t) FSb[(Y0 >> 24) & 0xFF] << 24);

    X2 = *RK++ ^
         ((uint32_t) FSb[(Y2) & 0xFF]) ^
         ((uint32_t) FSb[(Y3 >> 8) & 0xFF] << 8) ^
         ((uint32_t) FSb[(Y0 >> 16) & 0xFF] << 16) ^
         ((uint32_t) FSb[(Y1 >> 24) & 0xFF] << 24);

    X3 = *RK++ ^
         ((uint32_t) FSb[(Y3) & 0xFF]) ^
         ((uint32_t) FSb[(Y0 >> 8) & 0xFF] << 8) ^
         ((uint32_t) FSb[(Y1 >> 16) & 0xFF] << 16) ^
         ((uint32_t) FSb[(Y2 >> 24) & 0xFF] << 24);

    PUT_UINT32_LE(X0, output, 0);
    PUT_UINT32_LE(X1, output, 4);
    PUT_UINT32_LE(X2, output, 8);
    PUT_UINT32_LE(X3, output, 12);

    return (0);
}

#undef AES_FROUND
#undef GET_UINT32_LE
#undef PUT_UINT32_LE

/*
 * Counter-mode stream cipher construction.
 * This may not be precisely the same as NIST AES-CTR,
 * but for this application it doesn't matter.
 */
static void
aes_gen_keystream(void *ctx_, size_t offset,
                  uint8_t *obuf, size_t olen)
{
    uint8_t counter[16];
    uint8_t block[16];
    uint8_t *limit = obuf + olen;
    size_t offset_128b, offset_rem, i;

    if (olen == 0)
        return;

    /* Initialize the counter to a 128-bit big-endian count of the
       number of 128-bit cipher blocks already consumed at OFFSET.  */
    if (sizeof(size_t) > 16)
        abort();

    memset(counter, 0, 16);
    offset_128b = offset / 16;
    offset_rem  = offset % 16;
    for (i = 0; i < sizeof(size_t); i++)
    {
        if (offset_128b == 0)
            break;
        counter[15 - i] = offset_128b & 0xFF;
        offset_128b >>= 8;
    }

    i = offset_rem;
    for (;;)
    {
        aes_encrypt_block(ctx_, counter, block);
        for (; i < 16; i++)
        {
            *obuf++ = block[i];
            if (obuf >= limit)
                return;
        }

        /* increment counter */
        for (i = 0; i < 16; i++)
            if (++counter[15 - i] != 0)
                break;

        i = 0;
    }
}

/*
 * AES block function test vectors from
 * http://csrc.nist.gov/archive/aes/rijndael/rijndael-vals.zip
 * (ecb_vk.txt, ecb_vt.txt)
 */

#define B(a,b,c,d, e,f,g,h, i,j,k,l, m,n,o,p)                   \
    { 0x##a, 0x##b, 0x##c, 0x##d, 0x##e, 0x##f, 0x##g, 0x##h,   \
      0x##i, 0x##j, 0x##k, 0x##l, 0x##m, 0x##n, 0x##o, 0x##p }

static uint8_t
aes_vk_128[128][16] = {
    B(0E,DD,33,D3,C6,21,E5,46,45,5B,D8,BA,14,18,BE,C8),
    B(C0,CC,0C,5D,A5,BD,63,AC,D4,4A,80,77,4F,AD,52,22),
    B(2F,0B,4B,71,BC,77,85,1B,9C,A5,6D,42,EB,8F,F0,80),
    B(6B,1E,2F,FF,E8,A1,14,00,9D,8F,E2,2F,6D,B5,F8,76),
    B(9A,A0,42,C3,15,F9,4C,BB,97,B6,22,02,F8,33,58,F5),
    B(DB,E0,1D,E6,7E,34,6A,80,0C,4C,4B,48,80,31,1D,E4),
    B(C1,17,D2,23,8D,53,83,6A,CD,92,DD,CD,B8,5D,6A,21),
    B(DC,0E,D8,5D,F9,61,1A,BB,72,49,CD,D1,68,C5,46,7E),
    B(80,7D,67,8F,FF,1F,56,FA,92,DE,33,81,90,48,42,F2),
    B(0E,53,B3,FC,AD,8E,4B,13,0E,F7,3A,EB,95,7F,B4,02),
    B(96,9F,FD,3B,7C,35,43,94,17,E7,BD,E9,23,03,5D,65),
    B(A9,9B,51,2C,19,CA,56,07,04,91,16,6A,15,03,BF,15),
    B(6E,99,85,25,21,26,EE,34,4D,26,AE,36,9D,23,27,E3),
    B(B8,5F,48,09,F9,04,C2,75,49,1F,CD,CD,16,10,38,7E),
    B(ED,36,5B,8D,7D,20,C1,F5,D5,3F,B9,4D,D2,11,DF,7B),
    B(B3,A5,75,E8,6A,8D,B4,A7,13,5D,60,4C,43,30,48,96),
    B(89,70,4B,CB,8E,69,F8,46,25,9E,B0,AC,CB,C7,F8,A2),
    B(C5,6E,E7,C9,21,97,86,1F,10,D7,A9,2B,90,88,20,55),
    B(92,F2,96,F6,84,6E,0E,AF,94,22,A5,A2,4A,08,B0,69),
    B(E6,7E,32,BB,8F,11,DE,B8,69,93,18,BE,E9,E9,1A,60),
    B(B0,8E,EF,85,EA,F6,26,DD,91,B6,5C,4C,3A,97,D9,2B),
    B(66,10,83,A6,AD,DC,E7,9B,B4,E0,85,9A,B5,53,80,13),
    B(55,DF,E2,94,1E,0E,B1,0A,FC,0B,33,3B,D3,4D,E1,FE),
    B(6B,FE,59,45,E7,15,C9,66,26,09,77,0F,88,46,08,7A),
    B(79,84,8E,9C,30,C2,F8,CD,A8,B3,25,F7,FE,D2,B1,39),
    B(7A,71,3A,53,B9,9F,EF,34,AC,04,DE,EF,80,96,5B,D0),
    B(18,14,4A,2B,46,62,0D,32,C3,C3,2C,E5,2D,49,25,7F),
    B(87,2E,82,7C,70,88,7C,80,74,9F,7B,8B,B1,84,7C,7E),
    B(6B,86,C6,A4,FE,6A,60,C5,9B,1A,31,02,F8,DE,49,F3),
    B(98,48,BB,3D,FD,F6,F5,32,F0,94,67,9A,4C,23,1A,20),
    B(92,5A,D5,28,E8,52,E3,29,B2,09,1C,D3,F1,C2,BC,EE),
    B(80,DF,43,65,44,B0,DD,59,67,22,E4,67,92,A4,0C,D8),
    B(52,5D,AF,18,F9,3E,83,E1,E7,4B,BB,DD,E4,26,3B,BA),
    B(F6,5C,9D,2E,E4,85,D2,47,01,FF,A3,31,3B,9D,5B,E6),
    B(E4,FC,8D,8B,CA,06,42,5B,DF,94,AF,A4,0F,CC,14,BA),
    B(A5,3F,0A,5C,A1,E4,E6,44,0B,B9,75,FF,32,0D,E6,F8),
    B(D5,53,13,B9,39,40,80,46,2E,87,E0,28,99,B5,53,F0),
    B(34,A7,1D,76,1F,71,BC,D3,44,38,4C,7F,97,D2,79,06),
    B(23,3F,3D,81,95,99,61,2E,BC,89,58,02,45,C9,96,A8),
    B(B4,F1,37,4E,52,68,DB,CB,67,6E,44,75,29,E5,3F,89),
    B(08,16,BD,27,86,1D,2B,A8,91,D1,04,4E,39,95,1E,96),
    B(F3,BE,9E,A3,F1,0C,73,CA,64,FD,E5,DB,13,A9,51,D1),
    B(24,48,08,6A,81,06,FB,D0,30,48,DD,F8,57,D3,F1,C8),
    B(67,07,56,E6,5B,EC,8B,68,F0,3D,77,CD,CD,CE,7B,91),
    B(EF,96,8C,F0,D3,6F,D6,C6,EF,FD,22,5F,6F,B4,4C,A9),
    B(2E,87,67,15,79,22,E3,82,6D,DC,EC,1B,0C,C1,E1,05),
    B(78,CE,7E,EC,67,0E,45,A9,67,BA,B1,7E,26,A1,AD,36),
    B(3C,5C,EE,82,56,55,F0,98,F6,E8,1A,2F,41,7D,A3,FB),
    B(67,BF,DB,43,1D,CE,12,92,20,0B,C6,F5,20,7A,DB,12),
    B(75,40,FD,38,E4,47,C0,77,92,28,54,87,47,84,3A,6F),
    B(B8,5E,51,33,01,F8,A9,36,EA,9E,C8,A2,1A,85,B5,E6),
    B(04,C6,7D,BF,16,C1,14,27,D5,07,A4,55,DE,2C,9B,C5),
    B(03,F7,5E,B8,95,9E,55,07,9C,FF,B4,FF,14,9A,37,B6),
    B(74,55,02,87,F6,66,C6,3B,B9,BC,78,38,43,34,34,B0),
    B(7D,53,72,00,19,5E,BC,3A,EF,D1,EA,AB,1C,38,52,21),
    B(CE,24,E4,D4,0C,68,A8,2B,53,5C,BD,3C,8E,21,65,2A),
    B(AB,20,07,24,05,AA,8F,C4,02,65,C6,F1,F3,DC,8B,C0),
    B(6C,FD,2C,F6,88,F5,66,B0,93,F6,7B,9B,38,39,E8,0A),
    B(BD,95,97,7E,6B,72,39,D4,07,A0,12,C5,54,4B,F5,84),
    B(DF,9C,01,30,AC,77,E7,C7,2C,99,7F,58,7B,46,DB,E0),
    B(E7,F1,B8,2C,AD,C5,3A,64,87,98,94,5B,34,EF,EF,F2),
    B(93,2C,6D,BF,69,25,5C,F1,3E,DC,DB,72,23,3A,CE,A3),
    B(5C,76,00,2B,C7,20,65,60,EF,E5,50,C8,0B,8F,12,CC),
    B(F6,B7,BD,D1,CA,EE,BA,B5,74,68,38,93,C4,47,54,84),
    B(A9,20,E3,7C,C6,DC,6B,31,DA,8C,01,69,56,9F,50,34),
    B(91,93,80,EC,D9,C7,78,BC,51,31,48,B0,C2,8D,65,FD),
    B(EE,67,30,8D,D3,F2,D9,E6,C2,17,07,55,E5,78,4B,E1),
    B(3C,C7,3E,53,B8,56,09,02,3A,05,E1,49,B2,23,AE,09),
    B(98,3E,8A,F7,CF,05,EB,B2,8D,71,EB,84,1C,94,06,E6),
    B(0F,30,99,B2,D3,1F,A5,29,9E,E5,BF,43,19,32,87,FC),
    B(B7,63,D8,4F,38,C2,7F,E6,93,1D,CE,B6,71,5D,4D,B6),
    B(5A,E3,C9,B0,E3,CC,29,C0,C6,15,65,CD,01,F8,A2,48),
    B(F5,80,83,57,2C,D9,09,81,95,85,65,D4,8D,2D,EE,25),
    B(7E,62,55,EE,F8,F7,0C,0E,F1,03,37,AA,B1,CC,CE,F8),
    B(AA,D4,BA,C3,4D,B2,28,21,84,1C,E2,F6,31,96,19,02),
    B(D7,43,1C,04,09,BB,14,41,BA,9C,68,58,DC,7D,4E,81),
    B(EF,92,98,C6,5E,33,9F,6E,80,1A,59,C6,26,45,69,93),
    B(53,FE,29,F6,8F,F5,41,AB,C3,F0,EF,33,50,B7,2F,7E),
    B(F6,BB,A5,C1,0D,B0,25,29,E2,C2,DA,3F,B5,82,CC,14),
    B(E4,23,9A,A3,7F,C5,31,A3,86,DA,D1,12,6F,C0,E9,CD),
    B(8F,77,58,F8,57,D1,5B,BE,7B,FD,0E,41,64,04,C3,65),
    B(D2,73,EB,57,C6,87,BC,D1,B4,EA,72,18,A5,09,E7,B8),
    B(65,D6,4F,8D,76,E8,B3,42,3F,A2,5C,4E,B5,8A,21,0A),
    B(62,3D,80,2B,4E,C4,50,D6,6A,16,62,57,02,FC,DB,E0),
    B(74,96,46,0C,B2,8E,57,91,BA,EA,F9,B6,8F,B0,00,22),
    B(34,EA,60,0F,18,BB,06,94,B4,16,81,A4,9D,51,0C,1D),
    B(5F,8F,F0,D4,7D,57,66,D2,9B,5D,6E,8F,46,42,3B,D8),
    B(22,5F,92,86,C5,92,8B,F0,9F,84,D3,F9,3F,54,19,59),
    B(B2,1E,90,D2,5D,F3,83,41,6A,5F,07,2C,EB,EB,1F,FB),
    B(4A,EF,CD,A0,89,31,81,25,45,3E,B9,E8,EB,5E,49,2E),
    B(4D,3E,75,C6,CD,40,EC,48,69,BC,85,15,85,91,AD,B8),
    B(63,A8,B9,04,40,54,36,A1,B9,9D,77,51,86,67,71,B7),
    B(64,F0,DA,AE,47,52,91,99,79,2E,AE,17,2B,A5,32,93),
    B(C3,EE,F8,4B,EA,18,22,5D,51,5A,8C,85,2A,90,47,EE),
    B(A4,4A,C4,22,B4,7D,47,B8,1A,F7,3B,3E,9A,C9,59,6E),
    B(D1,6E,04,A8,FB,C4,35,09,4F,8D,53,AD,F2,5F,50,84),
    B(EF,13,DC,34,BA,B0,3E,12,4E,EA,D8,B6,BF,44,B5,32),
    B(D9,47,99,07,5C,24,DC,C0,67,AF,0D,39,20,49,25,0D),
    B(14,F4,31,77,1E,DD,CE,47,64,C2,1A,22,54,B5,E3,C8),
    B(70,39,32,9F,36,F2,ED,68,2B,02,99,1F,28,D6,46,79),
    B(12,4E,E2,4E,DE,55,51,63,9D,B8,B8,B9,41,F6,14,1D),
    B(C2,85,28,79,A3,4D,51,84,E4,78,EC,91,8B,99,3F,EE),
    B(86,A8,06,A3,52,5B,93,E4,32,05,3C,9A,B5,AB,BE,DF),
    B(C1,60,9B,F5,A4,F0,7E,37,C1,7A,36,36,6E,C2,3E,CC),
    B(7E,81,E7,CB,92,15,9A,51,FF,CE,A3,31,B1,E8,EA,53),
    B(37,A7,BE,00,28,56,C5,A5,9A,6E,03,EA,FC,E7,72,9A),
    B(BD,F9,8A,5A,4F,91,E8,90,C9,A1,D1,E5,FA,AB,13,8F),
    B(4E,96,AC,B6,6E,05,1F,2B,C7,39,CC,3D,3E,34,A2,6B),
    B(EE,99,6C,DD,12,0E,B8,6E,21,EC,FA,49,E8,E1,FC,F1),
    B(61,B9,E6,B5,79,DB,F6,07,0C,35,1A,14,40,DD,85,FF),
    B(AC,36,9E,48,43,16,44,0B,40,DF,C8,3A,A9,6E,28,E7),
    B(0A,2D,16,DE,98,5C,76,D4,5C,57,9C,11,59,41,3B,BE),
    B(DA,3F,DC,38,DA,1D,37,4F,A4,80,2C,DA,1A,1C,6B,0F),
    B(B8,42,52,3D,4C,41,C2,21,1A,FE,43,A5,80,0A,DC,E3),
    B(9E,2C,DA,90,D8,E9,92,DB,A6,C7,3D,82,29,56,71,92),
    B(D4,95,83,B7,81,D9,E2,0F,5B,E1,01,41,59,57,FC,49),
    B(EF,09,DA,5C,12,B3,76,E4,58,B9,B8,67,00,32,49,8E),
    B(A9,6B,E0,46,3D,A7,74,46,1A,5E,1D,5A,9D,D1,AC,10),
    B(32,CE,E3,34,10,60,79,0D,2D,4B,13,62,EF,39,70,90),
    B(21,CE,A4,16,A3,D3,35,9D,2C,4D,58,FB,6A,03,5F,06),
    B(17,2A,EA,B3,D5,07,67,8E,CA,F4,55,C1,25,87,AD,B7),
    B(B6,F8,97,94,1E,F8,EB,FF,9F,E8,0A,56,7E,F3,84,78),
    B(A9,72,32,59,D9,4A,7D,C6,62,FB,0C,78,2C,A3,F1,DD),
    B(2F,91,C9,84,B9,A4,83,9F,30,00,1B,9F,43,04,93,B4),
    B(04,72,40,63,45,A6,10,B0,48,CB,99,EE,0E,F3,FA,0F),
    B(F5,F3,90,86,64,6F,8C,05,ED,16,EF,A4,B6,17,95,7C),
    B(26,D5,0F,48,5A,30,40,8D,5A,F4,7A,57,36,29,24,50),
    B(05,45,AA,D5,6D,A2,A9,7C,36,63,D1,43,2A,3D,1C,84),
};

static uint8_t
aes_vk_192[256][16] = {
    B(DE,88,5D,C8,7F,5A,92,59,40,82,D0,2C,C1,E1,B4,2C),
    B(C7,49,19,4F,94,67,3F,9D,D2,AA,19,32,84,96,30,C1),
    B(0C,EF,64,33,13,91,29,34,D3,10,29,7B,90,F5,6E,CC),
    B(C4,49,5D,39,D4,A5,53,B2,25,FB,A0,2A,7B,1B,87,E1),
    B(63,6D,10,B1,A0,BC,AB,54,1D,68,0A,79,70,AD,C8,30),
    B(07,CF,04,57,86,BD,6A,FC,C1,47,D9,9E,45,A9,01,A7),
    B(6A,8E,3F,42,5A,75,99,34,8F,95,39,84,48,82,79,76),
    B(55,18,27,68,36,14,8A,00,D9,10,89,A2,0D,8B,FF,57),
    B(F2,67,E0,7B,5E,87,E3,BC,20,B9,69,C6,1D,4F,CB,06),
    B(5A,1C,DE,69,57,1D,40,1B,FC,D2,0D,EB,AD,A2,21,2C),
    B(70,A9,05,72,63,25,47,01,D1,2A,DD,7D,74,CD,50,9E),
    B(35,71,3A,7E,10,80,31,27,93,88,A3,3A,0F,E2,E1,90),
    B(E7,4E,DE,82,B1,25,47,14,F0,C7,B4,B2,43,10,86,55),
    B(39,27,2E,31,00,FA,A3,7B,55,B8,62,32,0D,1B,3E,B3),
    B(6D,6E,24,C6,59,FC,5A,EF,71,2F,77,BC,A1,9C,9D,D0),
    B(76,D1,82,12,F9,72,37,0D,3C,C2,C6,C3,72,C6,CF,2F),
    B(B2,1A,1F,0B,AE,39,E5,5C,75,94,ED,57,0A,77,83,EA),
    B(77,DE,20,21,11,89,5A,C4,8D,D1,C9,74,B3,58,B4,58),
    B(67,81,0B,31,19,69,01,2A,AF,7B,50,4F,FA,F3,9F,D1),
    B(C2,2E,A2,34,4D,3E,94,17,A6,BA,07,84,3E,71,3A,EA),
    B(C7,9C,AF,4B,97,BE,E0,BD,06,30,AB,35,45,39,D6,53),
    B(13,5F,D1,AF,76,1D,9A,E2,3D,F4,AA,6B,86,76,0D,B4),
    B(D4,65,9D,0B,06,AC,D4,D5,6A,B8,D1,1A,16,FD,83,B9),
    B(F7,D2,70,02,8F,C1,88,E4,E4,F3,5A,4A,AA,25,D4,D4),
    B(34,5C,AE,5A,8C,96,20,A9,91,3D,54,73,98,58,52,FF),
    B(4E,89,80,AD,DE,60,B0,E4,2C,0B,28,7F,EA,41,E7,29),
    B(F1,1B,6D,74,E1,F1,51,55,63,3D,C3,97,43,C1,A5,27),
    B(9C,87,91,6C,01,80,06,4F,9D,31,79,C6,F5,DD,8C,35),
    B(71,AB,18,6B,CA,EA,51,8E,46,1D,4F,7F,AD,23,0E,6A),
    B(C4,A3,1B,BC,3D,AA,F7,42,F9,14,1C,2A,50,01,A4,9C),
    B(E7,C4,7B,7B,1D,40,F1,82,A8,92,8C,8A,55,67,1D,07),
    B(8E,17,F2,94,B2,8F,A3,73,C6,24,95,38,86,8A,7E,EF),
    B(75,44,04,09,6A,5C,BC,08,AF,09,49,1B,E2,49,14,1A),
    B(10,1C,B5,6E,55,F0,5D,86,36,9B,6D,10,69,20,4F,0A),
    B(73,F1,9B,B6,60,42,05,C6,EE,22,7B,97,59,79,1E,41),
    B(62,70,C0,02,8F,0D,13,6C,37,A5,6B,2C,B6,4D,24,D6),
    B(A3,BF,7C,2C,38,D1,11,4A,08,7E,CF,21,2E,69,43,46),
    B(49,CA,BF,F2,CE,F7,D9,F9,5F,5E,FB,1F,7A,1A,7D,DE),
    B(EC,7F,8A,47,CC,59,B8,49,46,92,55,AD,49,F6,27,52),
    B(68,FA,E5,5A,13,EF,AF,9B,07,B3,55,2A,8A,0D,C9,D1),
    B(21,1E,6B,19,C6,9F,AE,F4,81,F6,4F,24,09,9C,DA,65),
    B(DB,B9,18,C7,5B,C5,73,24,16,F7,9F,B0,C8,EE,4C,5C),
    B(98,D4,94,E5,D9,63,A6,C8,B9,25,36,D3,EC,35,E3,FD),
    B(C9,A8,73,40,4D,40,3D,6F,07,41,90,85,1D,67,78,1A),
    B(07,3A,EF,4A,7C,77,D9,21,92,8C,B0,DD,9D,27,CA,E7),
    B(89,BD,E2,5C,EE,36,FD,E7,69,A1,0E,52,29,8C,F9,0F),
    B(26,D0,84,2D,37,EA,D3,85,57,C6,5E,0A,5E,5F,12,2E),
    B(F8,29,4B,A3,75,AF,46,B3,F2,29,05,BB,AF,FA,B1,07),
    B(2A,D6,3E,B4,D0,D4,38,13,B9,79,CF,72,B3,5B,DB,94),
    B(77,10,C1,71,EE,0F,4E,FA,39,BE,4C,99,51,80,18,1D),
    B(C0,CB,2B,40,DB,A7,BE,8C,06,98,FA,E1,E4,B8,0F,F8),
    B(97,97,0E,50,51,94,62,2F,D9,55,CA,1B,80,B7,84,E9),
    B(7C,B1,82,4B,29,F8,50,90,0D,F2,CA,D9,CF,04,C1,CF),
    B(FD,F4,F0,36,BB,98,8E,42,F2,F6,2D,E6,3F,E1,9A,64),
    B(08,90,8C,FE,2C,82,60,6B,2C,15,DF,61,B7,5C,F3,E2),
    B(B3,AA,68,9E,F2,D0,7F,F3,65,AC,B9,AD,BA,2A,F0,7A),
    B(F2,67,2C,D8,EA,A3,B9,87,76,66,0D,02,63,65,6F,5C),
    B(5B,DE,AC,00,E9,86,68,7B,9E,1D,94,A0,DA,7B,F4,52),
    B(E6,D5,7B,D6,6E,A1,62,73,63,EE,0C,4B,71,1B,0B,21),
    B(03,73,0D,D6,AC,B4,AD,99,96,A6,3B,E7,76,5E,C0,6F),
    B(A4,70,E3,61,AA,54,37,B2,BE,85,86,D2,F7,8D,E5,82),
    B(75,67,FE,EF,A5,59,91,1F,D4,79,67,02,46,B4,84,E3),
    B(29,82,9D,EA,15,A4,E7,A4,C0,49,04,5E,7B,10,6E,29),
    B(A4,07,83,4C,3D,89,D4,8A,2C,B7,A1,52,20,8F,A4,ED),
    B(68,F9,48,05,3F,78,FE,F0,D8,F9,FE,7E,F3,A8,98,19),
    B(B6,05,17,4C,AB,13,AD,8F,E3,B2,0D,A3,AE,7B,02,34),
    B(CC,AB,8F,0A,EB,FF,03,28,93,99,6D,38,3C,BF,DB,FA),
    B(AF,14,BB,84,28,C9,73,0B,7D,C1,7B,6C,1C,BE,BC,C8),
    B(5A,41,A2,13,32,04,08,77,EB,7B,89,E8,E8,0D,19,FE),
    B(AC,1B,A5,2E,FC,DD,E3,68,B1,59,6F,2F,0A,D8,93,A0),
    B(41,B8,90,E3,1B,90,45,E6,EC,DC,1B,C3,F2,DB,9B,CC),
    B(4D,54,A5,49,72,8E,55,B1,9A,23,66,04,24,A0,F1,46),
    B(A9,17,58,1F,41,C4,7C,7D,DC,FF,D5,28,5E,2D,6A,61),
    B(60,4D,F2,4B,A6,09,9B,93,A7,40,5A,52,4D,76,4F,CB),
    B(78,D9,D1,56,F2,8B,19,0E,23,2D,1B,7A,E7,FC,73,0A),
    B(5A,12,C3,9E,44,2C,D7,F2,7B,3C,D7,7F,5D,02,95,82),
    B(FF,2B,F2,F4,7C,F7,B0,F2,8E,E2,5A,F9,5D,BF,79,0D),
    B(18,63,BB,7D,19,3B,DA,39,DF,09,06,59,EB,8A,E4,8B),
    B(38,17,8F,2F,B4,CF,CF,31,E8,7E,1A,BC,DC,02,3E,B5),
    B(F5,B1,3D,C6,90,CC,0D,54,1C,6B,A5,33,02,3D,C8,C9),
    B(48,EC,05,23,8D,73,75,D1,26,DC,9D,08,88,4D,48,27),
    B(AC,D0,D8,11,39,69,1B,31,0B,92,A6,E3,77,BA,CC,87),
    B(9A,4A,A4,35,78,B5,5C,E9,CC,17,8F,0D,2E,16,2C,79),
    B(08,AD,94,BC,73,7D,B3,C8,7D,49,B9,E0,1B,72,0D,81),
    B(3B,CF,B2,D5,D2,10,E8,33,29,00,C5,99,1D,55,1A,2A),
    B(C5,F0,C6,B9,39,7A,CB,29,63,5C,E1,A0,DA,2D,8D,96),
    B(84,4A,29,EF,C6,93,E2,FA,99,00,F8,7F,BF,5D,CD,5F),
    B(51,26,A1,C4,10,51,FE,A1,58,BE,41,20,0E,1E,A5,9D),
    B(30,21,23,CA,7B,4F,46,D6,67,FF,FB,0E,B6,AA,77,03),
    B(A9,D1,6B,CE,7D,B5,C0,24,27,77,09,EE,2A,88,D9,1A),
    B(F0,13,C5,EC,12,3A,26,CF,C3,4B,59,8C,99,2A,99,6B),
    B(E3,8A,82,5C,D9,71,A1,D2,E5,6F,B1,DB,A2,48,F2,A8),
    B(6E,70,17,73,C0,31,1E,0B,D4,C5,A0,97,40,6D,22,B3),
    B(75,42,62,CE,F0,C6,4B,E4,C3,E6,7C,35,AB,E4,39,F7),
    B(C9,C2,D4,C4,7D,F7,D5,5C,FA,0E,E5,F1,FE,50,70,F4),
    B(6A,B4,BE,A8,5B,17,25,73,D8,BD,2D,5F,43,29,F1,3D),
    B(11,F0,3E,F2,8E,2C,C9,AE,51,65,C5,87,F7,39,6C,8C),
    B(06,82,F2,EB,1A,68,BA,C7,94,99,22,C6,30,DD,27,FA),
    B(AB,B0,FE,C0,41,3D,65,9A,FE,8E,3D,CF,6B,A8,73,BB),
    B(FE,86,A3,2E,19,F8,05,D6,56,9B,2E,FA,DD,9C,92,AA),
    B(E4,34,E4,72,27,5D,18,37,D3,D7,17,F2,EE,CC,88,C3),
    B(74,E5,7D,CD,12,A2,1D,26,EF,8A,DA,FA,5E,60,46,9A),
    B(C2,75,42,9D,6D,AD,45,DD,D4,23,FA,63,C8,16,A9,C1),
    B(7F,6E,C1,A9,AE,72,9E,86,F7,74,4A,ED,4B,8F,4F,07),
    B(48,B5,A7,1A,B9,29,2B,D4,F9,E6,08,EF,10,26,36,B2),
    B(07,6F,B9,5D,5F,53,6C,78,CB,ED,31,81,BC,CF,3C,F1),
    B(BF,A7,6B,EA,1E,68,4F,D3,BF,92,56,11,9E,E0,BC,0F),
    B(7D,39,59,23,D5,65,77,F3,FF,86,70,99,8F,8C,4A,71),
    B(BA,02,C9,86,E5,29,AC,18,A8,82,C3,4B,A3,89,62,5F),
    B(3D,FC,F2,D8,82,AF,E7,5D,3A,19,11,93,01,3A,84,B5),
    B(FA,D1,FD,E1,D0,24,17,84,B6,30,80,D2,C7,4D,23,6C),
    B(7D,6C,80,D3,9E,41,F0,07,A1,4F,B9,CD,2B,2C,15,CD),
    B(79,75,F4,01,FC,10,63,7B,B3,3E,A2,DB,05,8F,F6,EC),
    B(65,79,83,86,5C,55,A8,18,F0,2B,7F,CD,52,ED,7E,99),
    B(B3,2B,EB,17,76,F9,82,7F,F4,C3,AC,99,97,E8,4B,20),
    B(2A,E2,C7,C3,74,F0,A4,1E,3D,46,DB,C3,E6,6B,B5,9F),
    B(4D,83,5E,4A,BD,D4,BD,C6,B8,83,16,A6,E9,31,A0,7F),
    B(E0,7E,FA,BF,F1,C3,53,F7,38,4E,BB,87,B4,35,A3,F3),
    B(ED,30,88,DC,3F,AF,89,AD,87,B4,35,6F,F1,BB,09,C2),
    B(43,24,D0,11,40,C1,56,FC,89,8C,2E,32,BA,03,FB,05),
    B(BE,15,D0,16,FA,CB,5B,AF,BC,24,FA,92,89,13,21,66),
    B(AC,9B,70,48,ED,B1,AC,F4,D9,7A,5B,0B,3F,50,88,4B),
    B(44,8B,EC,E1,F8,6C,78,45,DF,A9,A4,BB,2A,01,6F,B3),
    B(10,DD,44,5E,87,68,6E,B4,6E,A9,B1,AB,C4,92,57,F0),
    B(B7,FC,CF,76,59,FA,75,6D,4B,73,03,EE,A6,C0,74,58),
    B(28,91,17,11,5C,A3,51,3B,AA,76,40,B1,00,48,72,C2),
    B(57,CB,42,F7,EE,71,86,05,1F,50,B9,3F,FA,7B,35,BF),
    B(F2,74,1B,FB,FB,81,66,3B,91,36,80,2F,B9,C3,12,6A),
    B(E3,2D,DD,C5,C7,39,8C,09,6E,3B,D5,35,B3,1D,B5,CE),
    B(81,D3,C2,04,E6,08,AF,9C,C7,13,EA,EB,CB,72,43,3F),
    B(D4,DE,EF,4B,FC,36,AA,A5,79,49,6E,69,35,F8,F9,8E),
    B(C3,56,DB,08,2B,97,80,2B,03,85,71,C3,92,C5,C8,F6),
    B(A3,91,9E,CD,48,61,84,5F,25,27,B7,7F,06,AC,6A,4E),
    B(A5,38,58,E1,7A,2F,80,2A,20,E4,0D,44,49,4F,FD,A0),
    B(5D,98,9E,12,2B,78,C7,58,92,1E,DB,EE,B8,27,F0,C0),
    B(4B,1C,0C,8F,9E,78,30,CC,3C,4B,E7,BD,22,6F,A8,DE),
    B(82,C4,0C,5F,D8,97,FB,CA,7B,89,9C,70,71,35,73,A1),
    B(ED,13,EE,2D,45,E0,0F,75,CC,DB,51,EA,8E,3E,36,AD),
    B(F1,21,79,9E,EF,E8,43,24,23,17,6A,3C,CF,64,62,BB),
    B(4F,A0,C0,6F,07,99,7E,98,27,1D,D8,6F,7B,35,5C,50),
    B(84,9E,B3,64,B4,E8,1D,05,86,49,DC,5B,1B,F0,29,B9),
    B(F4,8F,9E,0D,E8,DE,7A,D9,44,A2,07,80,93,35,D9,B1),
    B(E5,9E,92,05,B5,A8,1A,4F,D2,6D,FC,F3,08,96,60,22),
    B(3A,91,A1,BE,14,AA,E9,ED,70,0B,DF,9D,70,01,88,04),
    B(8A,BA,D7,8D,CB,79,A4,8D,79,07,0E,7D,A8,96,64,EC),
    B(B6,83,77,D9,8A,AE,60,44,93,8A,74,57,F6,C6,49,D9),
    B(E4,E1,27,5C,42,F5,F1,B6,3D,66,2C,09,9D,6C,E3,3D),
    B(7D,EF,32,A3,4C,6B,E6,68,F1,7D,A1,BB,19,3B,06,EF),
    B(78,B6,00,0C,C3,D3,0C,B3,A7,4B,68,D0,ED,BD,2B,53),
    B(0A,47,53,1D,E8,8D,D8,AE,5C,23,EA,E4,F7,D1,F2,D5),
    B(66,7B,24,E8,00,0C,F6,82,31,EC,48,45,81,D9,22,E5),
    B(39,DA,A5,EB,D4,AA,CA,E1,30,E9,C3,32,36,C5,20,24),
    B(E3,C8,87,60,B3,CB,21,36,06,68,A6,3E,55,BB,45,D1),
    B(F1,31,EE,90,3C,1C,DB,49,D4,16,86,6F,D5,D8,DE,51),
    B(7A,19,16,13,5B,04,47,CF,40,33,FC,13,04,7A,58,3A),
    B(F7,D5,5F,B2,79,91,14,3D,CD,FA,90,DD,F0,42,4F,CB),
    B(EA,93,E7,D1,CA,11,11,DB,D8,F7,EC,11,1A,84,8C,0C),
    B(2A,68,9E,39,DF,D3,CB,CB,E2,21,32,6E,95,88,87,79),
    B(C1,CE,39,9C,A7,62,31,8A,C2,C4,0D,19,28,B4,C5,7D),
    B(D4,3F,B6,F2,B2,87,9C,8B,FA,F0,09,2D,A2,CA,63,ED),
    B(22,45,63,E6,17,15,8D,F9,76,50,AF,5D,13,0E,78,A5),
    B(65,62,FD,F6,83,3B,7C,4F,74,84,AE,6E,BC,C2,43,DD),
    B(93,D5,8B,A7,BE,D2,26,15,D6,61,D0,02,88,5A,74,57),
    B(9A,0E,F5,59,00,3A,D9,E5,2D,3E,09,ED,3C,1D,33,20),
    B(96,BA,F5,A7,DC,6F,3D,D2,7E,B4,C7,17,A8,5D,26,1C),
    B(B8,76,2E,06,88,49,00,E8,45,22,93,19,0E,19,CC,DB),
    B(78,54,16,A2,2B,D6,3C,BA,BF,4B,17,89,35,51,97,D3),
    B(A0,D2,0C,E1,48,9B,AA,69,A3,61,2D,CE,90,F7,AB,F6),
    B(70,02,44,E9,3D,C9,42,30,CC,60,7F,FB,A0,E4,8F,32),
    B(85,32,9E,47,68,29,F8,72,A2,B4,A7,E5,9F,91,FF,2D),
    B(E4,21,9B,49,35,D9,88,DB,71,9B,8B,8B,2B,53,D2,47),
    B(6A,CD,D0,4F,D1,3D,4D,B4,40,9F,E8,DD,13,FD,73,7B),
    B(9E,B7,A6,70,AB,59,E1,5B,E5,82,37,87,01,C1,EC,14),
    B(29,DF,2D,69,35,FE,65,77,63,BC,7A,9F,22,D3,D4,92),
    B(99,30,33,59,D4,A1,3A,FD,BE,6C,78,40,28,CE,53,3A),
    B(FF,5C,70,A6,33,45,45,F3,3B,9D,BF,7B,EA,04,17,CA),
    B(28,9F,58,A1,7E,4C,50,ED,A4,26,9E,FB,3D,F5,58,15),
    B(EA,35,DC,B4,16,E9,E1,C2,86,1D,16,82,F0,62,B5,EB),
    B(3A,47,BF,35,4B,E7,75,38,3C,50,B0,C0,A8,3E,3A,58),
    B(BF,6C,1D,C0,69,FB,95,D0,5D,43,B0,1D,82,06,D6,6B),
    B(04,6D,1D,58,0D,58,98,DA,65,95,F3,2F,D1,F0,C3,3D),
    B(5F,57,80,3B,7B,82,A1,10,F7,E9,85,5D,6A,54,60,82),
    B(25,33,6E,CF,34,E7,BE,97,86,2C,DF,F7,15,FF,05,A8),
    B(AC,BA,A2,A9,43,D8,07,80,22,D6,93,89,0E,8C,4F,EF),
    B(39,47,59,78,79,F6,B5,8E,4E,2F,0D,F8,25,A8,3A,38),
    B(4E,B8,CC,33,35,49,61,30,65,5B,F3,CA,57,0A,4F,C0),
    B(BB,DA,77,69,AD,1F,DA,42,5E,18,33,2D,97,86,88,24),
    B(5E,75,32,D2,2D,DB,08,29,A2,9C,86,81,98,39,71,54),
    B(E6,6D,A6,7B,63,0A,B7,AE,3E,68,28,55,E1,A1,69,8E),
    B(4D,93,80,0F,67,1B,48,55,9A,64,D1,EA,03,0A,59,0A),
    B(F3,31,59,FC,C7,D9,AE,30,C0,62,CD,3B,32,2A,C7,64),
    B(8B,AE,4E,FB,70,D3,3A,97,92,EE,A9,BE,70,88,9D,72),
};

static uint8_t
aes_vk_256[256][16] = {
    B(E3,5A,6D,CB,19,B2,01,A0,1E,BC,FA,8A,A2,2B,57,59),
    B(50,75,C2,40,5B,76,F2,2F,55,34,88,CA,E4,7C,E9,0B),
    B(49,DF,95,D8,44,A0,14,5A,7D,E0,1C,91,79,33,02,D3),
    B(E7,39,6D,77,8E,94,0B,84,18,A8,61,20,E5,F4,21,FE),
    B(05,F5,35,C3,6F,CE,DE,46,57,BE,37,F4,08,7D,B1,EF),
    B(D0,C1,DD,DD,10,DA,77,7C,68,AB,36,AF,51,F2,C2,04),
    B(1C,55,FB,81,1B,5C,64,64,C4,E5,DE,15,35,A7,55,14),
    B(52,91,7F,3A,E9,57,D5,23,0D,3A,2A,F5,7C,7B,5A,71),
    B(C6,E3,D5,50,17,52,DD,5E,9A,EF,08,6D,6B,45,D7,05),
    B(A2,4A,9C,7A,F1,D9,B1,E1,7E,1C,9A,3E,71,1B,3F,A7),
    B(B8,81,EC,A7,24,A6,D4,3D,BC,6B,96,F6,F5,9A,0D,20),
    B(EC,52,4D,9A,24,DF,FF,2A,96,39,87,9B,83,B8,E1,37),
    B(34,C4,F3,45,F5,46,62,15,A0,37,F4,43,63,5D,6F,75),
    B(5B,A5,05,5B,ED,B8,89,5F,67,2E,29,F2,EB,5A,35,5D),
    B(B3,F6,92,AA,3A,43,52,59,EB,BE,F9,B5,1A,D1,E0,8D),
    B(41,4F,EB,43,76,F2,C6,4A,5D,2F,BB,2E,D5,31,BA,7D),
    B(A2,0D,51,9E,3B,CA,33,03,F0,7E,81,71,9F,61,60,5E),
    B(A0,8D,10,E5,20,AF,81,1F,45,BD,60,A2,DC,0D,C4,B1),
    B(B0,68,93,A8,C5,63,C4,30,E6,F3,85,88,26,EF,BB,E4),
    B(0F,FE,E2,6A,E2,D3,92,9C,6B,D9,C6,BE,DF,F8,44,09),
    B(4D,0F,5E,90,6E,D7,78,01,FC,0E,F5,3E,DC,5F,9E,2B),
    B(8B,6E,C0,01,19,AD,8B,02,6D,CE,56,EA,7D,EF,E9,30),
    B(69,02,65,91,D4,33,63,EE,9D,83,B5,00,7F,0B,48,4E),
    B(27,13,5D,86,95,0C,6A,2F,86,87,27,06,27,9A,47,61),
    B(35,E6,DB,87,23,F2,81,DA,41,0C,3A,C8,53,5E,D7,7C),
    B(57,42,7C,F2,14,B8,C2,8E,4B,BF,48,7C,CB,8D,0E,09),
    B(6D,F0,1B,F5,6E,51,31,AC,87,F9,6E,99,CA,B8,63,67),
    B(38,56,C5,B5,57,90,B7,68,BB,F7,D4,30,31,57,9B,CF),
    B(1E,6E,D8,FB,7C,15,BC,4D,2F,63,BA,70,37,ED,44,D0),
    B(E1,B2,ED,6C,D8,D9,3D,45,55,34,E4,01,15,6D,4B,CF),
    B(EF,BC,CA,5B,DF,DA,D1,0E,87,5F,02,33,62,12,CE,36),
    B(0B,77,7F,02,FD,18,DC,E2,64,6D,CF,E8,68,DF,AF,AD),
    B(C8,A1,04,B5,69,3D,1B,14,F5,BF,1F,10,10,0B,F5,08),
    B(4C,CE,66,15,24,4A,FC,B3,84,08,FE,CE,21,99,62,EA),
    B(F9,9E,78,45,D3,A2,55,B3,94,C9,C0,50,CB,A2,58,B1),
    B(B4,AF,BB,78,7F,9B,CF,B7,B5,5F,DF,44,7F,61,12,95),
    B(AE,1C,42,6A,69,7F,AF,28,08,B7,EF,6A,DD,B5,C0,20),
    B(75,72,F9,28,11,A8,5B,9B,DD,38,DE,AD,99,45,BC,AE),
    B(71,BC,7A,A4,6E,43,FB,95,A1,81,52,7D,9F,6A,36,0F),
    B(55,42,EF,29,23,06,6F,1E,C8,F5,46,DD,0D,8E,7C,A8),
    B(6B,92,31,7C,7D,62,37,90,B7,48,FD,D7,EF,C4,24,22),
    B(0F,E7,C0,97,E8,99,C7,1E,F0,45,36,0F,8D,6C,25,CF),
    B(4E,CE,7E,E1,07,D0,26,4D,04,69,31,51,C2,5B,9D,F6),
    B(FD,6A,E6,87,CB,FC,A9,E3,01,04,58,88,D3,BB,96,05),
    B(47,6B,57,9C,85,56,C7,25,44,24,90,2C,C1,D6,D3,6E),
    B(41,33,CB,CD,FD,D6,B8,86,0A,1F,C1,86,65,D6,D7,1B),
    B(3B,36,EC,26,64,79,8C,10,8B,81,68,12,C6,5D,FD,C7),
    B(36,4E,20,A2,34,FE,A3,85,D4,8D,C5,A0,9C,9E,70,CF),
    B(4A,4B,A2,59,69,DE,3F,5E,E5,64,2C,71,AA,D0,EF,D1),
    B(E4,2C,BA,AE,43,29,7F,67,A7,6C,1C,50,1B,B7,9E,36),
    B(23,CE,DE,DA,4C,15,B4,C0,37,E8,C6,14,92,21,79,37),
    B(A1,71,91,47,A1,F4,A1,A1,18,0B,D1,6E,85,93,DC,DE),
    B(AB,82,33,7E,9F,B0,EC,60,D1,F2,5A,1D,00,14,19,2C),
    B(74,BF,2D,8F,C5,A8,38,8D,F1,A3,A4,D7,D3,3F,C1,64),
    B(D5,B4,93,31,7E,6F,BC,6F,FF,D6,64,B3,C4,91,36,8A),
    B(BA,76,73,81,58,6D,A5,6A,2A,8D,50,3D,5F,7A,DA,0B),
    B(E8,E6,BC,57,DF,E9,CC,AD,B0,DE,CA,BF,4E,5C,F9,1F),
    B(3C,8E,5A,5C,DC,9C,EE,D9,08,15,D1,F8,4B,B2,99,8C),
    B(28,38,43,02,0B,A3,8F,05,60,01,B2,FD,58,5F,7C,C9),
    B(D8,AD,C7,42,6F,62,3E,CE,87,41,A7,06,21,D2,88,70),
    B(D7,C5,C2,15,59,2D,06,F0,0E,6A,80,DA,69,A2,8E,A9),
    B(52,CF,6F,A4,33,C3,C8,70,CA,C7,01,90,35,8F,7F,16),
    B(F6,3D,44,2A,58,4D,A7,17,86,AD,EC,9F,33,46,DF,75),
    B(54,90,78,F4,B0,CA,70,79,B4,5F,9A,5A,DA,FA,FD,99),
    B(F2,A5,98,6E,E4,E9,98,4B,E2,BA,FB,79,EA,81,52,FA),
    B(8A,74,53,50,17,B4,DB,27,76,66,8A,1F,AE,64,38,4C),
    B(E6,13,34,2F,57,A9,7F,D9,5D,C0,88,71,1A,5D,0E,CD),
    B(3F,FA,EB,F6,B2,2C,F1,DC,82,AE,17,CD,48,17,5B,01),
    B(BA,FD,52,EF,A1,5C,24,8C,CB,F9,75,77,35,E6,B1,CE),
    B(7A,F9,4B,C0,18,D9,DD,D4,53,9D,2D,D1,C6,F4,00,0F),
    B(FE,17,7A,D6,1C,A0,FD,B2,81,08,6F,BA,8F,E7,68,03),
    B(74,DB,EA,15,E2,E9,28,5B,AD,16,3D,7D,53,42,51,B6),
    B(23,DD,21,33,1B,3A,92,F2,00,FE,56,FF,05,0F,FE,74),
    B(A6,9C,5A,A3,4A,B2,0A,85,8C,AF,A7,66,EA,CE,D6,D8),
    B(3F,72,BB,4D,F2,A4,F9,41,A4,A0,9C,B7,8F,04,B9,7A),
    B(72,CC,43,57,7E,1F,D5,FD,14,62,2D,24,D9,7F,CD,CC),
    B(D8,3A,F8,EB,E9,3E,0B,6B,99,CA,FA,DE,22,49,37,D1),
    B(44,04,23,29,12,8D,56,CA,A8,D0,84,C8,BD,76,9D,1E),
    B(14,10,2D,72,29,0D,E4,F2,C4,30,AD,D1,ED,64,BA,1D),
    B(44,91,24,09,7B,1E,CD,0A,E7,06,52,06,DF,06,F0,3C),
    B(D0,60,A9,9F,8C,C1,53,A4,2E,11,E5,F9,7B,D7,58,4A),
    B(65,60,5B,3E,A9,26,14,88,D5,3E,48,60,2A,DE,A2,99),
    B(C5,E5,CA,D7,A2,08,DE,8E,A6,BE,04,9E,FE,5C,73,46),
    B(4C,28,0C,46,D2,18,16,46,04,8D,D5,BC,0C,08,31,A5),
    B(5D,D6,5C,F3,7F,2A,09,29,55,9A,AB,AF,DA,08,E7,30),
    B(31,F2,33,5C,AA,F2,64,17,2F,69,A6,93,22,5E,6D,22),
    B(3E,28,B3,5F,99,A7,26,62,59,0D,A9,64,26,DD,37,7F),
    B(57,0F,40,F5,D7,B2,04,41,48,65,78,ED,34,43,43,BE),
    B(C5,43,08,AD,1C,9E,3B,19,F8,B7,41,78,73,04,5A,8C),
    B(CB,F3,35,E3,9C,E1,3A,DE,2B,69,61,79,E8,FD,0C,E1),
    B(9C,2F,BF,42,23,55,D8,29,30,83,D5,1F,4A,3C,18,A9),
    B(5E,D8,B5,A3,1E,CE,FA,B1,6C,9A,A6,98,6D,A6,7B,CE),
    B(62,78,15,DC,FC,81,4A,BC,75,90,00,41,B1,DD,7B,59),
    B(9E,F3,E8,2A,50,A5,9F,16,62,60,49,4F,7A,7F,2C,C3),
    B(87,8C,D0,D8,D9,20,88,8B,59,35,D6,C3,51,12,87,37),
    B(E4,44,29,47,4D,6F,C3,08,4E,B2,A6,B8,B4,6A,F7,54),
    B(EB,AA,CF,96,41,D5,4E,1F,B1,8D,0A,2B,E4,F1,9B,E5),
    B(13,B3,BF,49,7C,EE,78,0E,12,3C,7E,19,3D,EA,3A,01),
    B(6E,8F,38,1D,E0,0A,41,16,1F,0D,F0,3B,41,55,BF,D4),
    B(35,E4,F2,9B,BA,2B,AE,01,14,49,10,78,3C,3F,EF,49),
    B(55,B1,7B,D6,67,88,CE,AC,36,63,98,A3,1F,28,9F,FB),
    B(11,34,1F,56,C0,D6,D1,00,8D,28,74,1D,AA,76,79,CE),
    B(4D,F7,25,3D,F4,21,D8,33,58,BD,BE,92,47,45,D9,8C),
    B(BA,E2,EE,65,11,16,D9,3E,DC,8E,83,B5,F3,34,7B,E1),
    B(F9,72,1A,BD,06,70,91,57,18,3A,F3,96,5A,65,9D,9D),
    B(19,A1,C2,52,A6,13,FE,28,60,A4,AE,6D,75,CE,6F,A3),
    B(B5,DD,B2,F5,D9,75,2C,94,9F,BD,E3,FF,F5,55,6C,6E),
    B(81,B0,44,FC,FF,C7,8E,CC,FC,D1,71,AA,D0,40,5C,66),
    B(C6,40,56,6D,3C,06,02,0E,B2,C4,2F,1D,62,E5,6A,9B),
    B(EA,6C,4B,CF,42,52,91,67,9F,DF,FD,26,A4,24,FB,CC),
    B(57,F6,90,14,65,D9,44,0D,9F,15,EE,2C,BA,5A,40,90),
    B(FB,CF,A7,4C,AD,C7,40,62,60,F6,3D,96,C8,AA,B6,B1),
    B(DF,F4,F0,96,CE,A2,11,D4,BB,DA,CA,03,3D,0E,C7,D1),
    B(1E,E5,19,0D,55,1F,0F,42,F6,75,22,7A,38,12,96,A9),
    B(F9,8E,19,05,01,2E,58,0F,09,76,23,C1,0B,93,05,4F),
    B(E7,D4,37,43,D2,1D,D3,C9,F1,68,C8,68,56,55,8B,9A),
    B(63,2A,9D,DA,73,0D,AB,67,59,3C,5D,08,D8,AC,10,59),
    B(E0,84,31,70,00,71,5B,90,57,BC,9D,E9,F3,AB,61,24),
    B(61,F9,EF,33,A0,BB,4E,66,6C,2E,D9,91,01,91,9F,AB),
    B(6D,C1,D6,8A,11,83,46,57,D4,67,03,C2,25,78,D5,9A),
    B(53,AC,15,48,86,3D,3D,16,F1,D4,DC,72,42,E0,5F,2C),
    B(E8,2C,D5,87,A4,08,30,6A,D7,8C,EA,E0,91,6B,9F,8C),
    B(0F,D2,D4,0E,A6,AD,17,A3,A7,67,F0,A8,60,0D,62,95),
    B(AD,84,CC,82,55,AD,B3,9D,FC,A2,3F,92,76,1A,E7,E9),
    B(F4,F2,0C,F7,D5,1B,EE,7D,A0,24,A2,B1,1A,7E,CA,0B),
    B(50,57,69,1B,85,D9,CE,93,A1,93,21,4D,B0,A0,16,B6),
    B(0F,58,C9,60,87,63,90,BD,EF,4B,B6,BE,95,CA,A1,EE),
    B(9A,3E,66,EE,BC,21,BC,0B,D9,43,0B,34,1E,F4,65,FA),
    B(20,41,50,35,F3,4B,8B,CB,CB,28,AB,F0,7F,78,F0,D4),
    B(AC,89,FC,7B,A1,04,79,EB,F1,0D,E6,5B,CE,F8,9B,3C),
    B(06,8F,A7,5A,30,BE,44,31,71,AF,3F,6F,EB,1A,20,D2),
    B(50,E0,2F,21,32,46,C5,25,A8,C2,77,00,CA,34,B5,02),
    B(22,7D,A4,7D,5A,09,06,DB,3A,B0,42,BB,0A,69,5F,B6),
    B(86,63,AC,30,ED,12,51,4F,1D,E4,67,77,F4,51,4B,FC),
    B(A9,87,D4,BC,12,E1,DE,9F,4B,6D,F4,35,67,C3,4A,8B),
    B(6D,5A,03,70,F5,99,AC,A6,05,F6,3B,04,E5,14,3D,0C),
    B(98,09,26,6E,37,8B,07,B7,AF,DB,3B,AA,97,B7,E4,42),
    B(8F,75,32,52,B3,0C,CC,AC,E1,2D,9A,30,1F,4D,50,90),
    B(03,24,65,F6,C0,CE,34,D4,19,62,F5,61,69,2A,1A,FF),
    B(C5,0E,9A,D5,BE,B8,F3,B0,08,21,DD,47,FF,8A,C0,93),
    B(9C,6F,EA,3D,46,26,8D,54,A6,82,9B,2A,D2,5B,B2,76),
    B(0F,D8,57,5E,87,70,6F,56,13,43,D7,B3,A4,1E,04,4A),
    B(BE,E9,BE,B3,73,95,40,D8,8C,BC,E7,79,25,F0,A1,14),
    B(D2,4E,AE,E7,FF,FB,AC,3D,6F,26,C2,DC,E0,DC,DE,28),
    B(47,77,1A,90,39,8F,F0,F7,FA,82,1C,2F,8F,5E,13,98),
    B(46,39,74,1B,6F,84,B1,35,AD,11,8C,82,49,B6,4E,D0),
    B(8E,E5,50,5E,C8,55,67,69,7A,33,06,F2,50,A2,77,20),
    B(7C,8A,19,AC,1A,EF,BC,5E,01,19,D9,1A,5F,05,D4,C2),
    B(51,41,B9,B6,72,E5,47,73,B6,72,E3,A6,C4,24,88,7B),
    B(B5,A2,D3,CD,20,66,53,C6,40,2F,34,FB,0A,E3,61,3D),
    B(0F,5B,D9,40,87,38,23,1D,11,4B,0A,82,75,32,79,A3),
    B(FE,F0,33,FF,42,68,EA,48,7F,C7,4C,5E,43,A4,53,38),
    B(A3,ED,C0,9D,CD,52,9B,11,39,10,D9,04,AD,85,55,81),
    B(AB,8F,BB,6F,27,A0,AC,7C,55,B5,9F,DD,36,B7,2F,1C),
    B(EE,A4,4D,5E,D4,D7,69,CC,93,0C,D8,3D,89,99,EC,46),
    B(69,72,27,68,03,AE,9A,A7,C6,F4,31,AB,10,97,9C,34),
    B(86,DE,AA,9F,39,24,41,01,81,81,78,47,4D,7D,BD,E9),
    B(88,C6,B4,66,EA,36,1D,66,2D,8D,08,CB,F1,81,F4,FE),
    B(91,AB,2C,6B,7C,63,FF,59,F7,CB,EE,BF,91,B2,0B,95),
    B(2D,FE,6C,14,6A,D5,B3,D8,C3,C1,71,8F,13,B4,8E,01),
    B(C7,CF,F1,62,34,51,71,13,91,A3,02,EE,C3,58,4A,AA),
    B(08,9F,E8,45,CC,05,01,16,86,C6,60,19,D1,8B,E0,50),
    B(08,C8,41,0B,9B,42,72,11,A6,71,24,B0,DC,CE,AD,48),
    B(8D,91,59,2F,55,66,08,52,54,78,46,06,33,4D,76,29),
    B(32,98,FE,AA,F2,E1,20,1D,62,99,FF,88,46,63,9C,97),
    B(C4,97,CB,9F,0B,DF,E0,EF,C8,C2,F3,F9,07,60,AA,72),
    B(27,88,AF,D0,46,E0,30,9C,BE,44,24,69,0D,A2,AB,89),
    B(E9,89,17,07,F2,5E,F2,9F,EE,37,28,90,D4,25,89,82),
    B(DB,04,1D,94,A2,3D,45,D4,D4,DC,ED,5A,03,0C,AF,61),
    B(FF,AF,DB,F0,EC,B1,8D,F9,EA,02,C2,70,77,44,8E,6D),
    B(2D,AA,A4,2A,7D,0A,1D,3B,0E,47,61,D9,9C,F2,15,0A),
    B(3B,7A,54,CB,7C,F3,0A,BE,26,3D,D6,ED,5B,FE,8D,63),
    B(EE,FA,09,01,74,C5,90,C4,48,A5,5D,43,64,8F,53,4A),
    B(9E,15,79,87,31,ED,42,F4,3E,A2,74,0A,69,1D,A8,72),
    B(31,FB,D6,61,54,0A,5D,EA,AD,10,17,CF,D3,90,9E,C8),
    B(CD,A9,AE,05,F2,24,14,0E,28,CB,95,17,21,B4,4D,6A),
    B(0C,5B,C5,12,C6,0A,1E,AC,34,34,EF,B1,A8,FB,B1,82),
    B(AA,86,36,10,DE,EE,EB,62,D0,45,E8,7E,A3,0B,59,B5),
    B(6A,C2,44,8D,E5,68,D2,79,C7,EE,BE,1D,F4,03,92,0C),
    B(E2,01,1E,3D,29,2B,26,88,8A,E8,01,21,5F,D0,CB,40),
    B(E0,6F,3E,15,EE,3A,61,67,2D,1C,99,BA,DE,5B,9D,BE),
    B(BB,70,27,F0,54,8C,F6,71,2C,EB,4C,7A,4B,28,E1,78),
    B(06,1E,C2,1F,B7,0F,AD,BD,F8,7C,3B,D2,AE,23,82,5B),
    B(4C,21,F2,6F,E9,4A,BB,AC,38,13,52,37,53,14,C3,EB),
    B(F7,CE,E6,DD,99,90,9C,2B,56,9E,ED,A6,1E,D8,94,2E),
    B(CE,98,C4,A8,76,C6,5E,4C,CB,26,1E,BB,1D,9D,F7,F5),
    B(A5,49,18,81,CF,83,3C,36,04,AB,C0,80,44,F4,02,AC),
    B(A1,BA,16,E6,4C,CC,B3,08,7D,57,A7,68,50,7B,0B,FC),
    B(D5,59,51,E2,02,D2,94,9E,BD,3B,E4,31,20,C7,38,BF),
    B(EB,B8,E4,30,69,E6,9F,45,0E,FE,C6,5D,CD,52,B7,FD),
    B(2B,29,21,35,66,3B,4A,A5,AB,FE,94,23,D5,7E,7E,E9),
    B(E9,1B,F9,74,B3,BE,3A,D9,66,24,9D,86,55,29,2A,85),
    B(38,43,65,99,8E,AA,95,62,23,6C,C5,8F,6A,DF,96,10),
    B(C2,E9,97,01,2A,A3,D4,D8,D3,59,C9,A9,47,CB,E6,9F),
    B(F4,94,21,20,41,48,BA,21,3B,E8,7E,2D,5C,22,B0,BF),
    B(82,ED,0E,D9,95,3A,A9,2E,4D,F3,09,29,CA,65,C0,0F),
    B(29,1E,B1,D1,16,53,C8,47,94,37,C7,4A,97,7F,51,06),
    B(BC,B9,97,B1,93,9B,89,83,AB,D5,50,D6,02,56,83,E3),
    B(1F,BA,25,92,C6,F4,89,77,5C,AA,DA,71,F9,B9,83,E9),
    B(96,9F,66,F2,17,AF,1A,3D,B9,E4,1C,1B,29,03,98,24),
    B(A5,4B,B7,D6,B1,7E,42,3A,C0,A7,74,4C,19,07,3C,B8),
    B(B0,AC,6E,65,78,D1,02,1F,47,DC,F9,74,8A,32,EA,D5),
    B(B8,7B,36,1C,3B,7B,19,4C,77,A4,35,8D,46,69,15,3E),
    B(46,A1,33,84,7F,96,EA,A8,28,2A,79,9D,C8,89,9D,58),
    B(22,65,EC,3A,9F,2D,5C,95,47,A0,91,CC,8C,FB,18,EA),
    B(54,CB,F3,A6,FC,4F,E5,6D,42,61,17,AA,1F,FD,1D,DE),
    B(53,12,87,7C,CE,AB,6C,FB,09,05,39,4A,37,0A,80,03),
    B(71,90,BD,6E,C6,13,FE,38,B8,4E,CF,E2,8F,70,2F,E4),
    B(D1,FA,5B,9C,A8,9A,43,B0,4C,05,F0,EF,29,EF,68,CD),
    B(80,82,85,75,15,48,ED,93,4F,D1,05,6D,2D,9A,E8,BA),
    B(27,58,DE,F3,E7,B9,5A,9A,E8,97,77,BE,64,D5,A6,CF),
    B(07,D8,1F,87,DB,3E,0A,CC,82,B0,1E,08,FB,22,F3,C1),
    B(8D,A2,50,E5,55,3D,65,07,11,A7,5E,E1,CB,4F,D1,C7),
    B(A9,3D,94,6B,D0,E8,7F,32,71,9D,F5,F1,58,CE,E6,69),
    B(03,94,52,36,EC,2A,4D,4E,AF,30,B8,AB,EB,54,33,0D),
    B(11,CC,35,30,1F,24,B7,9D,DE,31,AE,A2,D1,35,4F,88),
    B(E7,37,15,B3,E8,D9,A2,90,F4,4A,E6,FF,BF,24,7E,5D),
    B(73,45,E0,77,32,B7,1C,B1,58,BB,F6,4C,CA,5C,5B,96),
    B(6E,12,8F,29,6D,24,70,5A,19,24,FD,9B,70,C4,ED,04),
    B(95,A7,89,77,6F,03,67,83,FB,D3,30,94,70,83,F5,4F),
    B(36,0D,EC,25,33,EA,4A,A2,E3,E5,4F,D3,DE,29,06,EB),
    B(E6,8E,FD,7F,EC,F4,D6,01,EA,22,72,7B,D7,64,96,5B),
    B(90,65,C6,4A,8B,FF,44,AC,33,ED,BB,61,1C,F8,3D,7B),
    B(8F,33,C8,DF,2A,7A,51,CE,80,90,E8,F1,23,BC,37,23),
    B(80,7F,39,1F,FB,A8,29,1B,A6,25,62,32,10,F9,90,18),
    B(5E,8B,3F,3A,70,15,22,CE,5C,AA,76,1C,92,9D,62,92),
    B(3B,A4,04,DC,38,73,5A,78,28,9E,38,09,E8,36,48,35),
    B(D2,3B,ED,BA,D2,29,F8,30,5D,C4,25,B6,B7,59,DC,C9),
    B(44,88,0F,21,CF,59,13,04,0A,E3,76,AE,E2,A1,0A,D8),
    B(9B,C9,8E,29,D0,57,C0,E8,28,C3,B5,CC,E6,92,56,C1),
    B(B2,93,CC,7A,97,5D,A1,41,A6,82,79,36,80,57,CC,41),
    B(8D,60,FB,87,AC,D9,13,85,B3,13,BE,5F,1D,7B,D3,0F),
    B(2C,8E,56,13,2D,70,29,1B,30,3C,48,FD,F7,55,43,CD),
    B(D1,F8,00,35,B8,26,79,1F,6C,E4,E5,9B,7D,B1,BB,0D),
    B(42,CE,62,24,FC,36,46,93,39,A1,33,DD,08,17,3B,D4),
    B(61,81,71,55,EA,41,BC,BA,2A,F7,F0,6A,E7,CB,F5,85),
    B(D1,92,3A,98,66,06,8D,2E,F5,FB,77,D5,7C,33,15,B6),
    B(B3,7C,BD,B5,D7,19,F4,96,91,CA,96,8E,F2,E8,41,40),
    B(EC,97,4E,65,3A,05,5D,7F,8F,22,17,10,30,F6,8E,1D),
    B(DD,E5,D3,B9,AA,D9,C3,22,13,BB,36,75,A8,22,49,9C),
    B(D3,B6,E9,21,6E,A1,AE,57,EB,1C,62,8A,3C,38,AB,78),
    B(82,C9,9E,CC,69,47,2B,7E,96,32,4B,04,2A,E8,B8,7A),
    B(97,14,4D,C5,33,8C,43,60,0F,84,43,9C,0A,A0,D1,47),
    B(40,0A,C4,A0,BB,AD,A1,DB,21,21,EB,14,4C,7E,52,09),
    B(EF,D9,D5,50,EB,41,9E,D2,78,F4,88,5A,49,0A,B5,4C),
    B(2A,B7,81,6E,14,9B,7C,04,04,C8,8A,88,57,79,36,70),
    B(5B,59,1D,FF,9E,8D,EE,15,BA,D2,4C,02,5D,BC,A4,81),
    B(0C,06,63,3E,30,72,1C,37,49,F4,9A,D8,CB,F2,B7,54),
    B(96,D6,D3,1A,41,B5,12,3B,20,35,FD,91,A9,21,D4,CA),
    B(E7,F6,C3,4D,86,66,8B,C2,80,5C,A7,79,3C,5E,86,AD),
    B(F4,6D,FF,5F,F5,00,D6,87,9C,4D,3E,45,CF,0C,F0,F3),
    B(60,D8,42,D9,C6,1D,A7,49,5C,11,61,97,B7,CE,CB,BE),
    B(D4,5B,24,ED,B6,73,35,3E,BD,F2,48,B8,FA,06,B6,7A),
    B(11,9E,AE,BC,C1,65,D0,BD,02,C0,D3,5D,C8,2E,F9,92),
    B(E6,73,14,36,80,41,4A,DA,30,1D,0E,D3,46,26,B9,FE),
    B(6B,6C,FE,16,0A,62,63,63,1B,29,2F,87,9E,EF,F9,26),
};

static uint8_t
aes_vt_128[128][16] = {
    B(3A,D7,8E,72,6C,1E,C0,2B,7E,BF,E9,2B,23,D9,EC,34),
    B(45,BC,70,7D,29,E8,20,4D,88,DF,BA,2F,0B,0C,AD,9B),
    B(16,15,56,83,80,18,F5,28,05,CD,BD,62,02,00,2E,3F),
    B(F5,56,9B,3A,B6,A6,D1,1E,FD,E1,BF,0A,64,C6,85,4A),
    B(64,E8,2B,50,E5,01,FB,D7,DD,41,16,92,11,59,B8,3E),
    B(BA,AC,12,FB,61,3A,7D,E1,14,50,37,5C,74,03,40,41),
    B(BC,F1,76,A7,EA,AD,80,85,EB,AC,EA,36,24,62,A2,81),
    B(47,71,18,16,E9,1D,6F,F0,59,BB,BF,2B,F5,8E,0F,D3),
    B(B9,70,DF,BE,40,69,8A,F1,63,8F,E3,8B,D3,DF,3B,2F),
    B(F9,5B,59,A4,4F,39,1E,14,CF,20,B7,4B,DC,32,FC,FF),
    B(72,0F,74,AE,04,A2,A4,35,B9,A7,25,6E,49,37,8F,5B),
    B(2A,04,45,F6,1D,36,BF,A7,E2,77,07,07,30,CF,76,DA),
    B(8D,05,36,B9,97,AE,FE,C1,D9,40,11,BA,B6,69,9A,03),
    B(67,4F,00,2E,19,F6,ED,47,EF,F3,19,E5,1F,AD,44,98),
    B(29,2C,02,C5,CB,91,63,C8,0A,C0,F6,CF,1D,D8,E9,2D),
    B(FA,32,1C,F1,8E,F5,FE,72,7D,D8,2A,5C,1E,94,51,41),
    B(A5,A7,AF,E1,03,4C,39,CC,CE,BE,3C,58,4B,C0,BE,05),
    B(4F,F5,A5,2E,69,7E,77,D0,81,20,5D,BD,B2,1C,EA,39),
    B(20,9E,88,DC,94,C9,00,30,00,CE,07,69,AF,7B,71,66),
    B(5D,EE,41,AF,86,4C,B4,B6,50,E5,F5,15,51,82,4D,38),
    B(A7,9A,63,FA,7E,45,03,AE,6D,6E,09,F5,F9,05,30,30),
    B(A4,83,16,74,9F,AE,7F,AC,70,02,03,1A,6A,FD,8B,A7),
    B(D6,EE,E8,A7,35,7A,0E,1D,64,26,2C,A9,C3,37,AC,42),
    B(B0,13,CA,8A,62,A8,58,05,3E,9F,B6,67,ED,39,82,9E),
    B(DF,6E,A9,E4,53,8A,45,A5,2D,5C,1A,43,C8,8F,4B,55),
    B(7D,03,BA,45,13,71,59,1D,3F,D5,54,7D,91,65,C7,3B),
    B(0E,04,26,28,1A,62,77,E1,86,49,9D,36,5D,5F,49,FF),
    B(DB,C0,21,69,DD,20,59,E6,CC,4C,57,C1,FE,DF,5A,B4),
    B(82,65,90,E0,5D,16,7D,A6,F0,0D,CC,75,E2,27,88,EB),
    B(34,A7,3F,21,A0,44,21,D9,78,63,35,FA,AB,49,42,3A),
    B(ED,34,7D,0E,01,28,EE,1A,73,92,A1,D3,6A,B7,8A,A9),
    B(EE,94,4B,2F,E6,E9,FC,88,80,42,60,8D,A9,61,5F,75),
    B(9E,7C,85,A9,09,EF,72,18,BA,79,47,CF,B4,71,8F,46),
    B(81,1A,E0,7A,0B,2B,1F,81,65,87,FA,73,69,9A,E7,7D),
    B(68,46,6F,BF,43,C2,FE,13,D4,B1,8F,7E,C5,EA,74,5F),
    B(D2,0B,01,5C,71,91,B2,19,78,09,56,E6,10,1F,93,54),
    B(59,39,D5,C1,BB,F5,4E,E1,B3,E3,26,D7,57,BD,DE,25),
    B(B1,FD,AF,E9,A0,24,0E,8F,FE,A1,9C,E9,4B,51,05,D3),
    B(D6,29,62,EC,E0,2C,DD,68,C0,6B,DF,EF,B2,F9,49,5B),
    B(B3,BB,2D,E6,F3,C2,65,87,BA,8B,AC,4F,7A,D9,49,9A),
    B(E0,B1,07,2D,6D,9F,F7,03,D6,FB,EF,77,85,2B,0A,6B),
    B(D8,DD,51,C9,07,F4,78,DE,02,28,E8,3E,61,FD,17,58),
    B(A4,2D,FF,E6,E7,C1,67,1C,06,A2,52,36,FD,D1,00,17),
    B(25,AC,F1,41,55,0B,FA,B9,EF,45,1B,6C,6A,5B,21,63),
    B(4D,A7,FC,A3,94,9B,16,E8,21,DB,C8,4F,19,58,10,18),
    B(7D,49,B6,34,7C,BC,C8,91,9C,7F,A9,6A,37,A7,A2,15),
    B(90,00,24,B2,9A,08,C6,72,1B,95,BA,3B,75,3D,DB,4D),
    B(6D,21,82,FB,28,3B,69,34,D9,0B,A7,84,8C,AB,5E,66),
    B(F7,3E,F0,1B,44,8D,23,A4,D9,0D,E8,B2,F9,66,6E,7A),
    B(4A,D9,CD,A2,41,86,43,E9,A3,D9,26,AF,5E,6B,04,12),
    B(7C,AE,C8,E7,E5,95,39,97,D5,45,B0,33,20,1C,8C,5B),
    B(3C,43,CA,1F,6B,68,64,50,3E,27,B4,8D,88,23,0C,F5),
    B(44,F7,79,B9,31,08,FE,9F,EE,C8,80,D7,9B,A7,44,88),
    B(9E,50,E8,D9,CF,D3,A6,82,A7,8E,52,7C,90,72,A1,CF),
    B(68,D0,00,CB,C8,38,BB,E3,C5,05,D6,F8,14,C0,1F,28),
    B(2C,B2,A9,FE,C1,AC,D1,D9,B0,FA,05,20,5E,30,4F,57),
    B(01,EB,28,06,60,6E,46,44,45,20,A5,CC,61,80,CD,4B),
    B(DA,A9,B2,51,68,CC,70,23,26,F2,17,F1,A0,C0,B1,62),
    B(3E,07,E6,48,97,5D,95,78,D0,35,55,B1,75,58,07,ED),
    B(0B,45,F5,2E,80,2C,8B,8D,E0,95,79,42,5B,80,B7,11),
    B(65,95,95,DA,0B,68,F6,DF,0D,D6,CA,77,20,29,86,E1),
    B(05,FF,42,87,38,93,53,6E,58,C8,FA,98,A4,5C,73,C4),
    B(B5,B0,34,21,DE,8B,BF,FC,4E,AD,EC,76,73,39,A9,BD),
    B(78,8B,CD,11,1E,CF,73,D4,E7,8D,2E,21,BE,F5,54,60),
    B(90,9C,D9,EC,67,90,35,9F,98,2D,C6,F2,39,3D,53,15),
    B(33,29,50,F3,61,53,5F,F2,4E,FA,C8,C7,62,93,F1,2C),
    B(A6,8C,CD,4E,33,0F,FD,A9,D5,76,DA,43,6D,B5,3D,75),
    B(27,C8,A1,CC,FD,B0,B0,15,D1,ED,5B,3E,77,14,37,91),
    B(D7,6A,4B,95,88,7A,77,DF,61,0D,D3,E1,D3,B2,03,25),
    B(C0,68,AB,0D,E7,1C,66,DA,E8,3C,36,1E,F4,B2,D9,89),
    B(C2,12,0B,CD,49,ED,A9,A2,88,B3,B4,BE,79,AC,81,58),
    B(0C,54,6F,62,BF,27,73,CD,0F,56,4F,CE,CA,7B,A6,88),
    B(18,F3,46,2B,ED,E4,92,02,13,CC,B6,6D,AB,16,40,AA),
    B(FE,42,F2,45,ED,D0,E2,4B,21,6A,EB,D8,B3,92,D6,90),
    B(3D,3E,EB,C8,D3,D1,55,8A,19,4C,2D,00,C3,37,FF,2B),
    B(29,AA,ED,F0,43,E7,85,DB,42,83,6F,79,BE,6C,BA,28),
    B(21,5F,90,C6,74,4E,29,44,35,8E,78,61,91,59,A6,11),
    B(86,06,B1,AA,9E,1D,54,8E,54,42,B0,65,51,E2,C6,DC),
    B(98,7B,B4,B8,74,0E,C0,ED,E7,FE,A9,7D,F0,33,B5,B1),
    B(C0,A3,50,0D,A5,B0,AE,07,D2,F4,50,93,0B,EE,DF,1B),
    B(52,5F,DF,83,12,FE,8F,32,C7,81,48,1A,8D,AA,AE,37),
    B(BF,D2,C5,6A,E5,FB,9C,9D,E3,3A,69,44,57,2A,64,87),
    B(79,75,A5,7A,42,5C,DF,5A,A1,FA,92,91,01,F6,50,B0),
    B(BF,17,4B,C4,96,09,A8,70,9B,2C,D8,36,6D,AA,79,FE),
    B(06,C5,0C,43,22,2F,56,C8,74,B1,70,4E,9F,44,BF,7D),
    B(0C,EC,48,CD,34,04,3E,A2,9C,A3,B8,ED,52,78,72,1E),
    B(95,48,EA,34,A1,56,01,97,B3,04,D0,AC,B8,A1,69,8D),
    B(22,F9,E9,B1,BD,73,B6,B5,B7,D3,06,2C,98,62,72,F3),
    B(FE,E8,E9,34,BD,08,73,29,50,59,00,22,30,E2,98,D4),
    B(1B,08,E2,E3,EB,82,0D,13,9C,B4,AB,BD,BE,81,D0,0D),
    B(00,21,17,76,81,E4,D9,0C,EA,F6,9D,CE,D0,14,51,25),
    B(4A,8E,31,44,52,CA,8A,8A,36,19,FC,54,BC,42,36,43),
    B(65,04,74,74,F7,22,2C,94,C6,96,54,25,FF,1B,FD,0A),
    B(E1,23,F5,51,A9,C4,A8,48,96,22,B1,6F,96,1A,9A,A4),
    B(EF,05,53,09,48,B8,09,15,02,8B,B2,B6,FE,42,93,80),
    B(72,53,5B,7F,E0,F0,F7,77,CE,DC,D5,5C,D7,7E,2D,DF),
    B(34,23,D8,EF,C3,1F,A2,F4,C3,65,C7,7D,8F,3B,5C,63),
    B(DE,0E,51,C2,64,66,3F,3C,5D,BC,59,58,0A,98,D8,E4),
    B(B2,D9,39,11,66,68,09,47,AB,09,26,41,56,71,96,79),
    B(10,DB,79,F2,3B,06,D2,63,83,5C,42,4A,F7,49,AD,B7),
    B(DD,F7,2D,27,E6,B0,1E,C1,07,EA,3E,00,5B,59,56,3B),
    B(82,66,B5,74,85,A5,95,4A,42,36,75,1D,E0,7F,66,94),
    B(66,9A,50,1E,1F,1A,DE,6E,55,23,DE,01,D6,DB,C9,87),
    B(C2,0C,48,F2,98,97,25,D4,61,D1,DB,58,9D,C0,89,6E),
    B(DE,35,15,8E,78,10,ED,11,91,82,5D,2A,A9,8F,A9,7D),
    B(4F,E2,94,F2,C0,F3,4D,06,71,B6,93,A2,37,EB,DD,C8),
    B(08,7A,E7,4B,10,CC,BF,DF,67,39,FE,B9,55,9C,01,A4),
    B(5D,C2,78,97,0B,7D,EF,77,A5,53,6C,77,AB,59,C2,07),
    B(76,07,F0,78,C7,70,85,18,4E,AA,9B,06,0C,1F,BF,FF),
    B(9D,B8,41,53,1B,CB,E7,99,8D,AD,19,99,3F,B3,CC,00),
    B(D6,A0,89,B6,54,85,4A,94,56,0B,AE,13,29,88,35,B8),
    B(E1,E2,23,C4,CF,90,CC,5D,19,5B,37,0D,65,11,46,22),
    B(1C,BE,D7,3C,50,D0,53,BD,AD,37,2C,EE,E5,48,36,A1),
    B(D3,09,E6,93,76,D2,57,AD,F2,BF,DA,15,2B,26,55,5F),
    B(74,0F,76,49,11,7F,0D,EE,6E,AA,77,89,A9,99,4C,36),
    B(76,AE,64,41,7C,29,71,84,D6,68,C5,FD,90,8B,3C,E5),
    B(60,95,FE,A4,AA,80,35,59,1F,17,87,A8,19,C4,87,87),
    B(D1,FF,4E,7A,CD,1C,79,96,7F,EB,AB,0F,74,65,D4,50),
    B(5F,5A,D3,C4,2B,94,89,55,7B,B6,3B,F4,9E,CF,5F,8A),
    B(FB,56,CC,09,B6,80,B1,D0,7C,5A,52,14,9E,29,F0,7C),
    B(FF,49,B8,DF,4A,97,CB,E0,38,33,E6,61,97,62,0D,AD),
    B(5E,07,0A,DE,53,3D,2E,09,0E,D0,F5,BE,13,BC,09,83),
    B(3A,B4,FB,1D,2B,7B,A3,76,59,0A,2C,24,1D,1F,50,8D),
    B(58,B2,43,1B,C0,BE,DE,02,55,0F,40,23,89,69,EC,78),
    B(02,53,78,6E,12,65,04,F0,DA,B9,0C,48,A3,03,21,DE),
    B(20,02,11,21,4E,73,94,DA,20,89,B6,AC,D0,93,AB,E0),
    B(03,88,DA,CE,60,B6,A3,92,F3,28,C2,B9,71,B2,FE,78),
    B(58,E2,FC,CE,FA,7E,30,61,36,7F,1D,57,A4,E7,45,5A),
};

static uint8_t
aes_vt_192[192][16] = {
    B(6C,D0,25,13,E8,D4,DC,98,6B,4A,FE,08,7A,60,BD,0C),
    B(42,3D,27,72,A0,CA,56,DA,AB,B4,8D,21,29,06,29,87),
    B(10,21,F2,A8,DA,70,EB,22,19,DC,16,80,44,45,FF,98),
    B(C6,36,E3,5B,40,25,77,F9,69,74,D8,80,42,95,EB,B8),
    B(15,66,D2,E5,7E,83,93,C1,9E,29,F8,92,EA,28,A9,A7),
    B(88,3C,87,8F,ED,70,B3,6C,C0,9D,04,0F,96,19,DD,19),
    B(06,73,45,93,A9,74,96,57,90,E7,15,59,4F,C3,4A,A9),
    B(F1,9B,38,99,48,D9,A4,55,34,E5,BD,36,C9,84,13,4A),
    B(D8,41,0D,FC,14,FA,6D,17,5E,C9,68,EA,8C,AC,51,4C),
    B(7E,6C,6E,BB,40,29,A1,77,CF,7B,2F,DD,9A,C6,BB,7A),
    B(4B,51,DD,48,50,DC,0A,6C,3A,46,D9,24,00,3D,2C,27),
    B(2E,51,0A,9D,91,7B,15,BE,32,A1,92,B1,2A,66,8F,23),
    B(88,F6,F7,99,62,B0,FB,77,FE,A8,E7,C6,32,D3,10,8E),
    B(A3,A3,5A,B1,D8,8D,AF,07,B5,27,94,A0,F0,65,38,3A),
    B(DC,6C,C8,78,43,3E,2B,3B,B1,93,04,9A,4E,CB,FC,53),
    B(EF,CD,37,63,EB,7B,1A,41,59,38,24,8A,9A,5B,4F,D5),
    B(AB,7E,9F,B9,A6,6D,BE,5B,B4,48,54,F0,7D,90,15,EE),
    B(8B,8E,9D,33,65,F8,F6,74,3E,CF,7E,33,E9,92,55,A4),
    B(54,D3,7B,4F,17,6F,F3,D8,F6,AF,C8,66,06,6D,85,72),
    B(E8,33,10,88,94,80,FB,F3,C0,03,42,E3,12,6D,0D,02),
    B(D3,21,AB,25,11,F9,2F,09,81,74,AA,2D,E6,E8,5D,A2),
    B(D8,E3,F4,0B,11,12,D5,14,9D,58,C4,81,DF,A9,98,3F),
    B(24,54,C4,E0,80,66,39,DD,F1,98,54,D6,C6,80,54,AD),
    B(A5,50,6D,41,0F,7C,A3,2F,39,55,DD,79,D9,D0,94,18),
    B(79,08,EE,40,67,76,99,56,8A,7D,C1,AA,31,7C,7E,4E),
    B(B4,B7,B2,9D,D4,3B,2F,5C,F7,65,E2,51,92,27,39,82),
    B(92,AF,E9,66,81,59,BE,FF,E2,A8,6F,85,03,26,01,64),
    B(5C,36,A2,32,FB,A6,D1,87,A8,46,57,AD,40,28,B1,8F),
    B(A2,E9,94,DF,AB,3A,79,8D,F8,F5,4F,6D,A8,7E,58,E2),
    B(6C,DA,B1,0A,72,AD,F7,7D,71,D0,76,5B,AA,E9,56,31),
    B(9F,E3,C8,01,BC,AA,F7,BB,80,0F,2E,6B,F3,27,8E,21),
    B(B4,59,D9,0D,9A,6C,39,2E,54,93,BC,91,CF,5A,08,63),
    B(05,18,A9,FA,50,07,F6,78,7E,0F,B4,E5,AC,27,D7,58),
    B(BE,D9,79,54,15,D2,85,99,70,0E,D7,95,23,84,A9,63),
    B(F0,14,04,21,17,3D,60,25,1E,F6,CA,B0,22,9B,1B,50),
    B(46,0E,B4,65,2B,3F,67,79,EA,28,CB,11,B3,75,29,ED),
    B(C4,28,3D,35,1C,96,0A,6A,C1,3C,D1,9C,CF,03,AE,38),
    B(68,15,A1,00,47,B2,C8,34,A7,98,EB,DC,C6,78,6C,75),
    B(99,BA,19,F0,CD,D5,99,0D,03,86,B3,2C,E5,6C,9C,4C),
    B(DE,76,F6,2C,61,E0,79,15,16,2D,A1,3E,79,67,9D,EC),
    B(DD,03,25,D6,85,48,03,D0,6D,1D,22,77,D5,FB,8D,67),
    B(58,0B,71,A4,1D,E3,7D,6F,AC,83,CC,B0,B3,BB,1C,97),
    B(E9,B1,AB,47,0A,1B,02,EF,0F,F5,E6,75,4A,09,2C,96),
    B(85,90,62,0F,5A,F5,99,3B,74,10,28,2F,41,26,BC,1F),
    B(8D,49,14,D2,F1,B2,2B,2E,26,8E,66,E5,32,D2,9D,7C),
    B(FD,82,6C,E4,8E,62,C5,E3,08,67,04,4B,86,BA,4B,56),
    B(10,0E,7B,83,1C,9F,35,FA,12,71,F5,F1,31,6C,6F,CF),
    B(0A,2D,D0,C1,7F,68,B9,96,AA,96,C0,07,00,3D,0B,31),
    B(C9,5F,68,C5,7E,06,B0,A2,E1,F6,23,C8,3C,5D,80,BF),
    B(57,1C,AF,C9,2C,7C,8A,5E,C5,4C,07,41,E1,86,90,5C),
    B(22,51,43,53,E9,53,12,C1,12,25,5E,1E,ED,0B,2D,F6),
    B(79,1A,8B,F4,62,BD,17,58,0B,D9,15,2C,6D,11,C6,C5),
    B(58,82,A0,17,8D,54,8F,84,A1,65,DB,80,9C,60,DC,28),
    B(3C,E4,A9,0E,ED,44,58,CA,60,39,E4,2D,DA,DB,71,C3),
    B(D3,CB,AB,26,12,07,A1,6B,E2,75,1E,77,04,4F,D7,C9),
    B(24,E3,2B,69,8A,7B,32,21,70,93,62,8B,01,F4,24,AB),
    B(9F,6A,FC,0A,F2,7C,F5,65,11,0C,77,E3,C2,4F,4F,5B),
    B(E0,88,AA,5C,DA,20,EF,26,7B,B0,39,B0,0C,72,C4,5B),
    B(5C,F1,01,8B,7E,0B,A1,77,56,01,C2,E2,79,90,03,60),
    B(3B,1A,73,88,B8,9F,B9,41,6A,D8,75,3C,F5,AF,35,D2),
    B(13,7F,A4,ED,00,AF,CD,9F,5D,8B,C0,D1,4B,D5,83,7A),
    B(80,6F,5C,9B,66,35,59,BB,56,F2,34,88,1E,4A,3E,60),
    B(80,69,A4,49,15,22,92,DF,2D,E8,64,29,92,C6,32,B6),
    B(37,C6,CF,2A,1A,BD,1B,1F,19,22,B4,6C,7B,4A,28,0D),
    B(7A,28,35,26,0E,5A,0A,A2,B5,DC,30,18,00,EC,84,38),
    B(EE,81,FA,F2,F9,05,82,13,FF,CA,CF,28,1C,B8,50,9E),
    B(57,F2,2D,93,C3,71,29,BA,33,1F,DB,A3,8E,00,5A,1E),
    B(EC,79,87,82,E8,7B,7D,9F,78,0C,C3,C3,A4,65,19,B5),
    B(43,EA,28,49,7F,5D,40,E3,A4,74,4F,A2,ED,AA,42,DE),
    B(91,F0,04,E7,DE,BF,41,B3,41,4D,D8,C5,C3,17,37,2C),
    B(C2,49,EA,E5,4E,7B,4D,F4,3B,93,8C,1B,4C,C2,83,14),
    B(32,C2,89,D7,EE,FB,99,D2,F1,7A,D7,B7,D4,5F,E1,EC),
    B(A6,75,FB,2E,8D,DB,F8,10,CE,F0,1C,F2,B7,28,CD,2B),
    B(A4,18,AA,AB,6E,69,21,CC,73,1A,A8,A3,49,38,60,80),
    B(2E,2B,0F,44,86,3E,67,D9,B0,21,5C,4A,BD,60,41,7F),
    B(F0,AF,7C,B1,9E,91,1D,48,1F,64,26,DA,EF,DD,22,40),
    B(CB,13,04,DA,AA,2D,F6,87,8F,56,AC,2E,0F,88,7E,04),
    B(B1,B7,0A,7E,6A,0C,D1,91,6D,9B,78,BE,A1,90,84,AE),
    B(0C,DE,9F,9B,E6,46,A5,FC,E3,43,6B,79,4A,9C,FC,65),
    B(68,C7,94,6D,47,6A,0A,36,67,4B,36,AF,D7,E5,DF,33),
    B(48,77,01,59,A0,7D,D8,DF,FF,06,C8,01,05,F8,D5,7C),
    B(66,5E,62,80,1B,32,60,E3,C4,5B,D3,BE,34,DF,DE,BE),
    B(41,59,C1,F6,86,BF,BE,5B,0E,50,BD,B0,DA,53,2B,69),
    B(63,33,10,0A,5A,4A,D9,17,DC,2D,4E,78,A0,48,69,A3),
    B(86,6A,45,19,AB,1D,19,9F,25,88,6B,89,D0,53,9A,CC),
    B(EC,0C,FD,37,E4,CB,C7,E8,BE,38,52,83,F7,AE,A7,5A),
    B(CA,2F,38,3A,AC,CA,08,10,AA,13,F3,E7,10,62,14,22),
    B(1D,0E,EF,68,70,44,4F,95,09,37,83,1E,C0,A5,5D,98),
    B(37,83,9B,35,ED,68,01,E7,67,04,96,D4,79,A9,50,17),
    B(02,31,7C,8C,70,98,C4,F9,4A,B8,67,AC,7A,49,DD,8D),
    B(FF,B4,CB,4E,3F,7F,8B,F3,36,7E,BD,43,23,65,18,B4),
    B(36,BE,DE,F1,E4,AA,3E,4A,40,A3,05,74,17,13,FC,BF),
    B(B2,DF,E3,C4,87,02,69,C1,E3,FE,EC,39,16,15,40,D9),
    B(14,7E,F2,51,8A,D4,5D,A0,02,60,56,EC,BF,6A,3D,FA),
    B(02,7A,75,E4,DE,63,57,90,E4,7A,CE,90,D7,92,88,04),
    B(C4,CF,3C,CB,59,BF,87,D0,AF,BD,62,9F,48,CF,BB,7B),
    B(35,16,5C,93,F5,64,C9,7E,1C,32,EF,97,E8,15,1A,87),
    B(44,9D,E3,7F,7D,5A,1B,BD,62,8A,BB,E7,E0,61,70,1D),
    B(B1,D4,5E,AF,21,8F,17,99,B1,49,BA,D6,77,FE,12,9F),
    B(BE,08,AC,6D,B6,BD,05,83,AA,9D,2A,BC,71,C7,3D,CD),
    B(BC,C8,35,BD,3D,F1,A7,9E,4C,7C,14,5B,89,9A,5C,25),
    B(3D,31,1E,A6,11,FF,5A,F3,71,30,1C,58,A8,E9,91,2D),
    B(A5,A1,BE,A5,94,AC,C7,CA,80,F0,9E,A5,AD,DB,5C,71),
    B(0F,09,49,24,29,FE,72,22,D6,CD,81,90,D9,F2,FF,BF),
    B(81,6D,22,20,A1,6B,8A,AE,E7,13,64,FD,43,63,6C,6F),
    B(D7,E8,70,24,08,41,9E,D7,31,91,B1,07,EA,F7,5A,0B),
    B(9B,17,0E,FB,1E,23,5B,43,3C,78,E2,76,BE,A0,82,F0),
    B(03,BB,EC,C5,59,8A,E9,74,43,0F,29,39,55,22,F0,96),
    B(DB,53,51,77,66,C0,E8,CF,42,05,96,07,CB,A8,93,80),
    B(2E,2A,F4,B7,93,1F,0A,EF,FA,C5,47,11,48,A5,BB,97),
    B(C8,72,C0,40,82,66,40,3B,98,4F,63,5F,F5,68,3D,E4),
    B(15,DC,F7,50,B0,E3,A6,8A,D1,F4,EF,D0,7E,89,67,B4),
    B(B4,10,92,04,8E,9E,6A,74,9F,6F,D8,CE,51,5A,23,A3),
    B(4D,A9,26,7D,62,50,79,94,31,2B,D5,C9,9A,DD,E7,30),
    B(9E,2F,CA,6D,1D,62,6E,9C,6A,92,4E,BF,7D,BF,61,8A),
    B(E0,92,E8,D7,EF,2C,24,65,AE,FB,24,93,C3,06,35,90),
    B(1C,0E,58,DA,37,D1,06,83,78,A8,8D,BE,2E,DE,4E,10),
    B(19,06,3F,85,42,32,B8,50,9A,6A,3A,6D,46,80,99,59),
    B(44,7F,B0,9E,54,EF,A2,85,F7,53,0F,25,C4,EA,00,22),
    B(F6,AB,E8,63,21,BE,40,E1,FB,FD,AF,ED,37,CC,1D,9B),
    B(4E,85,06,CD,00,66,66,34,1D,6C,F5,1F,98,B4,1F,35),
    B(53,99,5D,E0,00,9C,A1,8B,EC,AF,B8,30,7C,54,C1,4C),
    B(20,06,BF,99,F4,C5,8B,6C,C2,62,78,56,59,3F,AE,EA),
    B(2D,A6,97,D2,73,7C,B3,0B,74,4A,46,44,FA,1C,BC,6E),
    B(47,A2,2A,CD,B6,0C,3A,98,6A,8F,76,EC,D0,EA,34,33),
    B(FD,AA,17,C2,CD,E2,02,68,FE,36,E1,64,EA,53,21,51),
    B(98,E7,24,7C,07,F0,FE,41,1C,26,7E,43,84,B0,F6,00),
    B(CD,33,B2,8A,C7,73,F7,4B,A0,0E,D1,F3,12,57,24,35),
};

static uint8_t
aes_vt_256[256][16] = {
    B(DD,C6,BF,79,0C,15,76,0D,8D,9A,EB,6F,9A,75,FD,4E),
    B(C7,09,8C,21,7C,33,4D,0C,9B,DF,37,EA,13,B0,82,2C),
    B(60,F0,FB,0D,4C,56,A8,D4,EE,FE,C5,26,42,04,04,2D),
    B(73,37,6F,BB,F6,54,D0,68,6E,0E,84,00,14,77,10,6B),
    B(2F,44,3B,52,BA,5F,0C,6E,A0,60,2C,7C,4F,D2,59,B6),
    B(75,D1,1B,0E,3A,68,C4,22,3D,88,DB,F0,17,97,7D,D7),
    B(77,9B,38,D1,5B,FF,B6,3D,8D,60,9D,55,1A,5C,C9,8E),
    B(52,75,F3,D8,6B,4F,B8,68,45,93,13,3E,BF,A5,3C,D3),
    B(1C,EF,20,74,B3,36,CE,C6,2F,12,DE,A2,F6,AB,14,81),
    B(1A,EF,5A,BB,AD,9D,71,60,87,45,78,DC,D8,BA,E1,72),
    B(46,C5,25,DB,17,E7,2F,26,BF,03,21,68,46,B6,F6,09),
    B(E2,44,11,F9,41,BB,E0,87,88,78,1E,3E,C5,2C,BA,A4),
    B(83,A3,DE,DD,1D,D2,70,18,F6,A6,47,7E,40,52,75,81),
    B(B6,8F,8A,2C,DB,AB,0C,92,3C,67,FC,8F,0F,10,87,DE),
    B(64,99,44,A7,0C,32,BF,87,A7,40,9E,7A,E1,28,FD,E8),
    B(28,46,52,6D,67,38,75,39,C8,93,14,DE,9E,0C,2D,02),
    B(A9,A0,B8,40,2E,53,C7,0D,D1,68,80,54,BA,58,DD,FD),
    B(4A,72,E6,E1,B7,9C,83,AC,4B,E3,EB,A5,69,9E,ED,48),
    B(B0,E3,6B,86,7B,A4,FF,2B,77,D0,61,4B,0E,36,4E,4C),
    B(49,B5,7D,E1,41,F6,41,8E,30,90,F2,4D,DD,40,14,B6),
    B(A6,C0,D5,B9,79,72,58,E1,98,7A,C5,F6,CD,20,14,6D),
    B(42,6C,F4,BD,CA,A3,69,17,59,65,D2,6E,7C,71,EE,A2),
    B(E2,7F,48,4C,E5,4B,C9,9B,C1,A5,2B,DA,3B,51,8A,26),
    B(D1,6D,18,62,84,C7,E6,EE,64,B8,10,4E,0E,F2,0B,A5),
    B(64,31,F8,53,8A,D5,4E,1E,04,4A,9F,71,F8,EF,55,6B),
    B(EC,D5,7C,EB,45,1D,27,EB,96,C5,5B,20,42,25,7E,8E),
    B(4F,0F,18,8D,C9,11,B1,95,4A,FB,C7,34,C9,F6,88,72),
    B(B5,4D,EF,03,37,62,6B,65,61,4E,81,ED,FD,E6,20,F3),
    B(66,55,D8,07,4C,AE,0B,90,B0,D3,A3,FE,72,D4,D9,DB),
    B(C6,B7,4B,6B,9E,B4,FC,0C,9A,23,7D,B1,B6,16,D0,9A),
    B(D7,B5,D0,76,EA,56,EC,2B,20,79,1D,7A,D5,1C,CF,8F),
    B(FE,16,0C,22,4B,F0,03,CE,3B,DD,C9,0C,B5,2E,D2,2C),
    B(5E,00,DA,9B,A9,4B,5E,C0,D2,58,D8,A8,00,2E,0F,6A),
    B(09,AC,6D,CF,F4,DA,CF,F1,65,1E,2B,A2,12,A2,92,A3),
    B(B2,83,61,7E,31,8D,99,AF,83,A0,5D,98,10,BA,89,F7),
    B(0B,5F,70,CC,B4,0B,0E,F2,53,8A,E9,B4,A9,77,0B,35),
    B(43,28,2B,F1,80,24,8F,B5,17,83,9B,37,F4,DD,AA,E4),
    B(DD,BD,53,4C,8B,2E,6D,30,A2,68,F8,8C,55,AD,76,5B),
    B(A4,1A,16,4E,50,EC,2D,9F,17,5E,75,2B,75,5E,0B,5C),
    B(37,BF,F9,9F,F2,F7,AA,97,77,9E,4A,DF,6F,13,FB,10),
    B(9B,A4,F7,BD,29,81,52,90,3A,68,3C,4C,EC,66,92,16),
    B(5F,B7,50,C7,CE,10,DE,7B,45,04,24,89,14,D0,DA,06),
    B(3E,74,8B,FA,10,8E,08,6F,51,D5,6E,C7,4A,9E,0F,B9),
    B(31,D4,E5,6B,99,F5,B7,3C,1B,84,37,DF,33,2A,FB,98),
    B(9D,C6,71,7B,84,FC,55,D2,66,E7,B1,D9,B5,C5,2A,5F),
    B(8E,F8,BA,00,7F,23,C0,A5,0F,C1,20,E0,70,41,BC,CD),
    B(C5,8F,38,E1,83,9F,C1,91,8A,12,B8,C9,E8,8C,66,B6),
    B(B6,95,D7,2A,3F,CF,50,8C,40,50,E1,2E,40,06,1C,2D),
    B(5D,27,36,AD,47,8A,50,58,3B,C8,C1,1B,EF,F1,6D,7A),
    B(DF,0E,AC,A8,F1,78,47,AD,41,F9,57,8F,14,C7,B5,6B),
    B(E5,AA,14,AD,48,AD,0A,3C,47,CC,35,D5,F8,02,0E,51),
    B(11,BE,6C,8F,58,EB,D8,CE,F1,A5,3F,59,1A,68,E8,CE),
    B(EC,FE,7B,AF,CB,F4,2C,1F,EE,01,54,88,77,0B,30,53),
    B(E5,52,64,9F,8D,8E,C4,A1,E1,CD,6D,F5,0B,6E,67,77),
    B(52,1C,06,29,DE,93,B9,11,9C,DB,1D,DC,58,09,DD,EA),
    B(CB,38,A6,2A,0B,AB,17,84,15,6B,A0,38,CB,A9,9B,F6),
    B(76,CC,EE,8A,AA,CD,39,4D,E1,EE,F3,DD,A1,0C,B5,4B),
    B(6A,FF,91,0F,A1,D5,67,31,40,E2,DB,59,B8,41,60,49),
    B(06,4A,12,C0,EF,73,FB,38,68,01,BF,4F,35,F3,12,0D),
    B(22,40,E3,74,92,9D,5B,1B,B8,FF,0F,FD,DD,F6,40,EC),
    B(D4,BA,15,C9,04,C7,69,21,85,DE,85,C0,20,52,E1,80),
    B(17,14,A3,15,AB,01,66,72,8A,44,CD,91,D4,AE,90,18),
    B(6C,97,0B,DD,9F,0E,22,27,22,EA,31,A1,D1,2D,D0,AD),
    B(F5,95,6E,DF,02,BD,36,A4,01,BB,B6,CE,77,C3,D3,FB),
    B(0C,A1,1F,12,2C,CD,7C,25,9D,C5,97,EE,D3,DF,9B,C4),
    B(50,10,9A,B4,91,2A,D2,56,0B,20,6F,33,1B,62,EB,6C),
    B(DB,E7,C9,1A,41,75,61,48,89,A2,D4,BE,FD,64,84,5E),
    B(0D,33,22,85,3A,57,1A,6B,46,B7,9C,02,28,E0,DD,25),
    B(96,E4,EE,0B,B9,A1,1C,6F,B8,52,2F,28,5B,AD,DE,B6),
    B(96,70,5C,52,D2,CF,CE,82,E6,30,C9,34,77,C7,9C,49),
    B(C5,01,30,AE,D6,A1,26,14,9D,71,F3,88,8C,83,C2,32),
    B(48,16,EF,E3,DE,B3,80,56,6E,BA,0C,17,BF,58,20,90),
    B(03,90,85,7B,4C,8C,98,E4,CF,7A,2B,6F,33,94,C5,07),
    B(42,2E,73,A0,20,25,EB,E8,B8,B5,D6,E0,FA,24,FC,B2),
    B(32,71,AA,7F,4B,F1,D7,C3,80,50,A4,30,76,D4,FF,76),
    B(D2,07,49,46,F0,D3,7B,89,75,60,7B,FC,2E,70,23,4C),
    B(1A,50,91,94,C1,27,0A,B9,2E,5A,42,D3,A9,F8,D9,8B),
    B(51,24,38,94,63,60,CC,C4,A5,C6,D7,3F,6E,ED,71,30),
    B(98,CF,CD,EC,46,EB,EA,1A,28,6B,30,04,F2,74,6A,0D),
    B(A1,CF,36,99,49,67,7A,3A,F3,D5,8E,3E,AB,F2,74,1B),
    B(D8,4C,2E,1A,0E,4A,52,16,6F,A8,FF,68,89,D1,E5,E2),
    B(4A,D9,1C,CE,EF,60,11,9B,50,78,FD,16,2D,27,35,DE),
    B(28,60,79,3D,81,8E,97,AA,FF,1D,33,9D,77,02,43,8D),
    B(6F,90,68,BE,73,36,4A,E2,50,D8,9D,78,A6,C9,CE,6F),
    B(02,4F,C3,FE,F4,88,3F,EB,1A,8D,D0,05,30,5F,EC,CE),
    B(08,A6,1F,E0,81,6D,75,EA,15,EB,3C,9F,B9,CC,DE,D6),
    B(44,9C,86,DF,A1,3F,26,01,75,CE,39,79,76,86,FF,A4),
    B(4F,FF,FC,29,A5,98,58,E1,13,3F,2B,FB,1A,8A,48,17),
    B(19,42,5D,1F,64,80,B2,50,96,56,12,95,69,7D,C2,B7),
    B(31,97,47,27,EC,DD,2C,77,C3,A4,28,FC,3A,8C,B3,FC),
    B(A5,7C,D7,04,B3,C9,5E,74,4D,08,DF,44,34,58,F2,F5),
    B(48,6D,8C,19,3D,B1,ED,73,AC,B1,79,90,44,2F,C4,0B),
    B(5E,4D,BF,4E,83,AB,3B,C0,55,B9,FC,C7,A6,B3,A7,63),
    B(AC,F2,E0,A6,93,FB,BC,BA,4D,41,B8,61,E0,D8,9E,37),
    B(32,A7,CB,2A,E0,66,A5,1D,2B,78,FC,4B,4C,FC,B6,08),
    B(67,7D,49,4D,BB,73,CA,F5,5C,19,90,15,8D,A1,2F,14),
    B(08,2A,0D,23,67,51,2A,DF,0D,75,A1,51,BF,BE,0A,17),
    B(5E,5B,B7,33,79,23,C4,82,CE,8C,BA,24,9E,6A,8C,7D),
    B(D3,00,1B,A7,C7,02,6E,E3,E5,00,31,79,53,0A,FC,FC),
    B(46,EC,44,F8,93,1E,62,9F,E8,FD,89,61,31,2E,DD,E1),
    B(C5,F8,EC,D7,9C,7B,30,E8,1D,17,E3,20,79,96,93,10),
    B(5B,8A,D6,91,9E,24,CA,EB,CC,55,40,1A,EE,0C,98,02),
    B(C2,30,2B,7E,70,1B,5C,C7,F8,B2,9E,35,16,DB,BF,A6),
    B(A1,D0,4D,6A,76,F9,F7,A9,4D,49,FA,A6,4A,87,F2,44),
    B(7F,B6,F9,2D,35,B5,CB,6C,63,16,00,ED,B9,E8,60,BA),
    B(B2,EF,70,78,BC,FA,CE,07,AE,EC,3F,9B,48,83,0E,B3),
    B(F4,75,A7,49,3D,24,C7,03,6E,53,39,03,74,C3,78,B3),
    B(B3,68,02,AC,98,73,77,A3,7B,D8,EA,DC,97,C5,7D,60),
    B(AD,DC,D3,D1,96,89,C4,DD,C7,38,CE,5F,69,DC,95,05),
    B(0D,AF,8C,A2,28,84,91,54,03,C0,F0,BB,1F,4B,D7,4F),
    B(4A,F3,6B,AE,26,60,50,3B,32,48,E4,68,50,59,FD,05),
    B(7D,56,31,81,4D,D8,E9,17,D9,7A,0D,51,4C,74,39,71),
    B(BC,33,52,50,0F,C0,CB,B9,DB,5B,5F,6B,49,1C,1B,E8),
    B(6A,4A,30,BA,87,E8,7A,F6,5C,90,AE,B7,AF,ED,C7,6B),
    B(77,E6,12,58,97,66,8A,C8,E7,3E,8C,79,A6,FF,83,36),
    B(3F,A9,D3,91,04,EB,B3,23,C7,AA,AA,24,89,60,DD,1E),
    B(FA,D7,5A,D7,6A,B1,0A,DC,49,03,6B,25,0E,22,9D,39),
    B(2F,AC,AA,5F,E3,5B,22,8A,16,AC,74,08,8D,70,2E,C4),
    B(88,B6,CB,CF,DF,EF,8A,D9,17,20,A1,BB,69,A1,F3,3E),
    B(C7,E9,D2,50,99,86,32,D4,44,35,62,42,EF,04,05,8D),
    B(B1,4D,AD,8D,3D,91,53,F4,6C,0D,3A,1A,D6,3C,7A,05),
    B(60,AB,A6,78,A5,06,60,8D,08,45,96,6D,29,B5,F7,90),
    B(48,2D,C4,3F,23,88,EF,25,D2,41,44,E1,44,BD,83,4E),
    B(14,90,A0,5A,7C,EE,43,BD,E9,8B,56,E3,09,DC,01,26),
    B(AB,FA,77,CD,6E,85,DA,24,5F,B0,BD,C5,E5,2C,FC,29),
    B(DD,4A,B1,28,4D,4A,E1,7B,41,E8,59,24,47,0C,36,F7),
    B(CE,A7,40,3D,4D,60,6B,6E,07,4E,C5,D3,BA,F3,9D,18),
    B(53,0F,8A,FB,C7,45,36,B9,A9,63,B4,F1,C4,CB,73,8B),
};

#undef B

static void
dump_hex(const char *label, const uint8_t *p, size_t n)
{
    size_t i;
    fputs(label, stderr);
    for (i = 0; i < n; i++)
        fprintf(stderr, "%02x", (unsigned int)p[i]);
    putc('\n', stderr);
}

static void
aes_selftest_vk(void (*init)(void *, const uint8_t *),
                uint8_t expected[][16],
                size_t n)
{
    aes_context ctx;
    size_t i;
    uint8_t pt[16];
    uint8_t ct[16];
    uint8_t key[32];
    bool failed = false;

    memset(pt, 0, 16);
    for (i = 0; i < n; i++)
    {
        memset(key, 0, 32);
        key[i/8] |= (1 << (7 - i%8));
        init(&ctx, key);
        aes_encrypt_block(&ctx, pt, ct);
        if (memcmp(ct, expected[i], 16))
        {
            fprintf(stderr, "FAIL: aes_vk_%zd[%zd]:\n", n, i);
            dump_hex("key: ", key, n/8);
            dump_hex("exp: ", expected[i], 16);
            dump_hex("got: ", ct, 16);
            failed = true;
        }
    }

    if (failed)
        abort();
}

static void
aes_selftest_vt(void (*init)(void *, const uint8_t *),
                uint8_t expected[][16],
                size_t n)
{
    aes_context ctx;
    size_t i;
    uint8_t pt[16];
    uint8_t ct[16];
    uint8_t key[32];
    bool failed = false;

    /* always provide the maximum size key */
    memset(key, 0, 32);
    init(&ctx, key);

    for (i = 0; i < 128; i++)
    {
        memset(pt, 0, 16);
        pt[i/8] |= (1 << (7 - i%8));
        aes_encrypt_block(&ctx, pt, ct);
        if (memcmp(ct, expected[i], 16))
        {
            fprintf(stderr, "FAIL: aes_vt_%zd[%zd]:\n", n, i);
            dump_hex("exp: ", expected[i], 16);
            dump_hex("got: ", ct, 16);
            failed = true;
        }
    }

    if (failed)
        abort();
}

/* AES keystream test vectors synthesized for this application with a
 * different implementation of AES (the one in OpenSSL).  The test
 * keys are the same ones used for arc4's selftests (q.v.)  as is the
 * pattern of sample offsets.  We only bother testing aes128 here
 * because we've already covered the block cipher primitives adequately;
 * the point of _this_ test is to test aes_gen_keystream.
 */

static const uint8_t
aes_test_keystream_keys[2][16] = {
    { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 },
    { 0xeb, 0xb4, 0x62, 0x27, 0xc6, 0xcc, 0x8b, 0x37,
      0x64, 0x19, 0x10, 0x83, 0x32, 0x22, 0x77, 0x2a }
};

static const struct
{
    unsigned int offset;
    uint8_t sample[16];
}
aes_test_keystreams[2][18] = {
    {
        {    0, { 0xdb, 0xf1, 0x84, 0x11, 0x2e, 0xb9, 0x11, 0x16,
                  0x59, 0x71, 0x2b, 0xaf, 0xcf, 0xf2, 0xab, 0x24 } },
        {   16, { 0x9a, 0x7a, 0x06, 0x19, 0xaa, 0xc2, 0x9e, 0x6c,
                  0x1f, 0x2b, 0x5c, 0x47, 0x53, 0xd5, 0x88, 0xf3 } },
        {  240, { 0x98, 0xc2, 0xdf, 0x4a, 0x0e, 0xa0, 0x2f, 0xcb,
                  0x63, 0x83, 0xff, 0x34, 0xd8, 0x4f, 0x10, 0x37 } },
        {  256, { 0x3c, 0xe3, 0xb1, 0xdf, 0x6b, 0x0d, 0x29, 0xd1,
                  0xdb, 0x01, 0x54, 0xa3, 0xcb, 0x05, 0xe4, 0xd9 } },
        {  496, { 0x00, 0x24, 0xcb, 0xff, 0x01, 0x05, 0x43, 0xc2,
                  0xd2, 0xe9, 0x07, 0x81, 0x2f, 0xe3, 0x19, 0xa7 } },
        {  512, { 0xca, 0x5d, 0xf6, 0x19, 0x8a, 0x83, 0x0f, 0xcb,
                  0x2e, 0x09, 0xd4, 0xd9, 0x46, 0x38, 0xe9, 0x09 } },
        {  752, { 0x6b, 0xc0, 0x0c, 0x0b, 0xea, 0xe8, 0x39, 0x33,
                  0xac, 0xb8, 0x3e, 0x1d, 0xf2, 0xdc, 0x1b, 0x3e } },
        {  768, { 0x14, 0xfd, 0x5e, 0x53, 0x52, 0xe4, 0x6e, 0xb8,
                  0x23, 0xc3, 0x3c, 0xf6, 0x74, 0xd6, 0x29, 0x2a } },
        { 1008, { 0x68, 0xf5, 0x46, 0xac, 0x16, 0x67, 0xf4, 0x39,
                  0x37, 0xdc, 0x48, 0x93, 0xdb, 0x32, 0x92, 0x49 } },
        { 1024, { 0x50, 0x0b, 0x4d, 0x0b, 0x7c, 0x54, 0x55, 0x17,
                  0xfb, 0x06, 0x65, 0xbb, 0xe2, 0xe0, 0xad, 0x8a } },
        { 1520, { 0x71, 0x26, 0x26, 0xe1, 0xce, 0xf6, 0xd9, 0x1f,
                  0xe0, 0x37, 0x09, 0x75, 0x67, 0xe3, 0x9e, 0x65 } },
        { 1536, { 0x35, 0xca, 0xe5, 0x6d, 0x60, 0x47, 0xa4, 0x68,
                  0x46, 0x0f, 0x1b, 0x95, 0x8d, 0x4c, 0x84, 0x96 } },
        { 2032, { 0x15, 0x01, 0x2a, 0xf8, 0xc0, 0x63, 0x4b, 0x62,
                  0x83, 0xa2, 0x0e, 0xa7, 0x6c, 0x7b, 0xd7, 0x0d } },
        { 2048, { 0xa8, 0x2c, 0xcd, 0xc4, 0xa5, 0xbe, 0x64, 0x43,
                  0x72, 0xbf, 0x7c, 0x66, 0x63, 0xa8, 0xc8, 0xeb } },
        { 3056, { 0x3b, 0x5c, 0x8d, 0x47, 0xa0, 0xb7, 0xcf, 0x74,
                  0x16, 0x69, 0xb8, 0xfa, 0xd0, 0x33, 0xbf, 0x30 } },
        { 3072, { 0x92, 0xb7, 0xb7, 0x35, 0xd1, 0xef, 0x5e, 0x01,
                  0xaf, 0x69, 0x61, 0x02, 0x60, 0x70, 0xdb, 0x30 } },
        { 4080, { 0x13, 0xbc, 0x92, 0xc0, 0x88, 0x31, 0x03, 0x33,
                  0x5d, 0xe8, 0xd6, 0x71, 0x2f, 0x17, 0x60, 0x6a } },
        { 4096, { 0x93, 0x6d, 0x5e, 0x5e, 0x4f, 0xb8, 0x40, 0x96,
                  0xc5, 0x54, 0x8c, 0x07, 0xaf, 0xf6, 0x62, 0x2c } },
    },
    {
        {    0, { 0xfc, 0x2b, 0x47, 0xbb, 0xdb, 0x39, 0xa2, 0x27,
                  0x4c, 0x88, 0xa8, 0xce, 0x04, 0x8a, 0x8b, 0xd4 } },
        {   16, { 0x69, 0x6d, 0x0f, 0x19, 0xa4, 0x67, 0x38, 0x4b,
                  0xde, 0xd2, 0xa8, 0x87, 0xac, 0x8b, 0xda, 0xd8 } },
        {  240, { 0xee, 0xa3, 0x74, 0xe3, 0x3d, 0xfb, 0xa7, 0x7e,
                  0x74, 0xdb, 0x7d, 0x9f, 0x8b, 0x5e, 0x49, 0xc6 } },
        {  256, { 0xb7, 0xf6, 0x4e, 0xd0, 0x91, 0x4d, 0x2b, 0xa1,
                  0xff, 0x96, 0xd9, 0x7d, 0xf2, 0xae, 0xc1, 0xd1 } },
        {  496, { 0x52, 0xfd, 0xdc, 0x58, 0xd6, 0xf1, 0x7a, 0xe7,
                  0x8d, 0x2b, 0x7c, 0x90, 0x00, 0xe1, 0xa7, 0xbe } },
        {  512, { 0x95, 0xe4, 0x13, 0x46, 0xfc, 0x3a, 0x7a, 0x30,
                  0xdf, 0xc2, 0x30, 0x75, 0x43, 0x81, 0x18, 0xd4 } },
        {  752, { 0x4a, 0x84, 0x9a, 0x57, 0xcc, 0x19, 0xa8, 0x88,
                  0xca, 0xe7, 0xe7, 0x54, 0xec, 0x37, 0x78, 0x37 } },
        {  768, { 0x60, 0x26, 0xe1, 0x2d, 0xdb, 0x68, 0xfc, 0x0e,
                  0xfc, 0x67, 0xe3, 0xd0, 0x50, 0x03, 0xbb, 0xdf } },
        { 1008, { 0x7b, 0x0e, 0xe0, 0x56, 0x48, 0x29, 0x4b, 0x33,
                  0x6a, 0x87, 0x80, 0x58, 0x19, 0x0b, 0xa2, 0xaf } },
        { 1024, { 0xa8, 0xed, 0x41, 0xee, 0x14, 0x0a, 0x18, 0xbe,
                  0x33, 0x96, 0x95, 0xeb, 0x7b, 0x05, 0x5c, 0x67 } },
        { 1520, { 0x40, 0xdf, 0xe6, 0xfa, 0x69, 0xb7, 0x0b, 0xf2,
                  0x9f, 0xb9, 0x01, 0xee, 0x39, 0x54, 0x44, 0x7f } },
        { 1536, { 0x40, 0x47, 0xf0, 0x59, 0xa6, 0xed, 0xdf, 0x1d,
                  0x5c, 0x8b, 0x55, 0xaf, 0x8f, 0xe4, 0x2c, 0x7f } },
        { 2032, { 0xb8, 0x65, 0x09, 0x79, 0xa3, 0x35, 0x33, 0x7d,
                  0x9f, 0xe6, 0x2a, 0x79, 0xaf, 0x75, 0x22, 0x1d } },
        { 2048, { 0x4d, 0xa6, 0xab, 0x1f, 0x48, 0x66, 0x8f, 0x69,
                  0xa4, 0x05, 0xd9, 0xb3, 0x3b, 0x30, 0xaf, 0x52 } },
        { 3056, { 0xc1, 0x38, 0x44, 0xfb, 0xb0, 0xe5, 0x00, 0xdc,
                  0xcd, 0xe2, 0x90, 0xfa, 0xbe, 0x6e, 0x4a, 0xb8 } },
        { 3072, { 0xe6, 0xbe, 0x49, 0xa9, 0xd3, 0x3f, 0x20, 0x90,
                  0x3e, 0x62, 0xfa, 0xca, 0x27, 0xa2, 0xdf, 0xce } },
        { 4080, { 0x95, 0x56, 0xde, 0x31, 0x28, 0xb3, 0x19, 0x09,
                  0x52, 0x0f, 0xaa, 0x22, 0x9f, 0xce, 0x3f, 0xbb } },
        { 4096, { 0x73, 0xa7, 0xfd, 0xa9, 0xaa, 0x71, 0x31, 0x40,
                  0xfc, 0xc6, 0xc3, 0xa7, 0x01, 0x7e, 0xe4, 0x38 } },
    }
};

static void
aes_selftest_ks(void)
{
    int i, j;
    uint8_t ksbuf[16];
    aes_context ctx;
    bool failed = false;

    for (i = 0; i < 2; i++)
    {
        aes128_init(&ctx, aes_test_keystream_keys[i]);

        for (j = 0; j < 18; j++)
        {
            aes_gen_keystream(&ctx,
                              aes_test_keystreams[i][j].offset,
                              ksbuf, 16);

            if (memcmp(ksbuf, aes_test_keystreams[i][j].sample, 16))
            {
                fprintf(stderr, "FAIL: aes128 keystream %d/%d (offset %d):\n",
                        i+1, j+1, aes_test_keystreams[i][j].offset);
                dump_hex("  exp: ", aes_test_keystreams[i][j].sample, 16);
                dump_hex("  got: ", ksbuf, 16);
                putc('\n', stderr);
                failed = true;
            }
        }
    }
    if (failed)
        abort();
}

static void
aes_selftest(void)
{
    aes_selftest_vk(aes128_init, aes_vk_128, 128);
    aes_selftest_vk(aes192_init, aes_vk_192, 192);
    aes_selftest_vk(aes256_init, aes_vk_256, 256);

    aes_selftest_vt(aes128_init, aes_vt_128, 128);
    aes_selftest_vt(aes192_init, aes_vt_192, 192);
    aes_selftest_vt(aes256_init, aes_vt_256, 256);

    aes_selftest_ks();
}

DEFINE_CIPHER(aes128, aes, 16);
DEFINE_CIPHER(aes192, aes, 24);
DEFINE_CIPHER(aes256, aes, 32);

/*
 * Local Variables:
 * indent-tabs-mode: nil
 * c-basic-offset: 4
 * c-file-offsets: ((substatement-open . 0))
 * End:
 */
