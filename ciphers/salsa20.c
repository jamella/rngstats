/*
 * Based on salsa20-regs.c version 20051118 by D. J. Bernstein.
 * Public domain.
 * Note that the IV is wired to all bits zero.
 */

#include "config.h"
#include "ciphers.h"

#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define U8TO32_LITTLE(p)                        \
    (((uint32_t) (p)[0]       ) |               \
     ((uint32_t) (p)[1] <<  8 ) |               \
     ((uint32_t) (p)[2] << 16 ) |               \
     ((uint32_t) (p)[3] << 24 ))

#define U32TO8_LITTLE(p, v)                     \
    do {                                        \
        (p)[0] = (uint8_t) ((v)      );         \
        (p)[1] = (uint8_t) ((v) >>  8);         \
        (p)[2] = (uint8_t) ((v) >> 16);         \
        (p)[3] = (uint8_t) ((v) >> 24);         \
    } while (0)

#define U32V(v) ((uint32_t)(v))
#define ROTL32(v, n)                            \
  (U32V((v) << (n)) | ((v) >> (32 - (n))))

#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

typedef struct
{
    uint32_t input[16];
    size_t offset;
}
salsa20_context;

static void
salsa20_128_init(void *ctx_, const uint8_t *k)
{
    static const char constants[] = "expand 16-byte k";
    salsa20_context *ctx = ctx_;

    ctx->input[ 1] = U8TO32_LITTLE(k + 0);
    ctx->input[ 2] = U8TO32_LITTLE(k + 4);
    ctx->input[ 3] = U8TO32_LITTLE(k + 8);
    ctx->input[ 4] = U8TO32_LITTLE(k + 12);
    ctx->input[11] = U8TO32_LITTLE(k + 0);
    ctx->input[12] = U8TO32_LITTLE(k + 4);
    ctx->input[13] = U8TO32_LITTLE(k + 8);
    ctx->input[14] = U8TO32_LITTLE(k + 12);
    ctx->input[ 0] = U8TO32_LITTLE(constants + 0);
    ctx->input[ 5] = U8TO32_LITTLE(constants + 4);
    ctx->input[10] = U8TO32_LITTLE(constants + 8);
    ctx->input[15] = U8TO32_LITTLE(constants + 12);
    ctx->input[ 6] = 0;
    ctx->input[ 7] = 0;
    ctx->input[ 8] = 0;
    ctx->input[ 9] = 0;
}

static void
salsa20_256_init(void *ctx_, const uint8_t *k)
{
    static const char constants[] = "expand 32-byte k";
    salsa20_context *ctx = ctx_;

    ctx->input[ 1] = U8TO32_LITTLE(k + 0);
    ctx->input[ 2] = U8TO32_LITTLE(k + 4);
    ctx->input[ 3] = U8TO32_LITTLE(k + 8);
    ctx->input[ 4] = U8TO32_LITTLE(k + 12);
    ctx->input[11] = U8TO32_LITTLE(k + 16);
    ctx->input[12] = U8TO32_LITTLE(k + 20);
    ctx->input[13] = U8TO32_LITTLE(k + 24);
    ctx->input[14] = U8TO32_LITTLE(k + 28);
    ctx->input[ 0] = U8TO32_LITTLE(constants + 0);
    ctx->input[ 5] = U8TO32_LITTLE(constants + 4);
    ctx->input[10] = U8TO32_LITTLE(constants + 8);
    ctx->input[15] = U8TO32_LITTLE(constants + 12);
    ctx->input[ 6] = 0;
    ctx->input[ 7] = 0;
    ctx->input[ 8] = 0;
    ctx->input[ 9] = 0;
}

/* This is the Salsa20 "core function".  Despite Salsa20 being
   described by its author as a stream cipher, this function is maybe
   best thought of as a 512-bit block cipher, which gen_keystream()
   will use in counter mode.  -zw */
static void
salsa20_wordtobyte(uint8_t output[64], const uint32_t input[16])
{
    uint32_t x0, x1,  x2,  x3,  x4,  x5,  x6,  x7;
    uint32_t x8, x9, x10, x11, x12, x13, x14, x15;
    int i;

     x0 = input[ 0];
     x1 = input[ 1];
     x2 = input[ 2];
     x3 = input[ 3];
     x4 = input[ 4];
     x5 = input[ 5];
     x6 = input[ 6];
     x7 = input[ 7];
     x8 = input[ 8];
     x9 = input[ 9];
    x10 = input[10];
    x11 = input[11];
    x12 = input[12];
    x13 = input[13];
    x14 = input[14];
    x15 = input[15];
    for (i = 20; i > 0; i -= 2)
    {
         x4 = XOR( x4,ROTATE(PLUS( x0,x12), 7));
         x8 = XOR( x8,ROTATE(PLUS( x4, x0), 9));
        x12 = XOR(x12,ROTATE(PLUS( x8, x4),13));
         x0 = XOR( x0,ROTATE(PLUS(x12, x8),18));
         x9 = XOR( x9,ROTATE(PLUS( x5, x1), 7));
        x13 = XOR(x13,ROTATE(PLUS( x9, x5), 9));
         x1 = XOR( x1,ROTATE(PLUS(x13, x9),13));
         x5 = XOR( x5,ROTATE(PLUS( x1,x13),18));
        x14 = XOR(x14,ROTATE(PLUS(x10, x6), 7));
         x2 = XOR( x2,ROTATE(PLUS(x14,x10), 9));
         x6 = XOR( x6,ROTATE(PLUS( x2,x14),13));
        x10 = XOR(x10,ROTATE(PLUS( x6, x2),18));
         x3 = XOR( x3,ROTATE(PLUS(x15,x11), 7));
         x7 = XOR( x7,ROTATE(PLUS( x3,x15), 9));
        x11 = XOR(x11,ROTATE(PLUS( x7, x3),13));
        x15 = XOR(x15,ROTATE(PLUS(x11, x7),18));
         x1 = XOR( x1,ROTATE(PLUS( x0, x3), 7));
         x2 = XOR( x2,ROTATE(PLUS( x1, x0), 9));
         x3 = XOR( x3,ROTATE(PLUS( x2, x1),13));
         x0 = XOR( x0,ROTATE(PLUS( x3, x2),18));
         x6 = XOR( x6,ROTATE(PLUS( x5, x4), 7));
         x7 = XOR( x7,ROTATE(PLUS( x6, x5), 9));
         x4 = XOR( x4,ROTATE(PLUS( x7, x6),13));
         x5 = XOR( x5,ROTATE(PLUS( x4, x7),18));
        x11 = XOR(x11,ROTATE(PLUS(x10, x9), 7));
         x8 = XOR( x8,ROTATE(PLUS(x11,x10), 9));
         x9 = XOR( x9,ROTATE(PLUS( x8,x11),13));
        x10 = XOR(x10,ROTATE(PLUS( x9, x8),18));
        x12 = XOR(x12,ROTATE(PLUS(x15,x14), 7));
        x13 = XOR(x13,ROTATE(PLUS(x12,x15), 9));
        x14 = XOR(x14,ROTATE(PLUS(x13,x12),13));
        x15 = XOR(x15,ROTATE(PLUS(x14,x13),18));
    }
     x0 = PLUS(x0,input[0]);
     x1 = PLUS(x1,input[1]);
     x2 = PLUS(x2,input[2]);
     x3 = PLUS(x3,input[3]);
     x4 = PLUS(x4,input[4]);
     x5 = PLUS(x5,input[5]);
     x6 = PLUS(x6,input[6]);
     x7 = PLUS(x7,input[7]);
     x8 = PLUS(x8,input[8]);
     x9 = PLUS(x9,input[9]);
    x10 = PLUS(x10,input[10]);
    x11 = PLUS(x11,input[11]);
    x12 = PLUS(x12,input[12]);
    x13 = PLUS(x13,input[13]);
    x14 = PLUS(x14,input[14]);
    x15 = PLUS(x15,input[15]);
    U32TO8_LITTLE(output + 0,x0);
    U32TO8_LITTLE(output + 4,x1);
    U32TO8_LITTLE(output + 8,x2);
    U32TO8_LITTLE(output + 12,x3);
    U32TO8_LITTLE(output + 16,x4);
    U32TO8_LITTLE(output + 20,x5);
    U32TO8_LITTLE(output + 24,x6);
    U32TO8_LITTLE(output + 28,x7);
    U32TO8_LITTLE(output + 32,x8);
    U32TO8_LITTLE(output + 36,x9);
    U32TO8_LITTLE(output + 40,x10);
    U32TO8_LITTLE(output + 44,x11);
    U32TO8_LITTLE(output + 48,x12);
    U32TO8_LITTLE(output + 52,x13);
    U32TO8_LITTLE(output + 56,x14);
    U32TO8_LITTLE(output + 60,x15);
}

static void
salsa20_gen_keystream(void *ctx_, size_t offset,
                      uint8_t *obuf, size_t olen)
{
    salsa20_context *ctx = ctx_;
    uint8_t block[64];
    uint8_t *limit = obuf + olen;
    size_t offset_512b, offset_rem, i;

    if (olen == 0)
        return;

    /* Initialize input[8] and [9] to a 64-bit little-endian count of
       the number of 64-byte (512-bit) cipher blocks already consumed
       at OFFSET. */
    offset_512b = offset / 64;
    offset_rem  = offset % 64;
#if SIZE_MAX > 0xFFFFFFFF
    ctx->input[9] = (uint32_t) ((offset_512b >> 32) & 0xFFFFFFFFu);
#endif
    ctx->input[8] = (uint32_t) ((offset_512b      ) & 0xFFFFFFFFu);

    i = offset_rem;
    for (;;)
    {
        salsa20_wordtobyte(block, ctx->input);
        for (; i < 64; i++)
        {
            *obuf++ = block[i];
            if (obuf >= limit)
                return;
        }

        i = 0;
        ctx->input[8]++;
        if (!ctx->input[8])
            ctx->input[9]++;
    }
}

/* Salsa20 test vectors from http://www.ecrypt.eu.org/stream/svn/viewcvs.cgi/ecrypt/trunk/submissions/salsa20/full/verified.test-vectors?logsort=rev&rev=210&view=markup */

#define B16_(a,b,c,d, e,f,g,h, i,j,k,l, m,n,o,p)              \
    0x##a, 0x##b, 0x##c, 0x##d, 0x##e, 0x##f, 0x##g, 0x##h,   \
    0x##i, 0x##j, 0x##k, 0x##l, 0x##m, 0x##n, 0x##o, 0x##p

#define B16(one) { B16_ one, B16_(0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0) }
#define B32(one, two) { B16_ one, B16_ two }
#define B64(one, two, three, four) { B16_ one, B16_ two, B16_ three, B16_ four }

/* This array is [4][32], even though we only use the first 16 bytes
   of each slot, so it is type-compatible with salsa20_test_one_size,
   below.  We take the first four vectors in "set 2". */
static const uint8_t
salsa20_128_test_keys[4][32] = {
    B16((00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00)),
    B16((09,09,09,09,09,09,09,09,09,09,09,09,09,09,09,09)),
    B16((12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12)),
    B16((1B,1B,1B,1B,1B,1B,1B,1B,1B,1B,1B,1B,1B,1B,1B,1B)),
};

/* again, the first four in set 2 */
static const uint8_t
salsa20_256_test_keys[4][32] = {
    B32((00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00),
        (00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00)),
    B32((09,09,09,09,09,09,09,09,09,09,09,09,09,09,09,09),
        (09,09,09,09,09,09,09,09,09,09,09,09,09,09,09,09)),
    B32((12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12),
        (12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12)),
    B32((1B,1B,1B,1B,1B,1B,1B,1B,1B,1B,1B,1B,1B,1B,1B,1B),
        (1B,1B,1B,1B,1B,1B,1B,1B,1B,1B,1B,1B,1B,1B,1B,1B)),
};

struct keystream_expectation
{
    unsigned int offset;
    uint8_t sample[64];
};

static const struct keystream_expectation
salsa20_128_test_keystreams[4][4] = {
    {
        {   0, B64((65,13,AD,AE,CF,EB,12,4C,1C,BE,6B,DA,EF,69,0B,4F),
                   (FB,00,B0,FC,AC,E3,3C,E8,06,79,2B,B4,14,80,19,98),
                   (34,BF,B1,CF,DD,09,58,02,C6,E9,5E,25,10,02,98,9A),
                   (C2,2A,E5,88,D3,2A,E7,93,20,D9,BD,77,32,E0,03,38)) },
        { 192, B64((75,E9,D0,49,3C,A0,5D,28,20,40,87,19,AF,C7,51,20),
                   (69,20,40,11,8F,76,B8,32,8A,C2,79,53,0D,84,66,70),
                   (65,E7,35,C5,2A,DD,4B,CF,E0,7C,9D,93,C0,09,17,90),
                   (2B,18,7D,46,A2,59,24,76,7F,91,A6,B2,9C,96,18,59)) },
        { 256, B64((0E,47,D6,8F,84,5B,3D,31,E8,B4,7F,3B,EA,66,0E,2E),
                   (CA,48,4C,82,F5,E3,AE,00,48,4D,87,41,0A,17,72,D0),
                   (FA,3B,88,F8,02,4C,17,0B,21,E5,0E,09,89,E9,4A,26),
                   (69,C9,19,73,B3,AE,57,81,D3,05,D8,12,27,91,DA,4C)) },
        { 448, B64((CC,BA,51,D3,DB,40,0E,7E,B7,80,C0,CC,BD,3D,2B,5B),
                   (B9,AA,D8,2A,75,A1,F7,46,82,4E,E5,B9,DA,F7,B7,94),
                   (7A,4B,80,8D,F4,8C,E9,48,30,F6,C9,14,68,60,61,1D),
                   (A6,49,E7,35,ED,5E,D6,E3,E3,DF,F7,C2,18,87,9D,63)) },
    },
    {
        {   0, B64((16,90,60,CC,B4,2B,EA,7B,EE,4D,80,12,A0,2F,36,35),
                   (EB,7B,CA,12,85,9F,A1,59,CD,55,90,94,B3,50,7D,B8),
                   (01,73,5D,1A,13,00,10,2A,9C,94,15,54,68,29,CB,D2),
                   (02,1B,A2,17,B3,9B,81,D8,9C,55,B1,3D,0C,60,33,59)) },
        { 192, B64((23,EF,24,BB,24,19,5B,9F,D5,74,82,3C,D8,A4,0C,29),
                   (D8,6B,D3,5C,19,1E,20,38,77,9F,F6,96,C7,12,B6,D8),
                   (2E,70,14,DB,E1,AC,5D,52,7A,F0,76,C0,88,C4,A8,D4),
                   (43,17,95,81,89,F6,EF,54,93,3A,7E,08,16,B5,B9,16)) },
        { 256, B64((D8,F1,2E,D8,AF,E9,42,2B,85,E5,CC,9B,8A,DE,C9,D6),
                   (CF,AB,E8,DB,C1,08,2B,CC,C0,2F,5A,72,66,AA,07,4C),
                   (A2,84,E5,83,A3,58,37,79,8C,C0,E6,9D,4C,E9,37,65),
                   (3B,8C,DD,65,CE,41,4B,89,13,86,15,CC,B1,65,AD,19)) },
        { 448, B64((F7,0A,0F,F4,EC,D1,55,E0,F0,33,60,46,93,A5,1E,23),
                   (63,88,0E,2E,CF,98,69,9E,71,74,AF,7C,2C,6B,0F,C6),
                   (59,AE,32,95,99,A3,94,92,72,A3,7B,9B,21,83,A0,91),
                   (09,22,A3,F3,25,AE,12,4D,CB,DD,73,53,64,05,5C,EB)) },
    },
    {
        {   0, B64((05,83,57,54,A1,33,37,70,BB,A8,26,2F,8A,84,D0,FD),
                   (70,AB,F5,8C,DB,83,A5,41,72,B0,C0,7B,6C,CA,56,41),
                   (06,0E,30,97,D2,B1,9F,82,E9,18,CB,69,7D,0F,34,7D),
                   (C7,DA,E0,5C,14,35,5D,09,B6,1B,47,29,8F,E8,9A,EB)) },
        { 192, B64((55,25,C2,2F,42,59,49,A5,E5,1A,4E,AF,A1,8F,62,C6),
                   (E0,1A,27,EF,78,D7,9B,07,3A,EB,EC,43,6E,C8,18,3B),
                   (C6,83,CD,32,05,CF,80,B7,95,18,1D,AF,F3,DC,98,48),
                   (66,44,C6,31,0F,09,D8,65,A7,A7,5E,E6,D5,10,5F,92)) },
        { 256, B64((2E,E7,A4,F9,C5,76,EA,DE,7E,E3,25,33,42,12,19,6C),
                   (B7,A6,1D,6F,A6,93,23,8E,6E,2C,8B,53,B9,00,FF,1A),
                   (13,3A,6E,53,F5,8A,C8,9D,6A,69,55,94,CE,03,F7,75),
                   (8D,F9,AB,E9,81,F2,33,73,B3,68,0C,7A,4A,D8,26,80)) },
        { 448, B64((CB,7A,05,95,F3,A1,B7,55,E9,07,0E,8D,3B,AC,CF,95),
                   (74,F8,81,E4,B9,D9,15,58,E1,93,17,C4,C2,54,98,8F),
                   (42,18,45,84,E5,53,8C,63,D9,64,F8,EF,61,D8,6B,09),
                   (D9,83,99,89,79,BA,3F,44,BA,F5,27,12,8D,3E,53,93)) },
    },
    {
        {   0, B64((72,A8,D2,6F,2D,F3,B6,71,3C,2A,05,3B,33,54,DB,A6),
                   (C1,07,43,C7,A8,F1,92,61,CF,0E,79,57,90,57,48,DD),
                   (D6,D3,33,3E,2C,BC,66,11,B6,8C,45,8D,5C,DB,A2,A2),
                   (30,AC,5A,B0,3D,59,E7,1F,E9,C9,93,E7,B8,E7,E0,9F)) },
        { 192, B64((7B,61,32,DC,5E,29,90,B0,04,9A,5F,7F,35,7C,9D,99),
                   (77,33,94,80,18,AE,1D,4F,9D,B9,99,F4,60,5F,D7,8C),
                   (B5,48,D7,5A,C4,65,7D,93,A2,0A,A4,51,B8,F3,5E,0A),
                   (3C,D0,88,80,CC,ED,7D,4A,50,8B,A7,FB,49,73,7C,17)) },
        { 256, B64((EF,7A,74,48,D0,19,C7,6E,D0,B9,C1,8B,5B,28,67,CF),
                   (9A,D8,4B,78,9F,B0,37,E6,B1,07,B0,A4,61,57,37,B5),
                   (C1,C1,13,F9,14,62,CD,A0,BC,B9,AD,DC,09,E8,EA,6B),
                   (99,E4,83,5F,ED,25,F5,CC,42,3E,EF,F5,6D,85,18,38)) },
        { 448, B64((6B,75,BD,D0,EC,8D,58,1C,B7,56,74,26,F0,B9,2C,9B),
                   (B5,05,7A,89,C3,F6,04,58,3D,B7,00,A4,6D,6B,8D,E4),
                   (1A,F3,15,AE,99,BB,5C,1B,52,C7,62,72,D1,E2,62,F9),
                   (FC,70,22,CE,70,B4,35,C2,7A,E4,43,28,4F,5F,84,C1)) },
    }
};

static const struct keystream_expectation
salsa20_256_test_keystreams[4][4] = {
    {
        {   0, B64((9A,97,F6,5B,9B,4C,72,1B,96,0A,67,21,45,FC,A8,D4),
                   (E3,2E,67,F9,11,1E,A9,79,CE,9C,48,26,80,6A,EE,E6),
                   (3D,E9,C0,DA,2B,D7,F9,1E,BC,B2,63,9B,F9,89,C6,25),
                   (1B,29,BF,38,D3,9A,9B,DC,E7,C5,5F,4B,2A,C1,2A,39)) },
        { 192, B64((2F,3C,3E,10,64,91,60,B4,43,21,B7,F8,30,D7,D2,22),
                   (69,9F,AE,0E,83,4C,76,C3,99,79,85,B5,40,48,08,AB),
                   (7E,6E,99,AA,1F,EC,27,30,74,92,13,E7,F3,7A,29,1A),
                   (A6,B5,AF,D2,E5,24,C2,D6,08,F3,4D,49,59,93,04,36)) },
        { 256, B64((85,98,D1,FA,94,51,6B,47,4B,69,DA,83,E3,C1,31,2C),
                   (49,A0,5B,82,83,B8,80,B3,18,72,CD,1E,A7,D8,F1,B2),
                   (D6,0A,86,CB,A8,18,4F,94,9E,A7,AE,85,02,A5,82,DB),
                   (39,2E,85,C4,D7,0D,3D,17,B2,E5,7D,81,7A,98,ED,6E)) },
        { 448, B64((F8,6C,74,89,71,2F,B7,78,96,70,6F,C8,92,D9,A1,C8),
                   (4B,B5,3D,08,1F,6E,B4,AE,1C,68,B1,19,0C,BB,0B,41),
                   (48,4E,9E,2B,6F,EA,0A,31,BF,12,44,15,92,1E,5C,F3),
                   (7C,26,49,3A,5B,C0,8F,76,20,A8,C8,05,03,C4,C7,6F)) },
    },
    {
        {   0, B64((70,41,E7,47,CE,B2,2E,D7,81,29,85,46,5F,50,33,31),
                   (24,F9,71,DA,1C,5D,6E,FE,5C,A2,01,B8,86,F3,10,46),
                   (E7,57,E5,C3,EC,91,4F,60,ED,1F,6B,CE,28,19,B6,81),
                   (09,53,F1,2B,8B,A1,19,9B,F8,2D,74,6A,8B,8A,88,F1)) },
        { 192, B64((4E,E9,0A,FB,71,3A,E7,E0,12,95,C7,43,81,18,0A,38),
                   (16,D7,02,0D,5A,39,6C,0D,97,AA,A7,83,EA,AB,B6,EC),
                   (44,D5,11,11,57,F2,21,2D,1B,1B,8F,CA,78,93,E8,B5),
                   (20,CD,48,24,18,C2,72,AB,11,9B,56,9A,2B,95,98,EB)) },
        { 256, B64((35,56,24,D1,2E,79,AD,AB,81,15,3B,58,CD,22,EA,F1),
                   (B2,A3,23,95,DE,DC,4A,1C,66,F4,D2,74,07,0B,98,00),
                   (EA,95,76,6F,02,45,A8,29,5F,8A,AD,B3,6D,DB,BD,FA),
                   (93,64,17,C8,DB,C6,23,5D,19,49,40,36,96,4D,3E,70)) },
        { 448, B64((5C,F3,8C,12,32,02,3E,6A,6E,F6,6C,31,5B,CB,2A,43),
                   (28,64,2F,AA,BB,7C,A1,E8,89,E0,39,E7,C4,44,B3,4B),
                   (B3,44,3F,59,6A,C7,30,F3,DF,3D,FC,DB,34,3C,30,7C),
                   (80,F7,6E,43,E8,89,8C,5E,8F,43,DC,3B,B2,80,AD,D0)) },
    },
    {
        {   0, B64((7B,CD,4C,55,28,F4,BE,AE,0F,C9,F1,64,CE,BE,C7,3E),
                   (D8,9C,E3,2D,A4,6E,B6,8C,A3,CE,DA,A7,C7,A5,80,FB),
                   (1C,50,D2,91,F3,1C,38,DB,28,11,86,4F,66,54,09,8E),
                   (14,1A,22,13,82,85,93,A9,8B,7D,00,20,BF,0D,6D,93)) },
        { 192, B64((87,DC,AB,67,C8,D5,A9,0D,17,AF,19,8D,3A,22,D4,32),
                   (BC,82,C0,68,72,F0,E6,1B,3A,3D,1A,1F,C1,45,27,D1),
                   (E8,C3,C9,CA,50,E5,BF,52,96,21,C2,86,0E,D3,04,F2),
                   (7E,6E,42,7A,9B,C6,4D,0F,C6,E2,E1,6B,D4,0C,43,4C)) },
        { 256, B64((12,1F,38,D3,1A,0E,D8,A6,D7,2F,4C,6A,46,78,A7,B0),
                   (D3,05,4A,62,68,D0,2C,9C,67,66,06,94,27,72,26,06),
                   (36,CD,6D,79,F8,1C,64,41,2A,93,F1,0D,B6,8D,1B,86),
                   (96,2D,FC,41,43,4B,1C,65,AF,47,70,F7,D1,85,51,4A)) },
        { 448, B64((BE,DD,FB,9B,60,B2,04,E0,33,27,26,D7,D7,E9,06,40),
                   (FF,29,31,8A,16,4A,95,51,D9,FA,47,7D,7E,43,72,73),
                   (A0,E0,8E,C3,50,46,CA,E1,0B,DA,EB,95,9F,44,E9,C2),
                   (A0,9F,FF,BA,A7,A8,9B,7B,9F,1A,F3,49,48,FF,FE,9D)) },
    },
    {
        {   0, B64((94,4B,67,EA,B6,2D,F3,75,60,85,CE,E5,77,D0,C1,DA),
                   (4D,D7,CD,17,B8,5F,9B,9C,51,00,41,07,C8,AA,69,35),
                   (7E,41,3A,EA,37,BB,51,2B,D8,24,6F,2D,03,E2,74,8D),
                   (3B,B2,4B,60,C1,FB,E4,D1,A5,52,37,FF,E3,D4,D6,04)) },
        { 192, B64((A9,57,4A,D5,FC,6A,0D,4A,57,FB,E9,8A,B5,12,2A,54),
                   (E2,C3,55,52,4A,AC,38,58,0C,65,9A,E4,E9,06,F1,4C),
                   (3F,B5,A0,96,58,6F,A8,08,F5,F2,66,18,2D,26,C7,84),
                   (72,B1,16,65,2E,E1,87,4C,B5,CF,00,7D,F2,E2,BB,5A)) },
        { 256, B64((EE,5A,30,6A,60,C8,3E,20,9A,CC,5F,3D,60,E1,7D,90),
                   (FD,DC,0D,79,0B,BB,7B,1E,EB,63,59,24,A4,C7,AE,BF),
                   (3A,DE,18,F1,F2,F0,3C,1E,74,09,38,47,B8,F9,22,5A),
                   (95,88,E9,2A,82,64,44,BD,D1,43,B3,8C,C3,93,4F,BD)) },
        { 448, B64((33,DD,C5,26,B9,1B,D4,52,29,6D,C8,AB,AE,E7,C6,5A),
                   (E7,D8,CA,37,FE,66,16,6B,67,57,07,26,63,98,41,C8),
                   (55,94,05,23,6A,37,A1,04,FA,A3,F5,A1,A1,93,2D,57),
                   (FF,E3,6E,C1,6D,43,9B,1C,29,1D,D1,16,38,C5,07,30)) },
    }
};

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
salsa20_test_one_size(void (*init)(void *, const uint8_t *),
                      const uint8_t keys[4][32],
                      const struct keystream_expectation samples[4][4])
{
    int i, j;
    uint8_t ksbuf[64];
    salsa20_context ctx;
    bool failed = false;

    for (i = 0; i < 4; i++)
    {
        init(&ctx, keys[i]);

        for (j = 0; j < 4; j++)
        {
            salsa20_gen_keystream(&ctx, samples[i][j].offset, ksbuf, 64);
            if (memcmp(ksbuf, samples[i][j].sample, 16))
            {
                fprintf(stderr, "FAIL: salsa20 keystream %d/%d (offset %d):\n",
                        i+1, j+1, samples[i][j].offset);
                dump_hex("  exp: ", samples[i][j].sample, 16);
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
salsa20_selftest(void)
{
    salsa20_test_one_size(salsa20_128_init,
                          salsa20_128_test_keys,
                          salsa20_128_test_keystreams);
    salsa20_test_one_size(salsa20_256_init,
                          salsa20_256_test_keys,
                          salsa20_256_test_keystreams);
}

DEFINE_CIPHER(salsa20_128, salsa20, 16);
DEFINE_CIPHER(salsa20_256, salsa20, 32);

/*
 * Local Variables:
 * indent-tabs-mode: nil
 * c-basic-offset: 4
 * c-file-offsets: ((substatement-open . 0))
 * End:
 */
