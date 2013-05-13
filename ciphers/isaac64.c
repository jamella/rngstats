/*
------------------------------------------------------------------------------
isaac64.c: My random number generator for 64-bit machines.
By Bob Jenkins, 1996.  Public Domain.
------------------------------------------------------------------------------
*/

#include "config.h"
#include "ciphers.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(uint64_t) == 8, "size sanity check");

#define RANDSIZL   (8)
#define RANDSIZ    (1<<RANDSIZL)
#define RANDSIZB   (RANDSIZ * sizeof(uint64_t))

typedef struct
{
    uint64_t offset, aa, bb, cc;
    uint64_t mm[RANDSIZ];
    uint64_t randrsl[RANDSIZ];
}
isaac64_context;

#define ind(mm,x)  (*(uint64_t *)((uint8_t *)(mm) + ((x) & ((RANDSIZ-1)<<3))))

#define rngstep(mix,a,b,mm,m,m2,r,x) do {       \
        x = *m;                                 \
        a = (mix) + *(m2++);                    \
        *(m++) = y = ind(mm,x) + a + b;         \
        *(r++) = b = ind(mm,y>>RANDSIZL) + x;   \
    } while (0)

#define mix(a,b,c,d,e,f,g,h) do {               \
        a-=e; f^=h>>9;  h+=a;                   \
        b-=f; g^=a<<9;  a+=b;                   \
        c-=g; h^=b>>23; b+=c;                   \
        d-=h; a^=c<<15; c+=d;                   \
        e-=a; b^=d>>14; d+=e;                   \
        f-=b; c^=e<<20; e+=f;                   \
        g-=c; d^=f>>17; f+=g;                   \
        h-=d; e^=g<<14; g+=h;                   \
    } while (0)

#define cpu_to_be64(p, v) do {                  \
        (p)[7] = (uint8_t)((v)      );          \
        (p)[6] = (uint8_t)((v) >>  8);          \
        (p)[5] = (uint8_t)((v) >> 16);          \
        (p)[4] = (uint8_t)((v) >> 24);          \
        (p)[3] = (uint8_t)((v) >> 32);          \
        (p)[2] = (uint8_t)((v) >> 40);          \
        (p)[1] = (uint8_t)((v) >> 48);          \
        (p)[0] = (uint8_t)((v) >> 56);          \
    } while (0)

/* The ISAAC64 core function emits RANDSIZ 64-bit words of randomness
   all at once.  They are saved in the context, and isaac64_gen_keystream
   pulls them out one at a time.  */
static void
isaac64_core(isaac64_context *ctx)
{
    uint64_t a,b,x,y,*m,*m2,*mm,*r,*mend;
    mm = ctx->mm;
    r  = ctx->randrsl;
    a  = ctx->aa;
    b  = ctx->bb + (++ctx->cc);
    for (m = ctx->mm, mend = m2 = m+(RANDSIZ/2); m<mend; )
    {
        rngstep(~(a^(a<<21)), a, b, mm, m, m2, r, x);
        rngstep(  a^(a>>5)  , a, b, mm, m, m2, r, x);
        rngstep(  a^(a<<12) , a, b, mm, m, m2, r, x);
        rngstep(  a^(a>>33) , a, b, mm, m, m2, r, x);
    }
    for (m2 = ctx->mm; m2<mend; )
    {
        rngstep(~(a^(a<<21)), a, b, mm, m, m2, r, x);
        rngstep(  a^(a>>5)  , a, b, mm, m, m2, r, x);
        rngstep(  a^(a<<12) , a, b, mm, m, m2, r, x);
        rngstep(  a^(a>>33) , a, b, mm, m, m2, r, x);
    }
    ctx->bb = b;
    ctx->aa = a;
}

static void
isaac64_init(void *ctx_, const uint8_t *key)
{
    isaac64_context *ctx = ctx_;
    uint8_t *p;
    int i;
    uint64_t a,b,c,d,e,f,g,h;
    uint64_t seed[RANDSIZ];
    uint64_t *mm = ctx->mm;

    /* There is no official keying algorithm.  Since AES is giving us
       128-bit keys, we just repeat them over the entire seed buffer. */
    for (p = (uint8_t *)seed; p < ((uint8_t *)&seed[RANDSIZ]); p += 16)
        memcpy(p, key, 16);

    a=b=c=d=e=f=g=h=0x9e3779b97f4a7c13LL;  /* the golden ratio */
    for (i = 0; i < 4; i++)
        mix(a,b,c,d,e,f,g,h);

    for (i = 0; i < RANDSIZ; i += 8)   /* fill in mm[] with messy stuff */
    {
        a+=seed[i  ]; b+=seed[i+1]; c+=seed[i+2]; d+=seed[i+3];
        e+=seed[i+4]; f+=seed[i+5]; g+=seed[i+6]; h+=seed[i+7];
        mix(a,b,c,d,e,f,g,h);
        mm[i  ]=a; mm[i+1]=b; mm[i+2]=c; mm[i+3]=d;
        mm[i+4]=e; mm[i+5]=f; mm[i+6]=g; mm[i+7]=h;
    }

    /* do a second pass to make all of the seed affect all of mm */
    for (i=0; i<RANDSIZ; i+=8)
    {
        a+=mm[i  ]; b+=mm[i+1]; c+=mm[i+2]; d+=mm[i+3];
        e+=mm[i+4]; f+=mm[i+5]; g+=mm[i+6]; h+=mm[i+7];
        mix(a,b,c,d,e,f,g,h);
        mm[i  ]=a; mm[i+1]=b; mm[i+2]=c; mm[i+3]=d;
        mm[i+4]=e; mm[i+5]=f; mm[i+6]=g; mm[i+7]=h;
    }

    ctx->aa = 0;
    ctx->bb = 0;
    ctx->cc = 0;
    ctx->offset = 0;

    /* gen_keystream expects isaac64_core to have been called once
       already */
    isaac64_core(ctx);
}

static void
isaac64_gen_keystream(void *ctx_, size_t offset, uint8_t *obuf, size_t olen)
{
    isaac64_context *ctx = ctx_;
    size_t offset_RANDSIZ, offset_64b, offset_rem;
    uint8_t buf[8];
    uint8_t *limit = obuf + olen;

    if (offset < ctx->offset)
        abort();

    offset_RANDSIZ = offset / RANDSIZB;
    while (ctx->offset < offset_RANDSIZ)
    {
        isaac64_core(ctx);
        ctx->offset += RANDSIZB;
    }

    offset_64b = (offset % RANDSIZB) / 8;
    offset_rem = (offset % RANDSIZB) % 8;
    for (;;)
    {
        for (; offset_64b < RANDSIZ; offset_64b++)
        {
            cpu_to_be64(buf, ctx->randrsl[offset_64b]);
            for (; offset_rem < 8; offset_rem++)
            {
                *obuf++ = buf[offset_rem];
                if (obuf >= limit)
                    goto out;
            }
            offset_rem = 0;
        }
        offset_64b = 0;
        isaac64_core(ctx);
    }
 out:
    ctx->offset = offset + olen;
    /* since the isaac64_core() call is at the bottom of the outer loop,
       if we get here exactly at a page boundary, we need to call it once
       more to maintain the invariant that randrsl[] is full on entry */
    if (ctx->offset % RANDSIZB == 0)
        isaac64_core(ctx);
}

#define R(a,b,c,d) RR(a), RR(b), RR(c), RR(d)
#define RR(x) RRR(0x##x##ul)
#define RRR(x) \
    ((x >> 56) & 0xFFul), \
    ((x >> 48) & 0xFFul), \
    ((x >> 40) & 0xFFul), \
    ((x >> 32) & 0xFFul), \
    ((x >> 24) & 0xFFul), \
    ((x >> 16) & 0xFFul), \
    ((x >>  8) & 0xFFul), \
    ((x >>  0) & 0xFFul)

static const uint8_t
isaac64_test_key[16] = { 0, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, 0, 0, 0 };
static const uint8_t
isaac64_test_keystream[] = {
    R(12a8f216af9418c2, d4490ad526f14431, b49c3b3995091a36, 5b45e522e4b1b4ef),
    R(a1e9300cd8520548, 49787fef17af9924, 03219a39ee587a30, ebe9ea2adf4321c7),
    R(804456af10f5fb53, d74bbe77e6116ac7, 7c0828dd624ec390, 14a195640116f336),
    R(2eab8ca63ce802d7, c6e57a78fbd986e0, 58efc10b06a2068d, abeeddb2dde06ff1),
    R(0b090a7560a968e3, 2cf9c8ca052f6e9f, 116d0016cb948f09, a59e0bd101731a28),
    R(63767572ae3d6174, ab4f6451cc1d45ec, c2a1e7b5b459aeb5, 2472f6207c2d0484),
    R(e699ed85b0dfb40d, d4347f66ec8941c3, f4d14597e660f855, 8b889d624d44885d),
    R(258e5a80c7204c4b, af0c317d32adaa8a, 9c4cd6257c5a3603, eb3593803173e0ce),
    R(36f60e2ba4fa6800, 38b6525c21a42b0e, f4f5d05c10cab243, cf3f4688801eb9aa),
    R(1ddc0325259b27de, b9571fa04dc089c8, d7504dfa8816edbb, 1fe2cca76517db90),
    R(261e4e4c0a333a9d, 219b97e26ffc81bd, 66b4835d9eafea22, 4cc317fb9cddd023),
    R(50b704cab602c329, edb454e7badc0805, 9e17e49642a3e4c1, 66c1a2a1a60cd889),
    R(7983eed3740847d5, 298af231c85bafab, 2680b122baa28d97, 734de8181f6ec39a),
    R(53898e4c3910da55, 1761f93a44d5aefe, e4dbf0634473f5d2, 4ed0fe7e9dc91335),
    R(d18d8549d140caea, 1cfc8bed0d681639, ca1e3785a9e724e5, b67c1fa481680af8),
    R(dfea21ea9e7557e3, d6b6d0ecc617c699, fa7e393983325753, a09e8c8c35ab96de),
    R(8fe88b57305e2ab6, 89039d79d6fc5c5c, 9bfb227ebdf4c5ce, 7f7cc39420a3a545),
    R(3f6c6af859d80055, c8763c5b08d1908c, 469356c504ec9f9d, 26e6db8ffdf5adfe),
    R(3a938fee32d29981, 2c5e9deb57ef4743, 1e99b96e70a9be8b, 764dbeae7fa4f3a6),
    R(aac40a2703d9bea0, 1a8c1e992b941148, 73aa8a564fb7ac9e, 604d51b25fbf70e2),
    R(dd69a0d8ab3b546d, 65ca5b96b7552210, 2fd7e4b9e72cd38c, 51d2b1ab2ddfb636),
    R(9d1d84fcce371425, a44cfe79ae538bbe, de68a2355b93cae6, 9fc10d0f989993e0),
    R(94ebc8abcfb56dae, d7a023a73260b45c, 72c8834a5957b511, 8f8419a348f296bf),
    R(1e152328f3318dea, 4838d65f6ef6748f, d6bf7baee43cac40, 13328503df48229f),
    R(7440fb816508c4fe, 9d266d6a1cc0542c, 4dda48153c94938a, 74c04bf1790c0efe),
    R(e1925c71285279f5, 8a8e849eb32781a5, 073973751f12dd5e, a319ce15b0b4db31),
    R(6dd856d94d259236, 67378d8eccef96cb, 9fc477de4ed681da, f3b8b6675a6507ff),
    R(c3a9dc228caac9e9, c37b45b3f8d6f2ba, b559eb1d04e5e932, 1b0cab936e65c744),
    R(af08da9177dda93d, ac12fb171817eee7, 1fff7ac80904bf45, a9119b60369ffebd),
    R(bfced1b0048eac50, b67b7896167b4c84, 9b3cdb65f82ca382, dbc27ab5447822bf),
    R(10dcd78e3851a492, b438c2b67f98e5e9, 43954b3252dc25e5, ab9090168dd05f34),
    R(ce68341f79893389, 36833336d068f707, dcdd7d20903d0c25, da3a361b1c5157b1),
    R(7f9d1a2e1ebe1327, 5d0a12f27ad310d1, 3bc36e078f7515d7, 4da8979a0041e8a9),
    R(950113646d1d6e03, 7b4a38e32537df62, 8a1b083821f40cb4, 3d5774a11d31ab39),
    R(7a76956c3eafb413, 7f5126dbba5e0ca7, 12153635b2c0cf57, 7b3f0195fc6f290f),
    R(5544f7d774b14aef, 56c074a581ea17fe, e7f28ecd2d49eecd, e479ee5b9930578c),
    R(9ff38fed72e9052f, 9f65789a6509a440, 0981dcd296a8736d, 5873888850659ae7),
    R(c678b6d860284a1c, 63e22c147b9c3403, 92fae24291f2b3f1, 829626e3892d95d7),
    R(cffe1939438e9b24, 79999cdff70902cb, 8547eddfb81ccb94, 7b77497b32503b12),
    R(97fcaacbf030bc24, 6ced1983376fa72b, 7e75d99d94a70f4d, d2733c4335c6a72f),
    R(dbc0d2b6ab90a559, 94628d38d0c20584, 64972d68dee33360, b9c11d5b1e43a07e),
    R(2de0966daf2f8b1c, 2e18bc1ad9704a68, d4dba84729af48ad, b7a0b174cff6f36e),
    R(e94c39a54a98307f, aa70b5b4f89695a2, 3bdbb92c43b17f26, cccb7005c6b9c28d),
    R(18a6a990c8b35ebd, fc7c95d827357afa, 1fca8a92fd719f85, 1dd01aafcd53486a),
    R(49353fea39ba63b1, f85b2b4fbcde44b7, be7444e39328a0ac, 3e2b8bcbf016d66d),
    R(964e915cd5e2b207, 1725cabfcb045b00, 7fbf21ec8a1f45ec, 11317ba87905e790),
    R(2fe4b17170e59750, e8d9ecbe2cf3d73f, b57d2e985e1419c7, 0572b974f03ce0bb),
    R(a8d7e4dab780a08d, 4715ed43e8a45c0a, c330de426430f69d, 23b70edb1955c4bf),
    R(098954d51fff6580, 8107fccf064fcf56, 852f54934da55cc9, 09c7e552bc76492f),
    R(e9f6760e32cd8021, a3bc941d0a5061cb, ba89142e007503b8, dc842b7e2819e230),
    R(bbe83f4ecc2bdecb, cd454f8f19c5126a, c62c58f97dd949bf, 693501d628297551),
    R(b9ab4ce57f2d34f3, 9255abb50d532280, ebfafa33d7254b59, e9f6082b05542e4e),
    R(35dd37d5871448af, b03031a8b4516e84, b3f256d8aca0b0b9, 0fd22063edc29fca),
    R(d9a11fbb3d9808e4, 3a9bf55ba91f81ca, c8c93882f9475f5f, 947ae053ee56e63c),
    R(c7d9f16864a76e94, 7bd94e1d8e17debc, d873db391292ed4f, 30f5611484119414),
    R(565c31f7de89ea27, d0e4366228b03343, 325928ee6e6f8794, 6f423357e7c6a9f9),
    R(99170a5dc3115544, 59b97885e2f2ea28, bc4097b116c524d2, 7a13f18bbedc4ff5),
    R(071582401c38434d, b422061193d6f6a7, b4b81b3fa97511e2, 65d34954daf3cebd),
    R(b344c470397bba52, bac7a9a18531294b, ecb53939887e8175, 565601c0364e3228),
    R(ef1955914b609f93, 16f50edf91e513af, 56963b0dca418fc0, d60f6dcedc314222),
    R(364f6ffa464ee52e, 6c3b8e3e336139d3, f943aee7febf21b8, 088e049589c432e0),
    R(d49503536abca345, 3a6c27934e31188a, 957baf61700cff4e, 37624ae5a48fa6e9),
    R(501f65edb3034d07, 907f30421d78c5de, 1a804aadb9cfa741, 0ce2a38c344a6eed),
    R(d363eff5f0977996, 2cd16e2abd791e33, 58627e1a149bba21, 7f9b6af1ebf78baf),
    R(d20d8c88c8ffe65f, 917f1dd5f8886c61, 56986e2ef3ed091b, 5fa7867caf35e149),
    R(81a1549fd6573da5, 96fbf83a12884624, e728e8c83c334074, f1bcc3d275afe51a),
    R(71f1ce2490d20b07, e6c42178c4bbb92e, 0a9c32d5eae45305, 0c335248857fa9e7),
    R(142de49fff7a7c3d, 64a53dc924fe7ac9, 9f6a419d382595f4, 150f361dab9dec26),
    R(c61bb3a141e50e8c, 2785338347f2ba08, 7ca9723fbb2e8988, ce2f8642ca0712dc),
    R(59300222b4561e00, c2b5a03f71471a6f, d5f9e858292504d5, 65fa4f227a2b6d79),
    R(93cbe0b699c2585d, 1d95b0a5fcf90bc6, 17efee45b0dee640, 9e4c1269baa4bf37),
    R(d79476a84ee20d06, 0a56a5f0bfe39272, 7eba726d8c94094b, 5e5637885f29bc2b),
    R(d586bd01c5c217f6, 233003b5a6cfe6ad, 24c0e332b70019b0, 9da058c67844f20c),
    R(e4d9429322cd065a, 1fab64ea29a2ddf7, 8af38731c02ba980, 7dc7785b8efdfc80),
    R(486289ddcc3d6780, 222bbfae61725606, 2bc60a63a6f3b3f2, 177e00f9fc32f791),
    R(522e23f3925e319e, 9c2ed44081ce5fbd, 964781ce734b3c84, f05d129681949a4c),
    R(046e3ecaaf453ce9, 962aceefa82e1c84, f5b4b0b0d2deeeb4, 1af3dbe25d8f45da),
    R(f9f4892ed96bd438, c4c118bfe78feaae, 07a69afdcc42261a, f8549e1a3aa5e00d),
    R(2102ae466ebb1148, e87fbb46217a360e, 310cb380db6f7503, b5fdfc5d3132c498),
    R(daf8e9829fe96b5f, cac09afbddd2cdb4, b862225b055b6960, 55b6344cf97aafae),
    R(ff577222c14f0a3a, 4e4b705b92903ba4, 730499af921549ff, 13ae978d09fe5557),
    R(d9e92aa246bf719e, 7a4c10ec2158c4a6, 49cad48cebf4a71e, cf05daf5ac8d77b0),
    R(abbdcdd7ed5c0860, 9853eab63b5e0b35, 352787baa0d7c22f, c7f6aa2de59aea61),
    R(03727073c2e134b1, 5a0f544dd2b1fb18, 74f85198b05a2e7d, 963ef2c96b33be31),
    R(4659d2b743848a2c, 19ebb029435dcb0f, 4e9d2827355fc492, ccec0a73b49c9921),
    R(46c9feb55d120902, 8d2636b81555a786, 30c05b1ba332f41c, f6f7fd1431714200),
    R(1a4ff12616eefc89, 990a98fd5071d263, 84547ddc3e203c94, 07a3aec79624c7da),
    R(8a328a1cedfe552c, d1e649de1e7f268b, 2d8d5432157064c8, 4ae7d6a36eb5dbcb),
    R(57e3306d881edb4f, 0a804d18b7097475, e74733427b72f0c1, 24b33c9d7ed25117),
    R(e805a1e290cf2456, 3b544ebe544c19f9, 3e666e6f69ae2c15, fb152fe3ff26da89),
    R(b49b52e587a1ee60, ac042e70f8b383f2, 89c350c893ae7dc1, b592bf39b0364963),
    R(190e714fada5156e, ec8177f83f900978, 91b534f885818a06, 81536d601170fc20),
    R(d4c718bc4ae8ae5f, 9eedeca8e272b933, 10e8b35af3eeab37, 0e09b88e1914f7af),
    R(3fa9ddfb67e2f199, b10bb459132d0a26, 2c046f22062dc67d, 5e90277e7cb39e2d),
    R(d6b04d3b7651dd7e, e34a1d250e7a8d6b, 53c065c6c8e63528, 1bdea12e35f6a8c9),
    R(21874b8b4d2dbc4f, 3a88a0fbbcb05c63, 43ed7f5a0fae657d, 230e343dfba08d33),
    R(b5b4071dbfc73a66, 8f9887e6078735a1, 08de8a1c7797da9b, fcb6be43a9f2fe9b),
    R(049a7f41061a9e60, 9f91508bffcfc14a, e3273522064480ca, cd04f3ff001a4778),
    R(6bfa9aae5ec05779, 371f77e76bb8417e, 3550c2321fd6109c, fb4a3d794a9a80d2),
    R(f43c732873f24c13, aa9119ff184cccf4, b69e38a8965c6b65, 1f2b1d1f15f6dc9c),
    R(67fef95d92607890, 31865ced6120f37d, 3a6853c7e70757a7, 32ab0edb696703d3),
    R(ee97f453f06791ed, 6dc93d9526a50e68, 78edefd694af1eed, 9c1169fa2777b874),
    R(50065e535a213cf6, de0c89a556b9ae70, d1e0ccd25bb9c169, 6b17b224bad6bf27),
    R(6b02e63195ad0cf8, 455a4b4cfe30e3f5, 9338e69c052b8e7b, 5092ef950a16da0b),
    R(7c45d833aff07862, a5b1cfdba0ab4067, 6ad047c430a12104, 6c47bec883a7de39),
    R(944f6de09134dfb6, 9aeba33ac6ecc6b0, 52e762596bf68235, 22af003ab672e811),
    R(b5635c95ff7296e2, ed2df21216235097, 4a29c6465a314cd1, d83cc2687a19255f),
    R(506c11b9d90e8b1d, 57277707199b8175, caf21ecd4377b28c, c0c0f5a60ef4cdcf),
    R(93b633abfa3469f8, e846963877671a17, 59ac2c7873f910a3, 660d3257380841ee),
    R(d813f2fab7f5c5ca, 4112cf68649a260e, 443f64ec5a371195, b0774d261cc609db),
    R(720bf5f26f4d2eaa, 1c2559e30f0946be, e328e230e3e2b3fb, 087e79e5a57d1d13),
    R(08dd9bdfd96b9f63, 64d0e29eea8838b3, ddf957bc36d8b9ca, 6ffe73e81b637fb3),
    R(1a4e4822eb4d7a59, 5d94337fbfaf7f5b, d30c088ba61ea5ef, 9d765e419fb69f6d),
    R(9e21f4f903b33fd9, b4d8f77bc3e56167, 733ea705fae4fa77, a4ec0132764ca04b),
    R(7976033a39f7d952, 106f72fe81e2c590, 8c90fd9b083f4558, fd080d236da814ba),
    R(7b64978555326f9f, 60e8ed72c0dff5d1, b063e962e045f54d, 959f587d507a8359),
    R(758f450c88572e0b, 1b6baca2ae4e125b, 61cf4f94c97df93d, 2738259634305c14),
    R(d39bb9c3a48db6cf, 8215e577001332c8, a1082c0466df6c0a, ef02cdd06ffdb432),
    R(fc87614baf287e07, 240ab57a8b888b20, bf8d5108e27e0d48, 61bdd1307c66e300),
    R(b925a6cd0421aff3, 3e003e616a6591e9, 94c3251f06f90cf3, bf84470805e69b5f),
    R(98f076a4f7a2322e, 70cb6af7c2d5bcf0, b64be8d8b25396c1, a9aa4d20db084e9b),
    R(2e6d02c36017f67f, efed53d75fd64e6b, d9f1f30ccd97fb09, a2ebee47e2fbfce1),
    R(b8d91274b9e9d4fb, 1db956e450275779, 4fc8e9560f91b123, 63573ff03e224774),
    R(0647dfedcd894a29, 7884d9bc6cb569d8, 7fba195410e5ca30, 106c09b972d2e822),
    R(241260ed4ad1e87d, 64c8e531bff53b55, ca672b91e9e4fa16, 3871700761b3f743),
    R(f95cffa23af5f6f4, 8d14dedb30be846e, 3b097adaf088f94e, 21e0bd5026c619bf),
    R(1bda0492e7e4586e, d23c8e176d113600, 252f59cf0d9f04bb, b3598080ce64a656),
    R(993e1de72d36d310, a2853b80f17f58ee, 1877b51e57a764d5, 001f837cc7350524),
};

static void
isaac64_selftest(void)
{
    isaac64_context ctx;
    uint8_t stream[sizeof isaac64_test_keystream];
    size_t n;
    bool failed = false;

    isaac64_init(&ctx, isaac64_test_key);
    isaac64_gen_keystream(&ctx, RANDSIZB, stream,
                          sizeof isaac64_test_keystream);
    for (n = 0; n < sizeof isaac64_test_keystream; n++)
        if (isaac64_test_keystream[n] != stream[n])
        {
            fprintf(stderr,
                    "FAIL: isaac64: offset %zu exp %02x got %02x\n",
                    n, isaac64_test_keystream[n], stream[n]);
            failed = true;
        }

    if (failed)
        abort();
}

DEFINE_CIPHER(isaac64, isaac64, 16);

/*
 * Local Variables:
 * indent-tabs-mode: nil
 * c-basic-offset: 4
 * c-file-offsets: ((substatement-open . 0))
 * End:
 */
