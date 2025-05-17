/*
 * Copyright (C) 2001-2017 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include "utilities.h"

#include <endian.h>
#include <stdio.h>
#include <string.h>

void MD5_Transform(uint32 *buf, uint32 const *in);

#define IS_BIG_ENDIAN() (__BYTE_ORDER == __BIG_ENDIAN)
#define IS_LITTLE_ENDIAN() (__BYTE_ORDER == __LITTLE_ENDIAN)

static void byteReverse(unsigned char *buf, unsigned longs);

/*
 * Note: this code is harmless on little-endian machines.
 */
static void byteReverse(unsigned char *buf, unsigned longs)
{
        uint32 t;
        do {
                t = (uint32) ((unsigned) buf[3] << 8 | buf[2]) << 16 |
                    ((unsigned) buf[1] << 8 | buf[0]);
                *(uint32 *) buf = t;
                buf += 4;
        } while (--longs);
}

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
void MD5_Init(struct MD5Context *ctx)
{
        ctx->buf[0] = 0x67452301U;
        ctx->buf[1] = 0xefcdab89U;
        ctx->buf[2] = 0x98badcfeU;
        ctx->buf[3] = 0x10325476U;

        ctx->bits[0] = 0;
        ctx->bits[1] = 0;


        if (IS_BIG_ENDIAN())
             ctx->doByteReverse = 1;
        else
             ctx->doByteReverse = 0;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
void MD5_Update(struct MD5Context *ctx, unsigned const char *buf, unsigned len)
{
        uint32 t;

        /* Update bitcount */

        t = ctx->bits[0];
        if ((ctx->bits[0] = t + ((uint32) len << 3)) < t)
                ctx->bits[1]++; /* Carry from low to high */
        ctx->bits[1] += len >> 29;

        t = (t >> 3) & 0x3f;    /* Bytes already in shsInfo->data */

        /* Handle any leading odd-sized chunks */

        if (t) {
                unsigned char *p = (unsigned char *) ctx->in + t;

                t = 64 - t;
                if (len < t) {
                        memcpy(p, buf, len);
                        return;
                }
                memcpy(p, buf, t);
                if (ctx->doByteReverse) byteReverse(ctx->in, 16);
                // puts("MD5_Update: odd-sized chunks MD5_Transform");
                MD5_Transform(ctx->buf, (uint32 *) ctx->in);
                buf += t;
                len -= t;
        }
        /* Process data in 64-byte chunks */

        while (len >= 64) {
                memcpy(ctx->in, buf, 64);
                if (ctx->doByteReverse) byteReverse(ctx->in, 16);
                MD5_Transform(ctx->buf, (uint32 *) ctx->in);
                buf += 64;
                len -= 64;
        }

        /* Handle any remaining bytes of data. */

        memcpy(ctx->in, buf, len);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
void MD5_Final(unsigned char digest[16], struct MD5Context *ctx)
{
        unsigned count;
        unsigned char *p;
        unsigned char data_807c8e0[64] = { 0 };
        memset(data_807c8e0, 0, sizeof (data_807c8e0));
        *data_807c8e0 = 0x80;


        /* Compute number of bytes mod 64 */
        count = (ctx->bits[0] >> 3) & 0x3F;


        /* Set the first char of padding to 0x80.  This is safe since there is
           always at least one byte free */
        p = ctx->in + count;
        *p++ = 0x80;

        /* Bytes of padding needed to make 64 bytes */
        count = 64 - 1 - count;


        /* Pad out to 56 mod 64 */
        if (count < 8) {
                /* Two lots of padding:  Pad the first block to 64 bytes */
                memset(p, 0, count);
                if (ctx->doByteReverse) byteReverse(ctx->in, 16);
                MD5_Transform(ctx->buf, (uint32 *) ctx->in);

                /* Now fill the next block with 56 bytes */
                memset(ctx->in, 0, 56);
        } else {
                /* Pad block to 56 bytes */
                memset(p, 0, count - 8);
        }
        if (ctx->doByteReverse) byteReverse(ctx->in, 14);

        /* Append length in bits and transform */
        memcpy(ctx->in+56, ctx->bits, sizeof(ctx->bits));
        MD5_Transform(ctx->buf, (uint32 *) ctx->in);
        if (ctx->doByteReverse) byteReverse((unsigned char *) ctx->buf, 4);
        memcpy(digest, ctx->buf, 16);
        // memset(ctx, 0, sizeof(*ctx));    /* In case it's sensitive */
}

void MD5_Transform(unsigned int *param_1, uint32 const *param_2)
{
    int iVar1;
    int iVar2;
    int iVar3;
    int iVar4;
    int iVar5;
    int iVar6;
    int iVar7;
    int iVar8;
    int iVar9;
    int iVar10;
    int iVar11;
    int iVar12;
    int iVar13;
    int iVar14;
    int iVar15;
    int iVar16;
    unsigned int uVar17;
    unsigned int uVar18;
    unsigned int uVar19;
    unsigned int uVar20;
    unsigned int uVar21;
    unsigned int uVar22;

    iVar1 = *param_2;
    uVar19 = param_1[1];
    uVar21 = param_1[2];
    uVar17 = *param_1 + -0x28955b88 + iVar1 + ((~uVar19 & param_1[3]) | (uVar21 & uVar19));
    iVar2 = param_2[1];
    uVar17 = (uVar17 >> 0x19 | uVar17 * 0x80) + uVar19;
    uVar18 = ((~uVar17 & uVar21) | (uVar17 & uVar19)) + param_1[3] + 0xe8c7b756U + iVar2;
    iVar3 = param_2[2];
    uVar18 = (uVar18 >> 0x14 | uVar18 * 0x1000) + uVar17;
    iVar4 = param_2[3];
    uVar21 = ((~uVar18 & uVar19) | (uVar18 & uVar17)) + uVar21 + 0x242070db + iVar3;
    uVar22 = (uVar21 >> 0xf | uVar21 * 0x20000) + uVar18;
    iVar5 = param_2[4];
    uVar19 = ((~uVar22 & uVar17) | (uVar22 & uVar18)) + uVar19 + 0xc1bdceee + iVar4;
    uVar20 = (uVar19 >> 10 | uVar19 * 0x400000) + uVar22;
    iVar6 = param_2[5];
    uVar19 = ((~uVar20 & uVar18) | (uVar20 & uVar22)) + uVar17 + 0xf57c0faf + iVar5;
    uVar19 = (uVar19 >> 0x19 | uVar19 * 0x80) + uVar20;
    iVar7 = param_2[6];
    uVar21 = ((~uVar19 & uVar22) | (uVar19 & uVar20)) + uVar18 + 0x4787c62a + iVar6;
    uVar21 = (uVar21 >> 0x14 | uVar21 * 0x1000) + uVar19;
    iVar8 = param_2[7];
    uVar17 = ((~uVar21 & uVar20) | (uVar21 & uVar19)) + uVar22 + 0xa8304613 + iVar7;
    uVar22 = (uVar17 >> 0xf | uVar17 * 0x20000) + uVar21;
    iVar9 = param_2[8];
    uVar17 = ((~uVar22 & uVar19) | (uVar22 & uVar21)) + uVar20 + 0xfd469501 + iVar8;
    uVar18 = (uVar17 >> 10 | uVar17 * 0x400000) + uVar22;
    iVar10 = param_2[9];
    uVar19 = ((~uVar18 & uVar21) | (uVar18 & uVar22)) + uVar19 + 0x698098d8 + iVar9;
    uVar19 = (uVar19 >> 0x19 | uVar19 * 0x80) + uVar18;
    iVar11 = param_2[10];
    uVar21 = ((~uVar19 & uVar22) | (uVar19 & uVar18)) + uVar21 + 0x8b44f7af + iVar10;
    uVar17 = (uVar21 >> 0x14 | uVar21 * 0x1000) + uVar19;
    iVar12 = param_2[0xb];
    uVar21 = ((~uVar17 & uVar18) | (uVar17 & uVar19)) + (uVar22 - 0xa44f) + iVar11;
    uVar20 = (uVar21 >> 0xf | uVar21 * 0x20000) + uVar17;
    iVar13 = param_2[0xc];
    uVar21 = ((~uVar20 & uVar19) | (uVar20 & uVar17)) + uVar18 + 0x895cd7be + iVar12;
    uVar18 = (uVar21 >> 10 | uVar21 * 0x400000) + uVar20;
    iVar14 = param_2[0xd];
    uVar19 = ((~uVar18 & uVar17) | (uVar18 & uVar20)) + uVar19 + 0x6b901122 + iVar13;
    uVar21 = (uVar19 >> 0x19 | uVar19 * 0x80) + uVar18;
    uVar19 = ((~uVar21 & uVar20) | (uVar21 & uVar18)) + uVar17 + 0xfd987193 + iVar14;
    uVar17 = (uVar19 >> 0x14 | uVar19 * 0x1000) + uVar21;
    iVar15 = param_2[0xe];
    iVar16 = param_2[0xf];
    uVar19 = ((~uVar17 & uVar18) | (uVar17 & uVar21)) + uVar20 + 0xa679438e + iVar15;
    uVar20 = (uVar19 >> 0xf | uVar19 * 0x20000) + uVar17;
    uVar19 = ((~uVar20 & uVar21) | (uVar20 & uVar17)) + uVar18 + 0x49b40821 + iVar16;
    uVar19 = (uVar19 >> 10 | uVar19 * 0x400000) + uVar20;
    uVar21 = ((uVar19 & uVar17) | (~uVar17 & uVar20)) + uVar21 + 0xf61e2562 + iVar2;
    uVar21 = (uVar21 >> 0x1b | uVar21 * 0x20) + uVar19;
    uVar17 = uVar17 + 0xc040b340 + iVar7 + ((uVar21 & uVar20) | (~uVar20 & uVar19));
    uVar18 = (uVar17 >> 0x17 | uVar17 * 0x200) + uVar21;
    uVar17 = ((uVar18 & uVar19) | (~uVar19 & uVar21)) + uVar20 + 0x265e5a51 + iVar12;
    uVar17 = (uVar17 >> 0x12 | uVar17 * 0x4000) + uVar18;
    uVar19 = ((uVar17 & uVar21) | (~uVar21 & uVar18)) + uVar19 + 0xe9b6c7aa + iVar1;
    uVar19 = (uVar19 >> 0xc | uVar19 * 0x100000) + uVar17;
    uVar21 = uVar21 + 0xd62f105d + iVar6 + ((uVar19 & uVar18) | (~uVar18 & uVar17));
    uVar20 = (uVar21 >> 0x1b | uVar21 * 0x20) + uVar19;
    uVar21 = ((uVar20 & uVar17) | (~uVar17 & uVar19)) + uVar18 + 0x2441453 + iVar11;
    uVar21 = (uVar21 >> 0x17 | uVar21 * 0x200) + uVar20;
    uVar17 = ((uVar21 & uVar19) | (~uVar19 & uVar20)) + uVar17 + 0xd8a1e681 + iVar16;
    uVar17 = (uVar17 >> 0x12 | uVar17 * 0x4000) + uVar21;
    uVar19 = uVar19 + 0xe7d3fbc8 + iVar5 + ((uVar17 & uVar20) | (~uVar20 & uVar21));
    uVar18 = (uVar19 >> 0xc | uVar19 * 0x100000) + uVar17;
    uVar19 = ((uVar18 & uVar21) | (~uVar21 & uVar17)) + uVar20 + 0x21e1cde6 + iVar10;
    uVar19 = (uVar19 >> 0x1b | uVar19 * 0x20) + uVar18;
    uVar21 = ((uVar19 & uVar17) | (~uVar17 & uVar18)) + uVar21 + 0xc33707d6 + iVar15;
    uVar21 = (uVar21 >> 0x17 | uVar21 * 0x200) + uVar19;
    uVar17 = uVar17 + 0xf4d50d87 + iVar4 + ((uVar21 & uVar18) | (~uVar18 & uVar19));
    uVar20 = (uVar17 >> 0x12 | uVar17 * 0x4000) + uVar21;
    uVar17 = ((uVar20 & uVar19) | (~uVar19 & uVar21)) + uVar18 + 0x455a14ed + iVar9;
    uVar17 = (uVar17 >> 0xc | uVar17 * 0x100000) + uVar20;
    uVar19 = ((uVar17 & uVar21) | (~uVar21 & uVar20)) + uVar19 + 0xa9e3e905 + iVar14;
    uVar19 = (uVar19 >> 0x1b | uVar19 * 0x20) + uVar17;
    uVar21 = uVar21 + 0xfcefa3f8 + iVar3 + ((uVar19 & uVar20) | (~uVar20 & uVar17));
    uVar18 = (uVar21 >> 0x17 | uVar21 * 0x200) + uVar19;
    uVar21 = ((uVar18 & uVar17) | (~uVar17 & uVar19)) + uVar20 + 0x676f02d9 + iVar8;
    uVar21 = (uVar21 >> 0x12 | uVar21 * 0x4000) + uVar18;
    uVar17 = ((uVar21 & uVar19) | (~uVar19 & uVar18)) + uVar17 + 0x8d2a4c8a + iVar13;
    uVar17 = (uVar17 >> 0xc | uVar17 * 0x100000) + uVar21;
    uVar19 = (uVar21 ^ uVar18 ^ uVar17) + (uVar19 - 0x5c6be) + iVar6;
    uVar19 = (uVar19 >> 0x1c | uVar19 * 0x10) + uVar17;
    uVar18 = (uVar17 ^ uVar21 ^ uVar19) + uVar18 + 0x8771f681 + iVar9;
    uVar18 = (uVar18 >> 0x15 | uVar18 * 0x800) + uVar19;
    uVar21 = (uVar19 ^ uVar17 ^ uVar18) + uVar21 + 0x6d9d6122 + iVar12;
    uVar21 = (uVar21 >> 0x10 | uVar21 * 0x10000) + uVar18;
    uVar17 = (uVar18 ^ uVar19 ^ uVar21) + uVar17 + 0xfde5380c + iVar15;
    uVar17 = (uVar17 >> 9 | uVar17 * 0x800000) + uVar21;
    uVar19 = (uVar21 ^ uVar18 ^ uVar17) + uVar19 + 0xa4beea44 + iVar2;
    uVar19 = (uVar19 >> 0x1c | uVar19 * 0x10) + uVar17;
    uVar18 = (uVar17 ^ uVar21 ^ uVar19) + uVar18 + 0x4bdecfa9 + iVar5;
    uVar18 = (uVar18 >> 0x15 | uVar18 * 0x800) + uVar19;
    uVar21 = (uVar19 ^ uVar17 ^ uVar18) + uVar21 + 0xf6bb4b60 + iVar8;
    uVar21 = (uVar21 >> 0x10 | uVar21 * 0x10000) + uVar18;
    uVar17 = (uVar18 ^ uVar19 ^ uVar21) + uVar17 + 0xbebfbc70 + iVar11;
    uVar17 = (uVar17 >> 9 | uVar17 * 0x800000) + uVar21;
    uVar19 = uVar19 + 0x289b7ec6 + iVar14 + (uVar21 ^ uVar18 ^ uVar17);
    uVar20 = (uVar19 >> 0x1c | uVar19 * 0x10) + uVar17;
    uVar19 = uVar18 + 0xeaa127fa + iVar1 + (uVar17 ^ uVar21 ^ uVar20);
    uVar18 = (uVar19 >> 0x15 | uVar19 * 0x800) + uVar20;
    uVar19 = (uVar20 ^ uVar17 ^ uVar18) + uVar21 + 0xd4ef3085 + iVar4;
    uVar19 = (uVar19 >> 0x10 | uVar19 * 0x10000) + uVar18;
    uVar21 = uVar17 + 0x4881d05 + iVar7 + (uVar18 ^ uVar20 ^ uVar19);
    uVar21 = (uVar21 >> 9 | uVar21 * 0x800000) + uVar19;
    uVar17 = uVar20 + 0xd9d4d039 + iVar10 + (uVar19 ^ uVar18 ^ uVar21);
    uVar20 = (uVar17 >> 0x1c | uVar17 * 0x10) + uVar21;
    uVar17 = (uVar21 ^ uVar19 ^ uVar20) + uVar18 + 0xe6db99e5 + iVar13;
    uVar17 = (uVar17 >> 0x15 | uVar17 * 0x800) + uVar20;
    uVar19 = uVar19 + 0x1fa27cf8 + iVar16 + (uVar20 ^ uVar21 ^ uVar17);
    uVar18 = (uVar19 >> 0x10 | uVar19 * 0x10000) + uVar17;
    uVar19 = uVar21 + 0xc4ac5665 + iVar3 + (uVar17 ^ uVar20 ^ uVar18);
    uVar21 = (uVar19 >> 9 | uVar19 * 0x800000) + uVar18;
    uVar19 = ((~uVar17 | uVar21) ^ uVar18) + uVar20 + 0xf4292244 + iVar1;
    uVar19 = (uVar19 >> 0x1a | uVar19 * 0x40) + uVar21;
    uVar17 = ((~uVar18 | uVar19) ^ uVar21) + uVar17 + 0x432aff97 + iVar8;
    uVar17 = (uVar17 >> 0x16 | uVar17 * 0x400) + uVar19;
    uVar18 = ((~uVar21 | uVar17) ^ uVar19) + uVar18 + 0xab9423a7 + iVar15;
    uVar18 = (uVar18 >> 0x11 | uVar18 * 0x8000) + uVar17;
    uVar21 = uVar21 + 0xfc93a039 + iVar6 + ((~uVar19 | uVar18) ^ uVar17);
    uVar20 = (uVar21 >> 0xb | uVar21 * 0x200000) + uVar18;
    uVar19 = uVar19 + 0x655b59c3 + iVar13 + ((~uVar17 | uVar20) ^ uVar18);
    uVar21 = (uVar19 >> 0x1a | uVar19 * 0x40) + uVar20;
    uVar19 = uVar17 + 0x8f0ccc92 + iVar4 + ((~uVar18 | uVar21) ^ uVar20);
    uVar17 = (uVar19 >> 0x16 | uVar19 * 0x400) + uVar21;
    uVar19 = (uVar18 - 0x100b83) + iVar11 + ((~uVar20 | uVar17) ^ uVar21);
    uVar18 = (uVar19 >> 0x11 | uVar19 * 0x8000) + uVar17;
    uVar19 = ((~uVar21 | uVar18) ^ uVar17) + uVar20 + 0x85845dd1 + iVar2;
    uVar19 = (uVar19 >> 0xb | uVar19 * 0x200000) + uVar18;
    uVar21 = ((~uVar17 | uVar19) ^ uVar18) + uVar21 + 0x6fa87e4f + iVar9;
    uVar21 = (uVar21 >> 0x1a | uVar21 * 0x40) + uVar19;
    uVar17 = ((~uVar18 | uVar21) ^ uVar19) + uVar17 + 0xfe2ce6e0 + iVar16;
    uVar17 = (uVar17 >> 0x16 | uVar17 * 0x400) + uVar21;
    uVar18 = ((~uVar19 | uVar17) ^ uVar21) + uVar18 + 0xa3014314 + iVar7;
    uVar18 = (uVar18 >> 0x11 | uVar18 * 0x8000) + uVar17;
    uVar19 = ((~uVar21 | uVar18) ^ uVar17) + uVar19 + 0x4e0811a1 + iVar14;
    uVar19 = (uVar19 >> 0xb | uVar19 * 0x200000) + uVar18;
    uVar21 = ((~uVar17 | uVar19) ^ uVar18) + uVar21 + 0xf7537e82 + iVar5;
    uVar21 = (uVar21 >> 0x1a | uVar21 * 0x40) + uVar19;
    uVar17 = uVar17 + 0xbd3af235 + iVar12 + ((~uVar18 | uVar21) ^ uVar19);
    uVar20 = (uVar17 >> 0x16 | uVar17 * 0x400) + uVar21;
    uVar17 = ((~uVar19 | uVar20) ^ uVar21) + uVar18 + 0x2ad7d2bb + iVar3;
    uVar17 = (uVar17 >> 0x11 | uVar17 * 0x8000) + uVar20;
    uVar19 = ((~uVar21 | uVar17) ^ uVar20) + uVar19 + 0xeb86d391 + iVar10;
    *param_1 = uVar21 + *param_1;
    param_1[2] = param_1[2] + uVar17;
    param_1[3] = param_1[3] + uVar20;
    param_1[1] = (uVar19 >> 0xb | uVar19 * 0x200000) + uVar17 + param_1[1];
}

void md5sum(char *const hashsum, MD5_CTX *const hashctx) {
    unsigned char digest[HASH_SIZE / 2];
    MD5_Final(digest, hashctx);
    *hashsum = '\0';
    for (size_t i = 0; i < HASH_SIZE / 2; i++) {
        char tmp[3];
        snprintf(tmp, 3, "%02x", digest[i]);
        strncat(hashsum, tmp, 2);
    }
}

void usage(void)
{
    fprintf(stderr, "dprkeygen MACHINE_ID\n");
    fprintf(stderr, "MACHINE_ID: 16 uppercase characters starting with RSS3\n");
    exit(1);
}

int main(int argc, char *argv[])
{
    if (argc != 2 || strlen(argv[1]) != 16 || strncmp("RSS3", argv[1], 4) != 0)
        usage();

    unsigned char license[17] = { 0 };
    unsigned license_len = 16;
    char digest[16] = { 0 };
    unsigned i = 0;
    unsigned j = 0;

    memcpy(license, argv[1], 16);
    license[16] = '\0';


    MD5_CTX mdk = { 0 };
    MD5_Init(&mdk);
    MD5_Update(&mdk, license, license_len);
    md5sum(digest, &mdk);

    printf("License key: ");

    for (; i < 64; i += 4, j += 1)
    {
        unsigned value = mdk.buf[j];
        mdk.result[i] = value;
        mdk.result[i + 1] = (value >> 8) & 0x1f;
        mdk.result[i + 2] = (value >> 16) & 0x4f;
        mdk.result[i + 3] = (value >> 24) & 0x8f;
    }

    for (i = 0; i < 10; ++i)
    {
        if (i && (i % 2) == 0)
            putchar('-');
        printf("%02X", mdk.result[i]);
    }

    printf("\n");

    return 0;
}
