// Copyright (c) [2023] SPHINX-HUB
// All rights reserved.
// This software is distributed under the MIT License.


//**
// Satoshi Nakamoto
// Why base-58 instead of standard base-64 encoding?
// - Don't want 0OIl characters that look the same in some fonts and
//      could be used to create visually identical looking account numbers.
// - A string with non-alphanumeric characters is not as easily accepted as an account number.
// - E-mail usually won't line-break if there's no punctuation to break at.
// - Doubleclicking selects the whole number as one word if it's all alphanumeric.
//**


#ifndef WIN32
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <base58.h>
#include <base58check.h>

bool (*b58_blake3_impl)(void *, const void *, size_t) = NULL;

static const int8_t b58digits_map[] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
};

typedef uint64_t b58_maxint_t;
typedef uint32_t b58_almostmaxint_t;
#define b58_almostmaxint_bits (sizeof(b58_almostmaxint_t) * 8)
static const b58_almostmaxint_t b58_almostmaxint_mask = ((((b58_maxint_t)1) << b58_almostmaxint_bits) - 1);

bool b58tobin(void *bin, size_t *binszp, const char *b58, size_t b58sz)
{
    size_t binsz = *binszp;
    const unsigned char *b58u = (void*)b58;
    unsigned char *binu = bin;
    size_t outisz = (binsz + sizeof(b58_almostmaxint_t) - 1) / sizeof(b58_almostmaxint_t);
    b58_almostmaxint_t outi[outisz];
    b58_maxint_t t;
    b58_almostmaxint_t c;
    size_t i, j;
    uint8_t bytesleft = binsz % sizeof(b58_almostmaxint_t);
    b58_almostmaxint_t zeromask = bytesleft ? (b58_almostmaxint_mask << (bytesleft * 8)) : 0;
    unsigned zerocount = 0;

    if (!b58sz)
        b58sz = strlen(b58);

    for (i = 0; i < outisz; ++i) {
        outi[i] = 0;
    }

        // Leading zeros, just count
    for (i = 0; i < b58sz && b58u[i] == '1'; ++i)
        ++zerocount;

    for (; i < b58sz; ++i)
    {
        if (b58u[i] & 0x80)
            // High-bit set on invalid digit
            return false;
        if (b58digits_map[b58u[i]] == -1)
            // Invalid base58 digit
            return false;
        c = (unsigned)b58digits_map[b58u[i]];
        for (j = outisz; j--; )
        {
            t = ((b58_maxint_t)outi[j]) * 58 + c;
            c = t >> b58_almostmaxint_bits;
            outi[j] = t & b58_almostmaxint_mask;
        }
        if (c)
            // Output number too big (carry to the next int32)
            return false;
        if (outi[0] & zeromask)
            // Output number too big (last int32 filled too far)
            return false;
    }

    j = 0;
    if (bytesleft) {
        for (i = bytesleft; i > 0; --i) {
            *(binu++) = (outi[0] >> (8 * (i - 1))) & 0xff;
        }
        ++j;
    }

    for (; j < outisz; ++j)
    {
        for (i = sizeof(*outi); i > 0; --i) {
            *(binu++) = (outi[j] >> (8 * (i - 1))) & 0xff;
        }
    }

    // Count canonical base58 byte count
    binu = bin;
    for (i = 0; i < binsz; ++i)
    {
        if (binu[i])
            break;
        --*binszp;
    }
    *binszp += zerocount;

    return true;
}
