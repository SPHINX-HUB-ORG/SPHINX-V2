// by Satoshi Nakamoto
// Why base-58 instead of standard base-64 encoding?
// - Don't want 0OIl characters that look the same in some fonts and
//      could be used to create visually identical looking account numbers.
// - A string with non-alphanumeric characters is not as easily accepted as an account number.
// - E-mail usually won't line-break if there's no punctuation to break at.
// - Doubleclicking selects the whole number as one word if it's all alphanumeric.

#ifndef BASE58CHECK_H
#define BASE58CHECK_H

#include <stddef.h>
#include <stdint.h>

// Blake3-256 hash function
void blake3_256(void *hash, const void *data, size_t len);

// Convert a blake3-256 hash to base58check
char *blake3_256_to_base58check(const void *hash, size_t len);

// Free a base58check string
void free_blake3_256_base58check(char *base58check);

#endif

