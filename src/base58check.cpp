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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lib/Blake3/c/blake3.h>
#include <base58.hpp>
#include <base58check.hpp>


// Blake3-256 hash function
void blake3_256(void *hash, const void *data, size_t len) {
  blake3_hash(hash, data, len);
}

// Convert a blake3-256 hash to base58check
char *blake3_256_to_base58check(const void *hash, size_t len) {
  char *base58check = malloc(b58check_encode_size(len));
  if (base58check == NULL) {
    return NULL;
  }

  b58check_encode(base58check, hash, len);

  return base58check;
}

// Free a base58check string
void free_blake3_256_base58check(char *base58check) {
  free(base58check);
}

int main() {
  // Generate a random blake3-256 hash
  uint8_t hash[32];
  blake3_256(hash, NULL, 0);

  // Convert the hash to base58check
  char *base58check = blake3_256_to_base58check(hash, sizeof(hash));
  if (base58check == NULL) {
    return 1;
  }

  // Print the base58check string
  printf("Base58check: %s\n", base58check);

  // Free the base58check string
  free_blake3_256_base58check(base58check);

  return 0;
}
