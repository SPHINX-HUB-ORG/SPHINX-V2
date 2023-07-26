#ifndef LIBBASE58_H
#define LIBBASE58_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

bool (*b58_blake3_impl)(void *, const void *, size_t);

bool b58tobin(void *bin, size_t *binszp, const char *b58, size_t b58sz);

#ifdef __cplusplus
}
#endif

#endif  // LIBBASE58_H
