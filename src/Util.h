/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#ifndef BITS_H
#define BITS_H

#include <stdint.h>
#include <assert.h>
#include <stdio.h>

// floor(log2(x))
static inline int Util_log2floor(uint64_t x) {
    assert(x);
    return 63 - _Generic(x,
        unsigned long long: __builtin_clzll(x),
        unsigned long: __builtin_clzl(x)
    );
}
// ceiling(log2(x))
static inline int Util_log2ceil(uint64_t x) {
	return ((x & (x - 1)) != 0) + Util_log2floor(x);
}

static inline uint64_t Util_reverse64(uint64_t x)
{
    #define Util_RM(in, mask, rb) ((((in) >> (rb)) & (mask)) | (((in) & (mask)) << (rb)))
    x = Util_RM(x, 0x5555555555555555ull, 1);
    x = Util_RM(x, 0x3333333333333333ull, 2);
    x = Util_RM(x, 0x0F0F0F0F0F0F0F0Full, 4);
    return __builtin_bswap64(x);
    #undef Util_RM
}

static inline uint32_t Util_annSoftNonceMax(uint32_t target) {
    int bits = (22 - Util_log2floor(target & 0x007fffff)) + ((0x20 - (target >> 24)) * 8) + 10;
    return (bits >= 24) ? 0x00ffffff : (0x00ffffff >> (24 - bits));
}

#if defined(__GNUC__) && __GNUC__ >= 7
    #define Util_fallthrough() __attribute__ ((fallthrough))
#else
    #define Util_fallthrough() ((void)0)
#endif

#define Util_likely(x)       __builtin_expect((x),1)
#define Util_unlikely(x)     __builtin_expect((x),0)

//#define DEBUG
#ifdef DEBUG
#define Util_INVAL_IF(expr) assert(!(expr))
#define Util_BUG_IF(expr) assert(!(expr))
#else
#define Util_INVAL_IF(expr) do { if (expr) { return -1; } } while (0)
#define Util_BUG_IF(expr) do { \
    if (!(expr)) { break; } \
    fprintf(stderr, "BUG %s:%d (%s)\n", __FILE__, __LINE__, #expr); \
    return -2; \
} while (0)
#endif

#endif
