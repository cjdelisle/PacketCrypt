/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#ifndef BUF_H
#define BUF_H

#include <stdint.h>
#include <string.h>

#define Buf_TYPES(byteCt) \
    uint8_t bytes[(byteCt)];  \
    uint16_t shorts[(byteCt)/2]; \
    uint32_t ints[(byteCt)/4];   \
    uint64_t longs[(byteCt)/8]

typedef union {
    Buf_TYPES(16);
} Buf16_t;
_Static_assert(sizeof(Buf16_t) == 16, "buf16 size");
typedef union {
    Buf_TYPES(32);
    Buf16_t sixteens[2];
} Buf32_t;
_Static_assert(sizeof(Buf32_t) == 32, "buf16 size");
typedef union {
    Buf_TYPES(64);
    Buf16_t sixteens[4];
    Buf32_t thirtytwos[2];
} Buf64_t;
_Static_assert(sizeof(Buf64_t) == 64, "buf64 size");

#define Buf_IS_ARRAY(arg) __builtin_types_compatible_p( \
    __typeof__(arg), __typeof__((arg)[0]) [ ])
#define Buf_SIZEOF(ptr) ( Buf_IS_ARRAY(ptr) ? sizeof (ptr) : sizeof *(ptr) )

#define Buf_OBJCPY(dst, src) do { \
        _Static_assert(Buf_SIZEOF(dst) == Buf_SIZEOF(src), "sizeof *(dst) != sizeof *(src)"); \
        _Static_assert(Buf_SIZEOF(dst) != sizeof(char*), "sizeof *(dst) is size of a pointer"); \
        memcpy((dst), (src), Buf_SIZEOF(dst)); \
    } while (0)

#define Buf_OBJCPY_LDST(dst, src) do { \
        _Static_assert(Buf_SIZEOF(dst) < Buf_SIZEOF(src), "sizeof *(dst) >= sizeof *(src)"); \
        _Static_assert(Buf_SIZEOF(dst) != sizeof(char*), "sizeof *(dst) is size of a pointer"); \
        memcpy((dst), (src), Buf_SIZEOF(dst)); \
    } while (0)

#define Buf_OBJCPY_LSRC(dst, src) do { \
        _Static_assert(Buf_SIZEOF(dst) > Buf_SIZEOF(src), "sizeof *(dst) >= sizeof *(src)"); \
        _Static_assert(Buf_SIZEOF(src) != sizeof(char*), "sizeof *(src) is size of a pointer"); \
        memcpy((dst), (src), Buf_SIZEOF(src)); \
    } while (0)

#define Buf_OBJSET(dst, val) do { \
        _Static_assert(Buf_SIZEOF(dst) != sizeof(char*), "sizeof *(dst) is size of a pointer"); \
        memset((dst), (val), Buf_SIZEOF(dst)); \
    } while (0)

#define Buf_OBJCMP(dst, src) __extension__ ({ \
        _Static_assert(Buf_SIZEOF(dst) == Buf_SIZEOF(src), "sizeof *(dst) != sizeof *(src)"); \
        _Static_assert(Buf_SIZEOF(dst) != sizeof(char*), "sizeof *(dst) is size of a pointer"); \
        memcmp((dst), (src), Buf_SIZEOF(dst)); \
    })

static inline int Buf_isZero(uint8_t* buf, int length) {
    int ret = 1;
    for (int i = 0; i < length; i++) { ret &= (buf[i] == 0); }
    return ret;
}

#define Buf_IS_ZERO(thing) __extension__ ({ \
        _Static_assert(Buf_SIZEOF(thing) != sizeof(char*), "sizeof thing is size of a pointer"); \
        Buf_isZero((uint8_t*)thing, Buf_SIZEOF(thing)); \
    })

static __attribute__((unused)) inline void Buf_test() {
    struct {
        struct {
            uint8_t version;
            uint8_t softNonce[3];
            uint32_t workBits;
            uint8_t x[48];
        } hdr;
    } _ann;
    _Static_assert(Buf_IS_ARRAY(_ann.hdr.softNonce), "");
    _Static_assert(!Buf_IS_ARRAY(&_ann.hdr), "");
    _Static_assert(!Buf_IS_ARRAY(&_ann.hdr.version), "");
    _Static_assert(Buf_SIZEOF(&_ann.hdr) == 56, "");
    _Static_assert(Buf_SIZEOF(_ann.hdr.softNonce) == 3, "");
    _Static_assert(Buf_SIZEOF(&_ann.hdr.version) == 1, "");
    _Static_assert(Buf_SIZEOF(&_ann.hdr.workBits) == 4, "");
}

#endif
