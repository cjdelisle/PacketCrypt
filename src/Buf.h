#ifndef BUF_H
#define BUF_H

#include <stdint.h>

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

#endif
