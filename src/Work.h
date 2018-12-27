#ifndef WORK_H
#define WORK_H

#include <stdint.h>

// 0 means failure
int Work_check(unsigned char * hash, int target);

static inline uint32_t Work_increase(uint32_t target, int bits) {
    int exponent = target >> 24;
    target &= 0x00ffffff;
    while (!(target & (3<<22))) { target <<= 1; bits++; }
    exponent -= bits / 8;
    assert(exponent > 0);
    target = (target >> (bits % 8)) | (exponent << 24);
    assert(!(target & (1<<23)));
    return target;
}

#endif
