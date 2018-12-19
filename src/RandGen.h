#ifndef RANDGEN_H
#define RANDGEN_H

#include <stdint.h>

uint32_t* RandGen_generate(
    uint8_t seed[32],
    uint32_t* insnCount,
    uint32_t minInsns,
    uint32_t maxInsns
);

#endif
