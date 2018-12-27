#ifndef RANDGEN_H
#define RANDGEN_H

#include "Buf.h"

#include <stdint.h>

// buf is a piece of memory where the result can be placed
// bufLen is a pointer to the length of the buffer in 4 byte units.
// returns:
//   * the length of the program if all is well,
//   * RandHash_TOO_BIG / RandHash_TOO_SMALL if the progam is non-conformant
//   * RandHash_ENOMEM if bufLen is too small for the program
int RandGen_generate(uint32_t* buf, int bufLen4, Buf32_t* seed);

#endif
