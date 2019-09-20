/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#ifndef RANDGEN_H
#define RANDGEN_H

#include "Buf.h"
#include "Conf.h"

#include <stdint.h>

// buf is a piece of memory where the result can be placed
// bufLen is a pointer to the length of the buffer in 4 byte units.
// returns:
//   * the length of the program if all is well,
//   * RandHash_TOO_BIG / RandHash_TOO_SMALL if the progam is non-conformant
//   * RandHash_ENOMEM if bufLen is too small for the program
int RandGen_generate(uint32_t buf[static Conf_RandGen_MAX_INSNS], Buf32_t* seed);

#endif
