/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#ifndef RANDHASH_H
#define RANDHASH_H

#include "Buf.h"
#include "CryptoCycle.h"
#include "Conf.h"

#include <stdint.h>

// keep these powers of 2 because there is unsigned modulo using &
// Also be careful not to change these without also checking the buffers
// which are passed to RandHash_execute()
#define RandHash_MEMORY_SZ 256
#define RandHash_INOUT_SZ  256

// Program is too big
#define RandHash_TOO_BIG   -1

// Program is too small
#define RandHash_TOO_SMALL -2

// program cycles-to-execute errors
#define RandHash_TOO_LONG  -3
#define RandHash_TOO_SHORT -4

int RandHash_interpret(
    uint32_t progbuf[Conf_RandGen_MAX_INSNS],
    CryptoCycle_State_t* ccState,
    uint32_t* memory,
    int progLen,
    uint32_t memorySizeBytes,
    int cycles);

#endif
