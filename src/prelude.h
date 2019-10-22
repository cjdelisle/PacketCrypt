/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#include "RandHash.h"
#include "OpTemplate2.h"
#include "Conf.h"

#include <stdint.h>

#define DEBUGF(...)

#define OP1(out, in) uint32_t out = in; DEBUGF("%s -> %08x\n", #in, out)
#define OP2(outA, outB, in) \
    uint32_t outA, outB;                    \
    do {                                    \
        uint64_t tmp = in;                  \
        outA = (uint32_t) tmp;              \
        outB = (uint32_t) (tmp >> 32);      \
    } while (0)
#define OP4(outA, outB, outC, outD, in) \
    uint32_t outA, outB, outC, outD;        \
    do {                                    \
        uint128 tmp = in;                   \
        outA = U128_0(tmp);                 \
        outB = U128_1(tmp);                 \
        outC = U128_2(tmp);                 \
        outD = U128_3(tmp);                 \
    } while (0)

#define IF_LIKELY(x) if (((uint8_t)(x) & 7) != 0)
#define IF_RANDOM(x) if (((uint8_t)(x) & 1) != 0)
#define LOOP(i, count) for (int i = 0; i < count; i++)

#define OUT(x) do { DEBUGF("out1(%08x) %d\n", (x), hashctr); hashOut[hashctr] += (x); hashctr = (hashctr + 1) % RandHash_INOUT_SZ; } while (0)
#define OUT2(x,y) do { OUT(x); OUT(y); } while (0)
#define OUT4(x,y,z,a) do { OUT2(x,y); OUT2(z,a); } while (0)
#define OUT8(x,y,z,a,b,c,d,e) do { OUT4(x,y,z,a); OUT4(b,c,d,e); } while (0)
#define IN(x) hashIn[(x) & (RandHash_MEMORY_SZ - 1)]
#define MEMORY(loopVar, base, step, carry) memory[(base + ((loopVar + carry) * step)) & (RandHash_MEMORY_SZ - 1)]

#define FUNC_DECL void run

#define BEGIN \
    FUNC_DECL (uint32_t* hashOut, uint32_t* hashIn, uint32_t* memory, int cycles) { \
        for (int i = 0; i < cycles; i++) {                                          \
            int hashctr = 0;

#define END \
            uint32_t* x = hashOut; hashOut = hashIn; hashIn = x;                    \
        }                                                                           \
    }
