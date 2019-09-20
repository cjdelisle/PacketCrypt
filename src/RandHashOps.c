/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#include <stdint.h>

#include "OpTemplate2.h"

enum OpCodes {
    #define OpCodes_ALL
    #define OpCodes_VISITOR(x) OpCode_ ## x,
    #include "OpCodes.h"

    OpCode__MAX
};

// Strictly for golang compliance testing
void RandHashOps_doOp(uint32_t inout[8], uint32_t opcode) {
    switch (opcode) {
    #define OpCodes_1_1
    #define OpCodes_VISITOR(OP) case OpCode_ ## OP : { inout[4] = OP(inout[0]); break; }
    #include "OpCodes.h"

    #define OpCodes_2_1
    #define OpCodes_VISITOR(OP) case OpCode_ ## OP : { inout[4] = OP(inout[0], inout[1]); break; }
    #include "OpCodes.h"

    #define OpCodes_2_2
    #define OpCodes_VISITOR(OP) case OpCode_ ## OP : { \
        uint64_t out = OP(inout[0], inout[1]); \
        inout[4] = out & 0xffffffff; inout[5] = out >> 32; \
        break; }
    #include "OpCodes.h"

    #define OpCodes_4_2
    #define OpCodes_VISITOR(OP) case OpCode_ ## OP : { \
        uint64_t out = OP(inout[0], inout[1], inout[2], inout[3]); \
        inout[4] = out & 0xffffffff; inout[5] = out >> 32; \
        break; }
    #include "OpCodes.h"

    #define OpCodes_4_4
    #define OpCodes_VISITOR(OP) case OpCode_ ## OP : { \
        uint128 out = OP(inout[0], inout[1], inout[2], inout[3]); \
        inout[4] = U128_0(out); inout[5] = U128_1(out); \
        inout[6] = U128_2(out); inout[7] = U128_3(out); \
        break; }
    #include "OpCodes.h"
    default:;
    }
}
