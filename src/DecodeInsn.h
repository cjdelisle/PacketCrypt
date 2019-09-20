/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#ifndef DECODEINSN_H
#define DECODEINSN_H

#include <stdint.h>

/*
 * Normal op
 *     3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
 *     1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  0 |  ?  |       regB      |?|0|      regA       |        op       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  4
 *
 * IMM op / IF / Loop / input
 *     3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
 *     1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  0 |          imm          |P|1|      regA       |        op       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  4
 *
 * JMP
 *     3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
 *     1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  0 |                     imm                     |        op       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  4
 *
 *  MEMORY
 *     3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
 *     1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  0 |            randloc          |  step | carry |        op       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  4
 */

#define DecodeInsn_REGA(insn)    (((insn) >>  9) & 0x1ff)
#define DecodeInsn_REGB(insn)    (((insn) >> 20) & 0x1ff)
#define DecodeInsn_HAS_IMM(insn) (((insn) >> 18) & 1)

#define DecodeInsn_MEMORY_CARRY(insn) (((insn) >> 9) & 15)
#define DecodeInsn_MEMORY_WITH_CARRY(insn, carry) (((insn) & ~(15 << 9)) | (((carry) & 15) << 9))

#define DecodeInsn_MEMORY_STEP(insn) (((insn) >> 13) & 15)
#define DecodeInsn_MEMORY_BASE(insn) ((insn) >> 17)

#define DecodeInsn_OP(insn) ((insn) & 0xff)

static inline int64_t DecodeInsn_imm(uint32_t insn) {
    if (insn & (1<<19)) {
        // it's a pattern

        //     1 1
        //     1 0 9 8 7 6 5 4 3 2 1 0
        //    +-+-+-+-+-+-+-+-+-+-+-+-+
        //  0 |S|I|    B    |    A    |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+
        int imm = insn >> 20;
        int a = imm & ((1<<5)-1); imm >>= 5;
        int b = imm & ((1<<5)-1); imm >>= 5;
        int i = imm & 1;          imm >>= 1;
        int s = imm;

        int64_t big1 = 1;
        uint64_t out = ((((uint64_t)i) << 63) - 1) ^ (big1 << b) ^ (big1 << a);

        // Drop the top bit
        imm <<= 1; imm >>= 1;

        big1 &= s;
        out |= big1 << 63;
        return (int64_t) out;
    }
    return (int64_t)( ((int32_t) insn) >> 20 );
}
static inline int32_t DecodeInsn_immLo(uint32_t insn) { return (int32_t) DecodeInsn_imm(insn); }

#endif
