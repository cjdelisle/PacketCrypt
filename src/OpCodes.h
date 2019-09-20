/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#ifndef OpCodes_VISITOR
    // No visitor, we'll do nothing
    #define OpCodes_VISITOR(x)
#endif

#define OpCodes_OP(_name) \
    OpCodes_VISITOR(_name ## 8)  \
    OpCodes_VISITOR(_name ## 16) \
    OpCodes_VISITOR(_name ## 32)

#define OpCodes_OPC(_name) \
    OpCodes_VISITOR(_name ## 8C)  \
    OpCodes_VISITOR(_name ## 16C) \
    OpCodes_VISITOR(_name ## 32C)

#ifdef OpCodes_ALL
    #undef OpCodes_ALL
    #define OpCodes_1_1
    #define OpCodes_2_1
    #define OpCodes_2_2
    #define OpCodes_4_2
    #define OpCodes_4_4
    #define OpCodes_CTRL
#endif

#ifdef OpCodes_CTRL
    OpCodes_VISITOR(INVALID_ZERO)
#endif

#ifdef OpCodes_1_1
    #undef OpCodes_1_1
    OpCodes_OP(POPCNT)
    OpCodes_OP(CLZ)
    OpCodes_OP(CTZ)

    OpCodes_VISITOR(BSWAP16)
    OpCodes_VISITOR(BSWAP32)
#endif

#ifdef OpCodes_2_1
    #undef OpCodes_2_1
    OpCodes_OP(ADD)
    OpCodes_OP(SUB)
    OpCodes_OP(SHLL)
    OpCodes_OP(SHRL)
    OpCodes_OP(SHRA)
    OpCodes_OP(ROTL)
    OpCodes_OP(MUL)

    OpCodes_VISITOR(AND)
    OpCodes_VISITOR(OR)
    OpCodes_VISITOR(XOR)
#endif

#ifdef OpCodes_2_2
    #undef OpCodes_2_2
    OpCodes_OPC(ADD)
    OpCodes_OPC(SUB)
    OpCodes_OPC(MUL)
    OpCodes_OPC(MULSU)
    OpCodes_OPC(MULU)
#endif

#ifdef OpCodes_4_2
    #undef OpCodes_4_2
    OpCodes_VISITOR(ADD64)
    OpCodes_VISITOR(SUB64)
    OpCodes_VISITOR(SHLL64)
    OpCodes_VISITOR(SHRL64)
    OpCodes_VISITOR(SHRA64)
    OpCodes_VISITOR(ROTL64)
    OpCodes_VISITOR(ROTR64)
    OpCodes_VISITOR(MUL64)
#endif

#ifdef OpCodes_4_4
    #undef OpCodes_4_4
    OpCodes_VISITOR(ADD64C)
    OpCodes_VISITOR(SUB64C)
    OpCodes_VISITOR(MUL64C)
    OpCodes_VISITOR(MULSU64C)
    OpCodes_VISITOR(MULU64C)
#endif

#ifdef OpCodes_CTRL
    #undef OpCodes_CTRL
    OpCodes_VISITOR(IN)
    OpCodes_VISITOR(MEMORY)

    OpCodes_VISITOR(LOOP)
    OpCodes_VISITOR(IF_LIKELY)
    OpCodes_VISITOR(IF_RANDOM)
    OpCodes_VISITOR(JMP)
    OpCodes_VISITOR(END)

    OpCodes_VISITOR(INVALID_BIG)
#endif

#undef OpCodes_OP
#undef OpCodes_OPC
#undef OpCodes_VISITOR
