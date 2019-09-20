/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#include "PrintProg.h"
#include "Conf.h"
#include "Vec.h"
#include "DecodeInsn.h"
#include "RandHash.h"

#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>

typedef struct {
    uint32_t* prog;
    int progLen;

    uint32_t insn;
    int pc;

    Vec vars;
    int scope;
    int varNum;
} Context;

enum OpCode {
    #define OpCodes_ALL
    #define OpCodes_VISITOR(x) OpCode_ ## x,
    #include "OpCodes.h"
    OpCode__MAX
};

static const char* OP_STR[] = {
    #define OpCodes_ALL
    #define OpCodes_VISITOR(x) [OpCode_ ## x] = #x,
    #include "OpCodes.h"
};

static const uint8_t OP_INS_OUTS[][2] = {
    #define OpCodes_1_1
    #define OpCodes_VISITOR(OP) [OpCode_ ## OP ] = { 1, 1 },
    #include "OpCodes.h"

    #define OpCodes_2_1
    #define OpCodes_VISITOR(OP) [OpCode_ ## OP ] = { 2, 1 },
    #include "OpCodes.h"

    #define OpCodes_2_2
    #define OpCodes_VISITOR(OP) [OpCode_ ## OP ] = { 2, 2 },
    #include "OpCodes.h"

    #define OpCodes_4_2
    #define OpCodes_VISITOR(OP) [OpCode_ ## OP ] = { 4, 2 },
    #include "OpCodes.h"

    #define OpCodes_4_4
    #define OpCodes_VISITOR(OP) [OpCode_ ## OP ] = { 4, 4 },
    #include "OpCodes.h"
};

static uint32_t getVar(Context* ctx, uint32_t idx, bool dbl) {
    if (dbl) {
        assert(idx > 0);
        assert(ctx->vars.elems[idx - 1] < ~0u);
    }
    assert(idx < ctx->vars.count);
    uint32_t e = ctx->vars.elems[idx];
    assert(e < ~0u);
    return e;
}

static uint32_t getA(Context* ctx, uint32_t insn, bool dbl) {
    return getVar(ctx, DecodeInsn_REGA(insn), dbl);
}
static uint32_t getB(Context* ctx, uint32_t insn, bool dbl) {
    return getVar(ctx, DecodeInsn_REGB(insn), dbl);
}

// we pack the var's scope and it's number into the var so it's quick to access
#define SCOPE(a) ((a) >> 16)
#define IDX(a) ((a) & 0xffff)
static void mkVars(Context* ctx, int num) {
    for (int i = 0; i < num; i++) { Vec_push(&ctx->vars, (ctx->scope << 16) | (++ctx->varNum)); }
}

static void pad(Context* ctx) {
    for (int i = 0; i < ctx->scope; i++) { printf("  "); }
}

static void out(Context* ctx, int outs, char* fmt, ...) {
    int v = ctx->varNum + 1;
    pad(ctx);
    mkVars(ctx, outs);
    switch (outs) {
        case 1: {
            printf("OP1(l_%d_%d, ", ctx->scope, v);
            break;
        }
        case 2: {
            printf("OP2(l_%d_%d, l_%d_%d, ", ctx->scope, v, ctx->scope, v + 1);
            break;
        }
        case 4: {
            printf("OP4(l_%d_%d, l_%d_%d, l_%d_%d, l_%d_%d, ",
                ctx->scope, v, ctx->scope, v + 1, ctx->scope, v + 2, ctx->scope, v + 3);
            break;
        }
        default: assert(0);
    }
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    printf("); // 0x%08x @ %d\n", ctx->insn, ctx->pc);
}

static void op(Context* ctx, uint32_t insn) {
    int ins = OP_INS_OUTS[DecodeInsn_OP(insn)][0];
    int outs = OP_INS_OUTS[DecodeInsn_OP(insn)][1];
    switch (ins) {
        case 1: {
            uint32_t a = getA(ctx, insn, false);
            out(ctx, outs, "%s(l_%d_%d)", OP_STR[DecodeInsn_OP(insn)], SCOPE(a), IDX(a));
            break;
        }
        case 2: {
            uint32_t a = getA(ctx, insn, false);
            if (DecodeInsn_HAS_IMM(insn)) {
                out(ctx, outs, "%s(l_%d_%d, 0x%08x)", OP_STR[DecodeInsn_OP(insn)],
                    SCOPE(a), IDX(a), DecodeInsn_immLo(insn));
            } else {
                uint32_t b = getB(ctx, insn, false);
                out(ctx, outs, "%s(l_%d_%d, l_%d_%d)", OP_STR[DecodeInsn_OP(insn)],
                    SCOPE(a), IDX(a), SCOPE(b), IDX(b));
            }
            break;
        }
        case 4: {
            uint32_t a = getA(ctx, insn, true);
            if (DecodeInsn_HAS_IMM(insn)) {
                uint64_t imm = (uint64_t) DecodeInsn_imm(insn);
                out(ctx, outs, "%s(l_%d_%d, l_%d_%d, 0x%08x, 0x%08x)",
                    OP_STR[DecodeInsn_OP(insn)],
                    SCOPE(a), IDX(a)-1, SCOPE(a), IDX(a), (uint32_t)imm, (uint32_t) (imm >> 32));
            } else {
                uint32_t b = getB(ctx, insn, true);
                out(ctx, outs, "%s(l_%d_%d, l_%d_%d, l_%d_%d, l_%d_%d)",
                    OP_STR[DecodeInsn_OP(insn)],
                    SCOPE(a), IDX(a)-1, SCOPE(a), IDX(a), SCOPE(b), IDX(b)-1, SCOPE(b), IDX(b));
            }

            break;
        }
        default: {
            printf("Unexpected number of inputs [%d] insn=[%s] (%d)\n",
                ins, OP_STR[DecodeInsn_OP(insn)], DecodeInsn_OP(insn));
            assert(0);
        }
    }
}

static void scope(Context* ctx) {
    ctx->scope++;
    ctx->varNum = 0;
    Vec_push(&ctx->vars, ~0u);
}

static void printC(Context* ctx)
{
    for (int pc = 0; ; pc++) {
        assert(pc < ctx->progLen);
        ctx->pc = pc;
        uint32_t insn = ctx->insn = ctx->prog[pc];
        assert(DecodeInsn_OP(insn) > OpCode_INVALID_ZERO);
        assert(DecodeInsn_OP(insn) < OpCode_INVALID_BIG);
        switch (DecodeInsn_OP(insn)) {
            // OP1(l_0_0, MEMORY(loop_0, 40, 55, 12));
            // #define MEMORY(loopVar, base, step, carry) ...
            case OpCode_MEMORY: {
                out(ctx, 1, "MEMORY(loop_%d, 0x%08x, %u, %u)",
                    ctx->scope, // loops are numbered by the scope
                    DecodeInsn_MEMORY_BASE(insn),
                    DecodeInsn_MEMORY_STEP(insn),
                    DecodeInsn_MEMORY_CARRY(insn));
                break;
            }
            case OpCode_IN: {
                out(ctx, 1, "IN(%d)", ((uint32_t) DecodeInsn_immLo(insn)) % RandHash_INOUT_SZ);
                break;
            }
            case OpCode_LOOP: {
                pad(ctx);
                scope(ctx);
                printf("LOOP(loop_%d, %d) { // 0x%08x @ %d\n",
                    ctx->scope, DecodeInsn_immLo(insn), insn, pc);
                break;
            }
            case OpCode_IF_RANDOM:
            case OpCode_IF_LIKELY: {
                pad(ctx);
                uint32_t a = getA(ctx, insn, false);
                printf("%s(l_%d_%d) { // 0x%08x @ %d\n",
                    OP_STR[DecodeInsn_OP(insn)], SCOPE(a), IDX(a), insn, pc);
                // every branch is followed immediately by a jmp, which we will ignore
                pc++;
                scope(ctx);
                break;
            }
            case OpCode_JMP: {
                // we get an end before a jmp
                pad(ctx);
                printf("else { // 0x%08x @ %d\n", insn, pc);
                scope(ctx);
                break;
            }
            case OpCode_END: {
                int i = 1;
                for (; i + 7 <= ctx->varNum; i += 8) {
                    pad(ctx); printf("OUT8(l_%d_%d", ctx->scope, i);
                    for (int j = i + 1; j < i + 8; j++) { printf(", l_%d_%d", ctx->scope, j); }
                    printf(");\n");
                }
                for (; i + 3 <= ctx->varNum; i += 4) {
                    pad(ctx); printf("OUT4(l_%d_%d", ctx->scope, i);
                    for (int j = i + 1; j < i + 4; j++) { printf(", l_%d_%d", ctx->scope, j); }
                    printf(");\n");
                }
                for (; i + 1 <= ctx->varNum; i += 2) {
                    pad(ctx); printf("OUT2(l_%d_%d", ctx->scope, i);
                    for (int j = i + 1; j < i + 2; j++) { printf(", l_%d_%d", ctx->scope, j); }
                    printf(");\n");
                }
                for (; i <= ctx->varNum; i++) {
                    pad(ctx); printf("OUT(l_%d_%d);\n", ctx->scope, i);
                }
                while (Vec_pop(&ctx->vars) != ~0u) { }
                ctx->scope--;
                pad(ctx);
                printf("} // 0x%08x @ %d\n", insn, pc);
                if (ctx->scope < 1) { return; }
                assert(ctx->vars.count);
                assert((int)(ctx->vars.elems[ctx->vars.count - 1] >> 16) == ctx->scope);
                ctx->varNum = ctx->vars.elems[ctx->vars.count - 1] & 0xffff;
                break;
            }
            default: op(ctx, insn);
        }
    }
}

void PrintProg_asC(uint32_t* prog, int progLen)
{
    Context ctx; memset(&ctx, 0, sizeof ctx);

    ctx.prog = prog;
    ctx.progLen = progLen;

    printf("BEGIN\n");
    printC(&ctx);
    printf("END\n");
}
