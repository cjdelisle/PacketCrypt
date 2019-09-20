/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#include "Conf.h"
#include "RandHash.h"
#include "Vec.h"
#include "OpTemplate2.h"
#include "DecodeInsn.h"
#include "RandGen.h"
#include "Buf.h"
#include "CryptoCycle.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum OpCodes {
    #define OpCodes_ALL
    #define OpCodes_VISITOR(x) OpCode_ ## x,
    #include "OpCodes.h"

    OpCode__MAX
};

typedef struct {
    uint32_t* memory;

    uint32_t* hashIn;
    uint32_t* hashOut;

    uint32_t* prog;
    int progLen;

    int hashctr;

    int loopCycle;
    int varCount;

    uint64_t opCtr;

    Vec vars;
    Vec scopes;
} Context;

typedef struct {
    uint32_t lo;
    uint32_t hi;
} Uint64;


static inline uint32_t getReg(Context* ctx, uint16_t index) {
    assert(index < ctx->vars.count);
    return ctx->vars.elems[index];
}

static inline uint32_t getA(Context* ctx, uint32_t insn) {
    return getReg(ctx, DecodeInsn_REGA(insn));
}
static inline uint32_t getB(Context* ctx, uint32_t insn) {
    if (DecodeInsn_HAS_IMM(insn)) { return DecodeInsn_immLo(insn); }
    return getReg(ctx, DecodeInsn_REGB(insn));
}

static inline Uint64 getA2(Context* ctx, uint32_t insn) {
    return (Uint64) { getReg(ctx, DecodeInsn_REGA(insn) - 1), getReg(ctx, DecodeInsn_REGA(insn)) };
}
static inline Uint64 getB2(Context* ctx, uint32_t insn) {
    if (DecodeInsn_HAS_IMM(insn)) {
        int64_t imm = DecodeInsn_imm(insn);
        return (Uint64) { (uint32_t) imm, (uint32_t)(((uint64_t) imm) >> 32) };
    }
    return (Uint64) { getReg(ctx, DecodeInsn_REGB(insn) - 1), getReg(ctx, DecodeInsn_REGB(insn)) };
}

#ifdef DEBUG
#include <stdio.h>
static const char* OP_STR[] = {
    #define OpCodes_ALL
    #define OpCodes_VISITOR(x) [OpCode_ ## x] = #x,
    #include "OpCodes.h"
};
#undef DEBUGF
#define DEBUGF(fmt, ...) do { \
    for (int i = 0; i < (int)ctx->scopes.count; i++) { printf("  "); }   \
    printf("// ");                                                  \
    printf(fmt, __VA_ARGS__);                                       \
} while (0)
#else
#undef DEBUGF
#define DEBUGF(fmt, ...)
#endif

#ifdef OPTEST
#include <stdio.h>
// Create function prototypes for optest functions which are defined inside of optest.c
#define OpCodes_1_1
#define OpCodes_VISITOR(OP) \
    uint32_t optest11_ ## OP (uint32_t a);
#include "OpCodes.h"

#define OpCodes_2_1
#define OpCodes_VISITOR(OP) \
    uint32_t optest21_ ## OP (uint32_t a, uint32_t b);
#include "OpCodes.h"

#define OpCodes_2_2
#define OpCodes_VISITOR(OP) \
    uint64_t optest22_ ## OP (uint32_t a, uint32_t b);
#include "OpCodes.h"

#define OpCodes_4_2
#define OpCodes_VISITOR(OP) \
    uint64_t optest42_ ## OP (uint32_t a, uint32_t b, uint32_t c, uint32_t d);
#include "OpCodes.h"

#define OpCodes_4_4
#define OpCodes_VISITOR(OP) \
    uint128 optest44_ ## OP (uint32_t a, uint32_t b, uint32_t c, uint32_t d);
#include "OpCodes.h"

#define TEST1(op1, op2, a) do { \
    uint32_t _a = (a); \
    assert(op1(_a) == op2(_a) && #op1); \
    /*printf("%s\n", #op1);*/ \
} while (0)

#define TEST2(op1, op2, a, b) do { \
    uint32_t _a = (a), _b = (b); \
    if (op1(_a, _b) != op2(_a, _b)) { \
        printf("%s %08x %08x -> %08llx %08llx\n", #op1, _a, _b, (long long)op1(_a, _b), (long long)op2(_a, _b)); \
        assert(0 && #op1 && #op2); \
    } \
    /*printf("%s\n", #op1);*/ \
} while (0)

#define TEST42(op1, op2, a, b) do { \
    uint64_t ret1 = op1(a.lo, a.hi, b.lo, b.hi); \
    uint64_t ret2 = op2(a.lo, a.hi, b.lo, b.hi); \
    assert(ret1 == ret2 && #op1); \
    /*printf("%s\n", #op1);*/ \
} while (0)

#define TEST44(op1, op2, a, b) do { \
    uint128 ret1 = op1(a.lo, a.hi, b.lo, b.hi); \
    uint128 ret2 = op2(a.lo, a.hi, b.lo, b.hi); \
    if (U128_0(ret1) != U128_0(ret2) || U128_1(ret1) != U128_1(ret2) || U128_2(ret1) != U128_2(ret2) || U128_3(ret1) != U128_3(ret2)) { \
        printf("%s 0x%08x%08x 0x%08x%08x -> 0x%08x%08x%08x%08x 0x%08x%08x%08x%08x\n", #op1, \
            a.hi, a.lo, b.hi, b.lo, U128_3(ret1),U128_2(ret1),U128_1(ret1),U128_0(ret1), U128_3(ret2),U128_2(ret2),U128_1(ret2),U128_0(ret2)); \
        assert(0); \
    } \
    /*printf("%s\n", #op1);*/ \
} while (0)
#else
#define TEST1(op1, op2, a)
#define TEST2(op1, op2, a, b)
#define TEST42(op1, op2, a, b)
#define TEST44(op1, op2, a, b)
#endif

static inline void out1(Context* ctx, uint32_t val) {
    Vec_push(&ctx->vars, val);
    ctx->varCount++;
}
static inline void out2(Context* ctx, uint64_t val) {
    out1(ctx, (uint32_t) val); out1(ctx, (uint32_t) (val >> 32));
}
static inline void out4(Context* ctx, uint128 val) {
    out1(ctx, U128_0(val)); out1(ctx, U128_1(val));
    out1(ctx, U128_2(val)); out1(ctx, U128_3(val));
}

static int interpret(Context* ctx, int pc);

static inline uint32_t branch(Context* ctx, uint32_t a, uint32_t insn, int pc) {
    int count = DecodeInsn_imm(insn);
    assert(count == 2);
    if (a) { return interpret(ctx, pc + count); }
    return interpret(ctx, pc+1);
}

#define uint32(x) ((uint32_t)(x))

static int interpret(Context* ctx, int pc) {
    // spacing added in RandGen
    if (pc != 0) {
        Vec_push(&ctx->vars, ~0);
        Vec_push(&ctx->scopes, ctx->varCount);
        ctx->varCount = 0;
    }

    for (;; pc++) {
        if (ctx->opCtr > Conf_RandHash_MAX_OPS) { return -1; }
        ctx->opCtr++;
        assert(pc < ctx->progLen);
        uint32_t insn = ctx->prog[pc];
        assert(DecodeInsn_OP(insn) > OpCode_INVALID_ZERO);
        assert(DecodeInsn_OP(insn) < OpCode_INVALID_BIG);
        switch (DecodeInsn_OP(insn)) {
            case OpCode_MEMORY: {
                int base = DecodeInsn_MEMORY_BASE(insn);
                int step = DecodeInsn_MEMORY_STEP(insn);
                int carry = DecodeInsn_MEMORY_CARRY(insn);
                // memory[(base + ((loopVar + carry) * step)) % RandHash_MEMORY_SZ]
                DEBUGF("MEMORY(%d, 0x%08x, %d, %d) -> %08x (%08x)\n", ctx->loopCycle, base, step, carry,
                    ctx->memory[(base + ((ctx->loopCycle + carry) * step)) & (RandHash_MEMORY_SZ - 1)],
                    ((base + ((ctx->loopCycle + carry) * step)) % RandHash_MEMORY_SZ));
                out1(ctx, ctx->memory[(base + ((ctx->loopCycle + carry) * step)) & (RandHash_MEMORY_SZ - 1)]);
                break;
            }
            case OpCode_IN: {
                //printf("// in %08x %d", ctx->hashIn[((uint32_t)DecodeInsn_imm(insn)) % RandHash_INOUT_SZ], (((uint32_t)DecodeInsn_imm(insn)) % HASH_SZ));
                int idx = ((uint32_t)DecodeInsn_imm(insn)) % RandHash_INOUT_SZ;
                DEBUGF("IN %d -> %08x\n", idx, ctx->hashIn[idx]);
                out1(ctx, ctx->hashIn[idx]);
                break;
            }
            case OpCode_LOOP: {
                DEBUGF("%s (%08x) %d\n", OP_STR[DecodeInsn_OP(insn)], insn, pc);
                int count = DecodeInsn_imm(insn);
                int ret = pc;
                for (int i = 0; i < count; i++) {
                    ctx->loopCycle = i;
                    ret = interpret(ctx, pc + 1);
                }
                if (ctx->opCtr > Conf_RandHash_MAX_OPS) { return -1; }
                pc = ret;
                if (pc == ctx->progLen - 1) {
                    assert(ctx->vars.count == 0 && ctx->scopes.count == 0 && ctx->varCount == 0);
                    return pc;
                }
                break;
            }

            case OpCode_IF_LIKELY:
                DEBUGF("%s (%08x) %d\n", OP_STR[DecodeInsn_OP(insn)], insn, pc);
                pc = branch(ctx, getA(ctx, insn) & 7, insn, pc);
                break;

            case OpCode_IF_RANDOM:
                DEBUGF("%s (%08x) %d\n", OP_STR[DecodeInsn_OP(insn)], insn, pc);
                pc = branch(ctx, getA(ctx, insn) & 1, insn, pc);
                break;

            case OpCode_JMP: {
                DEBUGF("%s (%08x) %d\n", OP_STR[DecodeInsn_OP(insn)], insn, pc);
                int count = (insn >> 8);
                pc += count;
                break;
            }

            case OpCode_END: {
                DEBUGF("%s (%08x) %d\n", OP_STR[DecodeInsn_OP(insn)], insn, pc);
                // output everything first
                assert(ctx->vars.count - ctx->varCount > 0);
                //printf("xx %d\n", ctx->vars.count);
                for (int i = ctx->vars.count - ctx->varCount; i < (int)ctx->vars.count; i++) {
                    //printf("// out1(%08x) %d\n", ctx->vars.elems[i], ctx->hashctr);
                    DEBUGF("OUTPUT %08x (%d)\n", ctx->vars.elems[i], ctx->hashctr);
                    ctx->hashOut[ctx->hashctr] += ctx->vars.elems[i];
                    ctx->hashctr = (ctx->hashctr + 1) % RandHash_INOUT_SZ;
                }
                ctx->vars.count -= ctx->varCount;
                assert(Vec_pop(&ctx->vars) == ~0u);
                ctx->varCount = Vec_pop(&ctx->scopes);
                return pc;
            }

            #define OpCodes_1_1
            #define OpCodes_VISITOR(OP) case OpCode_ ## OP : { \
                uint32_t a = getA(ctx, insn); \
                uint32_t out = OP(a); \
                DEBUGF("%s %08x -> %08x\n", #OP, a, out); \
                TEST1(optest11_ ## OP, OP, a); \
                out1(ctx, out); \
                break; }
            #include "OpCodes.h"

            #define OpCodes_2_1
            #define OpCodes_VISITOR(OP) case OpCode_ ## OP : { \
                uint32_t a = getA(ctx, insn); \
                uint32_t b = getB(ctx, insn); \
                uint32_t out = OP(a, b); \
                DEBUGF("%s %08x %08x -> %08x\n", #OP, a, b, out); \
                TEST2(optest21_ ## OP, OP, a, b); \
                out1(ctx, out); \
                break; }
            #include "OpCodes.h"

            #define OpCodes_2_2
            #define OpCodes_VISITOR(OP) case OpCode_ ## OP : { \
                uint32_t a = getA(ctx, insn); \
                uint32_t b = getB(ctx, insn); \
                uint64_t out = OP(a, b); \
                DEBUGF("%s %08x %08x -> %08x %08x\n", #OP, a, b, \
                    uint32(out & 0xffffffff), uint32(out >> 32)); \
                TEST2(optest22_ ## OP, OP, a, b); \
                out2(ctx, out); \
                break; }
            #include "OpCodes.h"

            #define OpCodes_4_2
            #define OpCodes_VISITOR(OP) case OpCode_ ## OP : { \
                Uint64 a = getA2(ctx, insn); \
                Uint64 b = getB2(ctx, insn); \
                uint64_t out = OP(a.lo, a.hi, b.lo, b.hi); \
                DEBUGF("%s %08x %08x %08x %08x -> %08x %08x\n", #OP, \
                    a.lo, a.hi, b.lo, b.hi, \
                    uint32(out & 0xffffffff), uint32(out >> 32)); \
                TEST42(optest42_ ## OP, OP, a, b); \
                out2(ctx, out); \
                break; }
            #include "OpCodes.h"

            #define OpCodes_4_4
            #define OpCodes_VISITOR(OP) case OpCode_ ## OP : { \
                Uint64 a = getA2(ctx, insn); \
                Uint64 b = getB2(ctx, insn); \
                uint128 out = OP(a.lo, a.hi, b.lo, b.hi); \
                DEBUGF("%s %08x %08x %08x %08x -> %08x %08x %08x %08x\n", #OP, \
                    a.lo, a.hi, b.lo, b.hi, \
                    U128_0(out), U128_1(out), U128_2(out), U128_3(out)); \
                TEST44(optest44_ ## OP, OP, a, b); \
                out4(ctx, out); \
                break; }
            #include "OpCodes.h"

            default: abort();
        }
    }
}

int RandHash_interpret(
    uint32_t progbuf[Conf_RandGen_MAX_INSNS],
    CryptoCycle_State_t* ccState,
    uint32_t* memory,
    int progLen,
    uint32_t memorySizeBytes,
    int cycles)
{
    assert(progLen >= 0);
    assert(memorySizeBytes >= RandHash_MEMORY_SZ * sizeof(uint32_t));
    Context _ctx; memset(&_ctx, 0, sizeof _ctx);
    Context* ctx = &_ctx;

    ctx->memory = memory;
    ctx->hashIn = ccState->sixtyfours[0].ints;
    ctx->hashOut = ccState->sixtyfours[16].ints;
    ctx->prog = progbuf;
    ctx->progLen = progLen;

    int ret = 0;

    for (int i = 0; i < cycles; i++) {
        ctx->opCtr = 0;
        interpret(ctx, 0);

        _Static_assert(!Conf_RandHash_MIN_OPS, "");
        if (ctx->opCtr > Conf_RandHash_MAX_OPS /* || ctx->opCtr < Conf_RandHash_MIN_OPS*/) {
            ret = (ctx->opCtr > Conf_RandHash_MAX_OPS) ? RandHash_TOO_LONG : RandHash_TOO_SHORT;
            break;
        }
        ctx->hashctr = 0;
        uint32_t* x = ctx->hashOut; ctx->hashOut = ctx->hashIn; ctx->hashIn = x;
    }

    Vec_free(&ctx->vars);
    Vec_free(&ctx->scopes);
    return ret;
}
