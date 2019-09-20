/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#include "RandGen.h"
#include "Vec.h"
#include "DecodeInsn.h"
#include "Conf.h"
#include "Buf.h"
#include "RandHash.h"
#include "Hash.h"

#include "sodium/crypto_stream_chacha20.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

typedef struct {
    // Random generator
    Buf32_t randseed;
    Buf64_t randbuf;
    uint32_t nextInt;
    uint32_t ctr;

    // output
    Vec insns;

    // variables / scopes
    Vec vars;
    uint32_t scope;

    bool tooBig;
} Context;

enum OpCode {
    #define OpCodes_ALL
    #define OpCodes_VISITOR(x) OpCode_ ## x,
    #include "OpCodes.h"

    OpCode__MAX
};

enum OpType {
    OpType_1_1,
    OpType_2_1,
    OpType_2_2,
    OpType_4_2,
    OpType_4_4
};
static const int COST_BY_TYPE[] = {
    [OpType_1_1] =  1,
    [OpType_2_1] =  2,
    [OpType_2_2] =  4,
    [OpType_4_2] =  8,
    [OpType_4_4] = 16
};
static const enum OpCode CODES_1_1[] = {
    #define OpCodes_1_1
    #define OpCodes_VISITOR(x) OpCode_ ## x,
    #include "OpCodes.h"
};
static const enum OpCode CODES_2_1[] = {
    #define OpCodes_2_1
    #define OpCodes_VISITOR(x) OpCode_ ## x,
    #include "OpCodes.h"
};
static const enum OpCode CODES_2_2[] = {
    #define OpCodes_2_2
    #define OpCodes_VISITOR(x) OpCode_ ## x,
    #include "OpCodes.h"
};
static const enum OpCode CODES_4_2[] = {
    #define OpCodes_4_2
    #define OpCodes_VISITOR(x) OpCode_ ## x,
    #include "OpCodes.h"
};
static const enum OpCode CODES_4_4[] = {
    #define OpCodes_4_4
    #define OpCodes_VISITOR(x) OpCode_ ## x,
    #include "OpCodes.h"
};
#define GET_OP(list, idx) ((list)[ (idx) % (sizeof(list) / sizeof(*(list))) ])

#ifdef DEBUG
#include <stdio.h>
static void debug(Context* ctx, uint32_t insn) {
    for (int i = 0; i < (int)ctx->scope; i++) { printf(" "); }
    switch (insn & 0xff) {
        #define OpCodes_ALL
        #define OpCodes_VISITOR(x) case OpCode_ ## x : printf("%s %08x\n", #x, insn); break;
        #include "OpCodes.h"
        default: assert(0);
    }
}
#else
#define debug(a, b)
#endif

static uint32_t randu32(Context* ctx) {
    if (ctx->nextInt >= (sizeof(ctx->randbuf) / sizeof(uint32_t))) {
        Hash_expand(ctx->randbuf.bytes, sizeof(ctx->randbuf), ctx->randseed.bytes, ctx->ctr++);
        ctx->nextInt = 0;
    }
    return ctx->randbuf.ints[ctx->nextInt++];
}
static uint32_t cointoss(Context* ctx, uint32_t oneIn) { return (randu32(ctx) % oneIn) == 0; }
static int randRange(Context* ctx, int start, int end) { return randu32(ctx) % (end - start) + start; }

static int spend(uint32_t* budget, uint32_t amount) {
    if (*budget >= amount) { *budget -= amount; return true; }
    return false;
}

static void emit(Context* ctx, uint32_t insn) {
    debug(ctx, insn);
    assert((insn & 0xff) > OpCode_INVALID_ZERO);
    assert((insn & 0xff) < OpCode_INVALID_BIG);
    if (ctx->insns.count >= Conf_RandGen_MAX_INSNS) {
        ctx->tooBig = true;
        return;
    }
    Vec_push(&ctx->insns, insn);
}

static void scope(Context* ctx) { ctx->scope++; Vec_push(&ctx->vars, ~0u); }
static void end(Context* ctx) {
    emit(ctx, OpCode_END);
    ctx->scope--;
    while (Vec_pop(&ctx->vars) != ~0u) { }
}

static void mkVar(Context* ctx) { Vec_push(&ctx->vars, 0); }


static int _getVar(Context* ctx, bool dbl) {
    int eof = ctx->vars.count;
    int bof = eof - 1;
    for (; bof >= 0; bof--) {
        if (ctx->vars.elems[bof] != ~0u) { continue; }
        // only 1 var in this frame and we're looking for dword, continue looking
        if (dbl) {
            if (bof >= eof - 2) { goto nextFrame; }
        } else {
            // no vars in this frame, continue looking
            if (bof >= eof - 1) { goto nextFrame; }
        }
        // end of the line, this is tested after because first frame should always have 4 vars.
        if (!bof) { break; }
        // walk up to a higher scope
        if (!cointoss(ctx, Conf_RandGen_HIGHER_SCOPE_LIKELYHOOD)) { break; }
    nextFrame:
        eof = bof;
    }
    //printf("%d %d - %d [%08x]\n", bof, eof, dbl, ctx->vars.elems[0]);
    assert(bof >= 0);
    int start = randRange(ctx, bof + 1, eof);
    //printf("%d %d %d - %d\n", bof, eof, start, dbl);
    for (int j = start + 1;; j++) {
        if (j >= eof) { j = bof + 1; }
        //printf("%08x %d\n", ctx->vars.elems[j], j);
        if ((!dbl || (j > bof + 1)) && cointoss(ctx, Conf_RandGen_VAR_REUSE_LIKELYHOOD)) {
            //printf("reuse\n");
            return j;
        } else if (!(ctx->vars.elems[j] & 1)) {
            if (!dbl || !(ctx->vars.elems[j-1] & 1)) { return j; }
        }
    }
}
static int getVar(Context* ctx, bool dbl) {
    int out = _getVar(ctx, dbl);
    assert(out < (int)ctx->vars.count);
    assert(out >= 0);
    //printf("%08x %d <\n", ctx->vars.elems[out], out);
    assert(ctx->vars.elems[out] != ~0u);
    ctx->vars.elems[out] |= 1;
    if (dbl) {
        assert(out > 0);
        assert(ctx->vars.elems[out-1] != ~0u);
        ctx->vars.elems[out-1] |= 1;
    }
    return out;
}
static uint32_t getA(Context* ctx, bool dbl) { return ((uint32_t) getVar(ctx, dbl)) << 9; }
static uint32_t getB(Context* ctx, bool dbl) {
    if (cointoss(ctx, Conf_RandGen_IMMEDIATE_LIKELYHOOD)) {
        return (randu32(ctx) << 20) | (1 << 18);
    } else {
        return ((uint32_t) getVar(ctx, dbl)) << 20;
    }
}

static bool op(Context* ctx, enum OpType type, uint32_t* budget) {
    uint32_t rand = randu32(ctx);
    if (!spend(budget, COST_BY_TYPE[type])) { return false; }
    switch (type) {
        case OpType_1_1: {
            emit(ctx, GET_OP(CODES_1_1, rand) | getA(ctx, false));
            mkVar(ctx);
            break;
        }
        case OpType_2_1: {
            emit(ctx, GET_OP(CODES_2_1, rand) | getA(ctx, false) | getB(ctx, false));
            mkVar(ctx);
            break;
        }
        case OpType_2_2: {
            emit(ctx, GET_OP(CODES_2_2, rand) | getA(ctx, false) | getB(ctx, false));
            mkVar(ctx); mkVar(ctx);
            break;
        }
        case OpType_4_2: {
            emit(ctx, GET_OP(CODES_4_2, rand) | getA(ctx, true) | getB(ctx, true));
            mkVar(ctx); mkVar(ctx);
            break;
        }
        case OpType_4_4: {
            emit(ctx, GET_OP(CODES_4_4, rand) | getA(ctx, true) | getB(ctx, true));
            mkVar(ctx); mkVar(ctx); mkVar(ctx); mkVar(ctx);
            break;
        }
    }
    return true;
}

static bool input(Context* ctx, uint32_t* budget) {
    if (!spend(budget, Conf_RandGen_INPUT_COST)) { return false; }
    mkVar(ctx);
    emit(ctx, (randu32(ctx) << 8) | OpCode_IN);
    return true;
}

static int body(Context* ctx, uint32_t* budget, bool createScope);

static bool branch(Context* ctx, uint32_t* budget) {
    if (!spend(budget, Conf_RandGen_BRANCH_COST)) { return false; }
    uint32_t op = cointoss(ctx, Conf_RandGen_RANDOM_BRANCH_LIKELYHOOD) ? OpCode_IF_RANDOM : OpCode_IF_LIKELY;

    emit(ctx, getA(ctx, false) | op | (2<<20));
    uint32_t j1 = ctx->insns.count; emit(ctx, OpCode_JMP);

    uint32_t b1 = Conf_RandGen_IF_BODY_BUDGET(*budget, ctx->scope);
    body(ctx, &b1, true);

    uint32_t j2 = ctx->insns.count; emit(ctx, OpCode_JMP);

    uint32_t b2 = Conf_RandGen_IF_BODY_BUDGET(*budget, ctx->scope);
    body(ctx, &b2, true);

    assert((j2 - j1) < (1<<23));
    assert((ctx->insns.count - j2) < (1<<23));

    // Now we fill in the first jmp
    ctx->insns.elems[j1] = ((j2 - j1) << 8) | OpCode_JMP;

    // and then the else jmp
    ctx->insns.elems[j2] = ((ctx->insns.count - j2 - 1) << 8) | OpCode_JMP;
    return true;
}

static int loop(Context* ctx, uint32_t* budget) {
    uint32_t loopLen   = randRange(ctx, Conf_RandGen_LOOP_MIN_CYCLES, Conf_RandGen_LOOP_MAX_CYCLES(ctx->scope));
    // this must be at least 2
    int numMemAcc = randRange(ctx, 2, 4);

    if (*budget < (Conf_RandGen_MEMORY_COST * loopLen)) { return 0; }
    *budget /= loopLen;
    emit(ctx, (loopLen << 20) | OpCode_LOOP);
    scope(ctx);

    uint32_t memTemplate = (randu32(ctx) << 8) | OpCode_MEMORY;
    for (int i = 0; i < numMemAcc; i++) {
        if (!spend(budget, Conf_RandGen_MEMORY_COST)) { break; }
        mkVar(ctx);
        emit(ctx, DecodeInsn_MEMORY_WITH_CARRY(memTemplate, randu32(ctx)));
    }
    int ret = body(ctx, budget, false);
    end(ctx);
    return ret;
}

static int body(Context* ctx, uint32_t* budget, bool createScope) {
    if (createScope) { scope(ctx); }
    for (;;) {
        if (ctx->insns.count > Conf_RandGen_MAX_INSNS) { goto out; }
        int max = randRange(ctx, 2, 12);
        for (int i = 1; i <= max; i++) {
            if (cointoss(ctx, 4 * max / i) && op(ctx, OpType_4_4, budget)) { continue; }
            if (cointoss(ctx, 3 * max / i) && op(ctx, OpType_4_2, budget)) { continue; }
            if (cointoss(ctx, 3 * max / i) && op(ctx, OpType_2_2, budget)) { continue; }
            if (cointoss(ctx, 2 * max / i) && op(ctx, OpType_2_1, budget)) { continue; }
            if (cointoss(ctx, 1 * i)       && input(ctx, budget)         ) { continue; }
            if (                              op(ctx, OpType_1_1, budget)) { continue; }
            goto out;
        }
        if (Conf_RandGen_SHOULD_BRANCH(randu32(ctx), ctx->insns.count) && !branch(ctx, budget)) { goto out; }
        if (Conf_RandGen_SHOULD_LOOP(randu32(ctx)) && !loop(ctx, budget))   { goto out; }
    }
out:
    if (createScope) { end(ctx); }
    return false;
}

int RandGen_generate(uint32_t buf[static Conf_RandGen_MAX_INSNS], Buf32_t* seed)
{
    uint32_t budget = Conf_RandGen_INITIAL_BUDGET;
    Context ctx; memset(&ctx, 0, sizeof ctx);
    _Static_assert(sizeof ctx.randseed == sizeof *seed, "");
    memcpy(ctx.randseed.bytes, seed->bytes, sizeof ctx.randseed);
    ctx.nextInt = -1;
    ctx.insns.max = Conf_RandGen_MAX_INSNS;
    ctx.insns.elems = buf;

    loop(&ctx, &budget);

    Vec_free(&ctx.vars);

    _Static_assert(!Conf_RandGen_MIN_INSNS, "");
    if (ctx.tooBig) { return RandHash_TOO_BIG; }
    #if Conf_RandGen_MIN_INSNS > 0
    if (ctx.insns.count < Conf_RandGen_MIN_INSNS) { return RandHash_TOO_SMALL; }
    #endif

    return ctx.insns.count;
}
