#include <stdint.h>
#include <stdlib.h>

#include "Constants.h"
#include "Vec.h"
#include "OpTemplate.h"
#include "DecodeInsn.h"

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
    uint64_t maxOps;

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

//#define DEBUG
#ifdef DEBUG
#include <stdio.h>
static const char* OP_STR[] = {
    #define OpCodes_ALL
    #define OpCodes_VISITOR(x) [OpCode_ ## x] = #x,
    #include "OpCodes.h"
};
#undef DEBUGF
#define DEBUGF(fmt, ...) do { \
    for (int i = 0; i < ctx->scopes.count; i++) { printf("  "); }   \
    printf("// ");                                                  \
    printf(fmt, __VA_ARGS__);                                       \
} while (0)
#endif

static inline void out1(Context* ctx, uint32_t val) {
    Vec_push(&ctx->vars, val);
    ctx->varCount++;
}
static inline void out2(Context* ctx, uint64_t val) {
    out1(ctx, (uint32_t) val); out1(ctx, (uint32_t) (val >> 32));
}
static inline void out4(Context* ctx, uint128 val) {
    out1(ctx, val.ints[0]); out1(ctx, val.ints[1]);
    out1(ctx, val.ints[2]); out1(ctx, val.ints[3]);
}

static int interpret(Context* ctx, int pc);

static inline uint32_t branch(Context* ctx, uint32_t a, uint32_t insn, int pc) {
    int count = DecodeInsn_imm(insn);
    assert(count == 2);
    if (a) { return interpret(ctx, pc + count); }
    return interpret(ctx, pc+1);
}

static int interpret(Context* ctx, int pc) {
    // spacing added in RandGen
    if (pc != 0) {
        Vec_push(&ctx->vars, ~0);
        Vec_push(&ctx->scopes, ctx->varCount);
        ctx->varCount = 0;
    }

    for (;; pc++) {
        if (ctx->opCtr > ctx->maxOps) { return 0; }
        ctx->opCtr++;
        assert(pc < ctx->progLen);
        uint32_t insn = ctx->prog[pc];
        assert(DecodeInsn_OP(insn) > OpCode_INVALID_ZERO);
        assert(DecodeInsn_OP(insn) < OpCode_INVALID_BIG);
        DEBUGF("%s (%08x) %d\n", OP_STR[DecodeInsn_OP(insn)], insn, pc);
        switch (DecodeInsn_OP(insn)) {
            case OpCode_MEMORY: {
                int base = DecodeInsn_MEMORY_BASE(insn);
                int step = DecodeInsn_MEMORY_STEP(insn);
                int carry = DecodeInsn_MEMORY_CARRY(insn);
                // memory[(base + ((loopVar + carry) * step)) % MEMORY_SZ]
                DEBUGF("MEMORY(%d, 0x%08x, %d, %d) -> %08x (%08x)\n", ctx->loopCycle, base, step, carry,
                    ctx->memory[(base + ((ctx->loopCycle + carry) * step)) & (MEMORY_SZ - 1)],
                    ((base + ((ctx->loopCycle + carry) * step)) % MEMORY_SZ));
                out1(ctx, ctx->memory[(base + ((ctx->loopCycle + carry) * step)) & (MEMORY_SZ - 1)]);
                break;
            }
            case OpCode_IN: {
                //printf("// in %08x %d", ctx->hashIn[((uint32_t)DecodeInsn_imm(insn)) % HASH_SZ], (((uint32_t)DecodeInsn_imm(insn)) % HASH_SZ));
                out1(ctx, ctx->hashIn[((uint32_t)DecodeInsn_imm(insn)) % HASH_SZ]);
                break;
            }
            case OpCode_LOOP: {
                int count = DecodeInsn_imm(insn);
                int ret = pc;
                for (int i = 0; i < count; i++) {
                    ctx->loopCycle = i;
                    ret = interpret(ctx, pc + 1);
                }
                pc = ret;
                if (pc == ctx->progLen - 1) {
                    assert(ctx->vars.count == 0 && ctx->scopes.count == 0 && ctx->varCount == 0);
                    return pc;
                }
                break;
            }

            case OpCode_IF_LIKELY: pc = branch(ctx, getA(ctx, insn) & 7, insn, pc); break;
            case OpCode_IF_RANDOM: pc = branch(ctx, getA(ctx, insn) & 1, insn, pc); break;

            case OpCode_JMP: {
                int count = (insn >> 8);
                pc += count;
                break;
            }

            case OpCode_END: {
                // output everything first
                assert(ctx->vars.count - ctx->varCount > 0);
                //printf("xx %d\n", ctx->vars.count);
                for (int i = ctx->vars.count - ctx->varCount; i < (int)ctx->vars.count; i++) {
                    //printf("// out1(%08x) %d\n", ctx->vars.elems[i], ctx->hashctr);
                    DEBUGF("out1 %08x (%d)\n", ctx->vars.elems[i], ctx->hashctr);
                    ctx->hashOut[ctx->hashctr] += ctx->vars.elems[i];
                    ctx->hashctr = (ctx->hashctr + 1) % HASH_SZ;
                }
                ctx->vars.count -= ctx->varCount;
                assert(Vec_pop(&ctx->vars) == ~0u);
                ctx->varCount = Vec_pop(&ctx->scopes);
                return pc;
            }

            #define OpCodes_1_1
            #define OpCodes_VISITOR(OP) case OpCode_ ## OP : \
                DEBUGF("%s %08x -> %08x\n", #OP, getA(ctx, insn), OP(getA(ctx, insn))); \
                out1(ctx, OP(getA(ctx, insn))); break;
            #include "OpCodes.h"

            #define OpCodes_2_1
            #define OpCodes_VISITOR(OP) case OpCode_ ## OP : \
                DEBUGF("%s %08x %08x\n", #OP, getA(ctx, insn), getB(ctx, insn)); \
                out1(ctx, OP(getA(ctx, insn), getB(ctx, insn))); break;
            #include "OpCodes.h"

            #define OpCodes_2_2
            #define OpCodes_VISITOR(OP) case OpCode_ ## OP : \
                DEBUGF("%s %08x %08x\n", #OP, getA(ctx, insn), getB(ctx, insn)); \
                out2(ctx, OP(getA(ctx, insn), getB(ctx, insn))); break;
            #include "OpCodes.h"

            #define OpCodes_4_2
            #define OpCodes_VISITOR(OP) case OpCode_ ## OP : { \
                Uint64 a = getA2(ctx, insn); Uint64 b = getB2(ctx, insn); \
                DEBUGF("%s %08x %08x %08x %08x\n", #OP, a.lo, a.hi, b.lo, b.hi); \
                out2(ctx, OP(a.lo, a.hi, b.lo, b.hi)); break; }
            #include "OpCodes.h"

            #define OpCodes_4_4
            #define OpCodes_VISITOR(OP) case OpCode_ ## OP : { \
                Uint64 a = getA2(ctx, insn); Uint64 b = getB2(ctx, insn); \
                DEBUGF("%s %08x %08x %08x %08x\n", #OP, a.lo, a.hi, b.lo, b.hi); \
                out4(ctx, OP(a.lo, a.hi, b.lo, b.hi)); break; }
            #include "OpCodes.h"

            default: abort();
        }
    }
}

int Interpreter_run(
    uint32_t* prog, int progLen,
    uint32_t* hashOut, uint32_t* hashIn, uint32_t* memory, int cycles, int maxOps)
{
    Context ctx = {
        .memory = memory,
        .hashIn = hashIn,
        .hashOut = hashOut,

        .prog = prog,
        .progLen = progLen,
        .maxOps = maxOps
    };
    ctx.maxOps *= cycles;
    for (int i = 0; i < cycles; i++) {
        interpret(&ctx, 0);
        ctx.hashctr = 0;
        uint32_t* x = ctx.hashOut; ctx.hashOut = ctx.hashIn; ctx.hashIn = x;
    }
    return ctx.opCtr / cycles;
}
