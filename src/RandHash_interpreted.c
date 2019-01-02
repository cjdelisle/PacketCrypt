#include "Conf.h"
#include "RandHash.h"
#include "Vec.h"
#include "OpTemplate.h"
#include "DecodeInsn.h"
#include "RandGen.h"
#include "Buf.h"

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
        if (ctx->opCtr > Conf_RandHash_MAX_OPS) { return -1; }
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
                // memory[(base + ((loopVar + carry) * step)) % RandHash_MEMORY_SZ]
                DEBUGF("MEMORY(%d, 0x%08x, %d, %d) -> %08x (%08x)\n", ctx->loopCycle, base, step, carry,
                    ctx->memory[(base + ((ctx->loopCycle + carry) * step)) & (RandHash_MEMORY_SZ - 1)],
                    ((base + ((ctx->loopCycle + carry) * step)) % RandHash_MEMORY_SZ));
                out1(ctx, ctx->memory[(base + ((ctx->loopCycle + carry) * step)) & (RandHash_MEMORY_SZ - 1)]);
                break;
            }
            case OpCode_IN: {
                //printf("// in %08x %d", ctx->hashIn[((uint32_t)DecodeInsn_imm(insn)) % RandHash_INOUT_SZ], (((uint32_t)DecodeInsn_imm(insn)) % HASH_SZ));
                out1(ctx, ctx->hashIn[((uint32_t)DecodeInsn_imm(insn)) % RandHash_INOUT_SZ]);
                break;
            }
            case OpCode_LOOP: {
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
                    ctx->hashctr = (ctx->hashctr + 1) % RandHash_INOUT_SZ;
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

struct RandHash_Compiled_s {
    RandHash_Program_t* programs;
    int count;
};

RandHash_Compiled_t* RandHash_compile_interpreted(RandHash_Program_t* progs, int count) {
    RandHash_Compiled_t* out = malloc(sizeof(RandHash_Compiled_t));
    assert(out);
    out->programs = progs;
    out->count = count;
    return out;
}

void RandHash_freeProgram_interpreted(RandHash_Compiled_t* prog) { free(prog); }

int RandHash_interpret(
    RandHash_Program_t* prog,
    Buf64_t* hash,
    uint32_t* memory,
    uint32_t memorySizeBytes,
    int cycles)
{
    assert(memorySizeBytes >= RandHash_MEMORY_SZ * sizeof(uint32_t));
    Context _ctx; memset(&_ctx, 0, sizeof _ctx);
    Context* ctx = &_ctx;

    ctx->memory = memory;
    ctx->hashIn = hash->thirtytwos[0].ints;
    ctx->hashOut = hash->thirtytwos[1].ints;
    ctx->prog = prog->insns;
    ctx->progLen = prog->len;

    for (int i = 0; i < cycles; i++) {
        ctx->opCtr = 0;
        interpret(ctx, 0);
        _Static_assert(!Conf_RandHash_MIN_OPS, "");
        if (ctx->opCtr > Conf_RandHash_MAX_OPS /* || ctx->opCtr < Conf_RandHash_MIN_OPS*/) {
            return (ctx->opCtr > Conf_RandHash_MAX_OPS) ? RandHash_TOO_LONG : RandHash_TOO_SHORT;
        }
        ctx->hashctr = 0;
        uint32_t* x = ctx->hashOut; ctx->hashOut = ctx->hashIn; ctx->hashIn = x;
    }
    return 0;
}

int RandHash_execute_interpreted(
    RandHash_Compiled_t* progs,
    int progNum,
    Buf64_t* hash,
    uint32_t* memory,
    uint32_t memorySizeBytes,
    int cycles)
{
    return RandHash_interpret(&progs->programs[progNum], hash, memory, memorySizeBytes, cycles);
}
