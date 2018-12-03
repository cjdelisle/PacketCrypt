#include <stdint.h>
#include <assert.h>
#include <string.h>

#include "common/Writer.h"
#include "common/OpCodes.h"

// Register numbers
#define RDI 0
#define RSI 1
#define R12 2
#define RCX 3
#define R8  4
#define R9  5
#define R10 6
#define R11 7

// Used as scratch registers, not part of the 8
#define RDX 8
#define R13 9
#define RAX 10
#define R14 11

// Encode register into amd64 instruction
#define REGISTER_LOWER(r) \
    ((((7<<0) | (6<<3) | (4<<6) | (1<<9) | (0<<12) | (1<<15) | (2<<18) | \
        (3<<21) | (2<<24) | (5<<27) | (0<<30) | (6ull<<33)) >> (r*3)) & 7)
#define REGISTER_UPPER(r) \
    ((((0<<0) | (0<<1) | (1<<2) | (0<<3) | (1<<4) | (1<<5) | (1<<6) | \
        (1<<7) | (0<<8) | (1<<9) | (0<<10) | (1<<11)) >> r) & 1)
#define ENCODE_REGISTER(r, ushift, lshift) \
    ((REGISTER_UPPER(r) << ushift) | (REGISTER_LOWER(r) << lshift))

// amd64 instruction templates
#define _ADDQ 0x4801c0
#define _SUBQ 0x4829c0
#define _ORQ  0x4809c0
#define _ANDQ 0x4821c0
#define _XORQ 0x4831c0
#define _POPCNT 0xf3480fb8c0ull
#define _BSWAPQ 0x480fc8
#define _IMULQ 0x480fafc0
#define _LZCNT 0xf3480fbdc0
#define _ROLQ 0x48c1c000
#define _MULQ 0x48f7e0
#define _DIVQ 0x48f7f0
#define _IDIV 0x48f7f8
#define _ORI  0x4883c800
#define _XORI 0x4883f000
#define _SHRI 0x48c1e800
#define _SHLI 0x48c1e000
#define _MOV 0x4889c0
#define _CQTO 0x4899
#define _MOVI64 0x48b8
#define _CMP 0x4839c0
#define _SETB 0x0f92c0
#define _SETA 0x0f97c0
#define _SETE 0x0f94c0
#define _SETL 0x0f9cc0
#define _DEC 0x48ffc8
#define _JNZ 0x0f8500000000ull

// instruction mapping table, just for ops that use it
static const uint64_t INSN_TABLE[] = {
    [OP_ADD] =   _ADDQ,
    [OP_SUB] =   _SUBQ,
    [OP_XOR] =   _XORQ,
    [OP_POP] =   _POPCNT,
    [OP_CLZ] =   _LZCNT,
    [OP_DUV] =   _DIVQ,
    [OP_DIV] =   _IDIV,
    [OP_SHR] =   _SHRI,
    [OP_SHL] =   _SHLI,
};

// Abbreviation
static inline void op(struct Writer* w, struct Writer_Insn insn)
{
    Writer_op(w, insn);
}

#define INSN(d, w) ((struct Writer_Insn) { .data = d, .width = w })

#define CQTO() INSN(_CQTO, 2)

#define THREE_BYTE_INSN(template, a, b) \
    INSN((template | ENCODE_REGISTER((b), 16, 0) | ENCODE_REGISTER((a), 18, 3)), 3)
#define ANDQ(a,b) THREE_BYTE_INSN(_ANDQ,a,b)
#define ORQ(a,b)  THREE_BYTE_INSN(_ORQ,a,b)
#define XORQ(a,b) THREE_BYTE_INSN(_XORQ,a,b)
#define ADDQ(a,b) THREE_BYTE_INSN(_ADDQ,a,b)
#define MOV(a,b)  THREE_BYTE_INSN(_MOV,a,b)
#define CMP(a,b)  THREE_BYTE_INSN(_CMP,a,b)

// %rax encodes as all zeros so a one-arg 3 byte instruction is same 
#define THREE_BYTE_1ARG(template, a) THREE_BYTE_INSN(template,RAX,a)
#define MULQ(a)   THREE_BYTE_1ARG(_MULQ,a)
#define BSWAPQ(a) THREE_BYTE_1ARG(_BSWAPQ,a)
#define DEC(a)    THREE_BYTE_1ARG(_DEC,a)

#define FOUR_BYTE_IMMEDIATE(template, a, imm) \
    INSN((template | ENCODE_REGISTER((a), 24, 8) | (imm)), 4)
#define ROLQ(a, bits) FOUR_BYTE_IMMEDIATE(_ROLQ, a, bits)
#define ORI(a, bits)  FOUR_BYTE_IMMEDIATE(_ORI, a, bits)
#define XORI(a, bits)  FOUR_BYTE_IMMEDIATE(_XORI, a, bits)
#define SHRI(a, bits)  FOUR_BYTE_IMMEDIATE(_SHRI, a, bits)
#define SHLI(a, bits)  FOUR_BYTE_IMMEDIATE(_SHLI, a, bits)

#define MOVI64(a) INSN(_MOVI64 | ENCODE_REGISTER((a), 8, 0), 2)
#define JNZ(offset) INSN(_JNZ | ((uint64_t)offset), 6)

#define TAKE(data, bits) (data & ((1<<bits)-1)); data >>= bits
static inline void to_native_insn(struct Writer* w, uint16_t data)
{
    int insn = TAKE(data, 4);
    int regA = TAKE(data, 3);
    int regB = TAKE(data, 3);
    regA = (regA + (regA == regB)) % 8;
    switch (insn) {
        case OP_ADD:
        case OP_SUB:
        case OP_XOR: {
            op(w, THREE_BYTE_INSN(INSN_TABLE[insn], regA, regB));
            break;
        }

        case OP_SHL:
        case OP_SHR: {
            int bits = TAKE(data, 6);
            op(w, MOV(regA, RAX));
            op(w, FOUR_BYTE_IMMEDIATE(INSN_TABLE[insn], RAX, bits));
            op(w, ADDQ(RAX, regB));
            break;
        }

        case OP_EOR: {
            int bits = TAKE(data, 6);
            op(w, MOV(regA, RAX));
            op(w, XORI(RAX, bits));
            op(w, ADDQ(RAX, regB));
            break;
        }
    

        case OP_POP:
        case OP_CLZ: {
            op(w, INSN(INSN_TABLE[insn] | ENCODE_REGISTER(regA, 24, 0), 5));
            op(w, ADDQ(RAX, regB));
            break;
        }
    
        case OP_SWP: {
            op(w, BSWAPQ(regB));
            break;
        }

        case OP_REV: {
            struct { uint64_t mask; int bits; } masks[3] = {
                { .mask = 0x5555555555555555ull, .bits = 1},
                { .mask = 0x3333333333333333ull, .bits = 2},
                { .mask = 0x0F0F0F0F0F0F0F0Full, .bits = 4},
            };
            for (int i = 0; i < 3; i++) {
                op(w, MOVI64(R13)); op(w, INSN(masks[i].mask, 8));

                op(w, MOV(regB, RAX));
                op(w, SHRI(RAX, masks[i].bits));
                op(w, ANDQ(R13, RAX));

                op(w, MOV(regB, RDX));
                op(w, ANDQ(R13, RDX));
                op(w, SHLI(RDX, masks[i].bits));

                op(w, MOV(RAX, regB));
                op(w, ORQ(RDX, regB));
            }
            op(w, BSWAPQ(regB));
            break;
        }

        case OP_ROL: {
            int bits = TAKE(data, 6);
            op(w, ROLQ(regB, bits));
            break;
        }

        case OP_MIL:
        case OP_MUL:
        {
            op(w, MOV(regB, RAX));
            if (insn == OP_MIL) {
                op(w, INSN(_IMULQ | ENCODE_REGISTER(regA, 24, 0), 4));
            } else {
                op(w, MULQ(regA));
                op(w, ADDQ(RDX, RAX));
            }
            op(w, ADDQ(RAX, regB));
            break;
        }

        case OP_DUV:
        case OP_DIV:
        {
            op(w, MOV(regB, RAX));
            op(w, MOV(regA, R13));
            if (insn == OP_DUV) {
                op(w, XORQ(RDX, RDX));
            } else {
                op(w, CQTO());
            }
            op(w, ORI(R13, 1));
            op(w, THREE_BYTE_1ARG(INSN_TABLE[insn], R13));
            op(w, ADDQ(RAX, regB));
            op(w, ADDQ(RDX, regB));
            break;
        }

        //   b += (b < a); break;
        case OP_CMP: {
            int type = TAKE(data, 3);
            op(w, XORQ(RAX, RAX));
            switch (type) {
                case 0: {
                    // (b < a)
                    op(w, CMP(regA, regB));
                    op(w, INSN(_SETB, 3));
                    break;
                }

                case 1: {
                    // (b > a)
                    op(w, CMP(regA, regB));
                    op(w, INSN(_SETA, 3));
                    break;
                }

                case 2: // (b & 0xf) == 0
                case 3: // (a & 0xf) == 0
                case 4: // (b & 0xf) == (a & 0xf)
                {
                    int a = RAX;
                    int b = RAX;
                    if (type != 3) {
                        op(w, MOV(regB, RDX));
                        op(w, SHLI(RDX, 60));
                        a = RDX;
                    }
                    if (type != 2) {
                        op(w, MOV(regA, R13));
                        op(w, SHLI(R13, 60));
                        b = R13;
                    }
                    op(w, CMP(a, b));
                    op(w, INSN(_SETE, 3));
                    break;
                }

                case 5: {
                    // ((int64_t)b) < ((int64_t)a)
                    op(w, CMP(regA, regB));
                    op(w, INSN(_SETL, 3));
                    break;
                }

                case 6: {
                    // ((int64_t)a) < 0
                    op(w, CMP(RAX, regA));
                    op(w, INSN(_SETL, 3));
                    break;
                }

                case 7: {
                    // ((int64_t)b) < 0
                    op(w, CMP(RAX, regB));
                    op(w, INSN(_SETL, 3));
                    break;
                }
            }
            op(w, ADDQ(RAX, regB));
        }
    }
}

void Codegen_generate(struct Writer* w, uint16_t* program, int length)
{
    uint32_t jmp = w->offset;
    for (int i = 0; i < length; i++) { to_native_insn(w, program[i]); }
    op(w, DEC(R14));
    jmp -= w->offset;
    // need to subtract 6 for the width of the jnz
    jmp -= 6;
    jmp = __builtin_bswap32(jmp);
    op(w, JNZ(jmp));
}