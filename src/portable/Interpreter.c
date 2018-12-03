#include "common/OpCodes.h"

#include <stdint.h>

static inline uint64_t mul_hi_plus_lo(uint64_t a, uint64_t b)
{
    uint64_t u1 = a & 0xffffffff;
    uint64_t v1 = b & 0xffffffff;
    uint64_t t = u1 * v1;
    uint64_t w3 = t & 0xffffffff;
    uint64_t k = t >> 32;

    a >>= 32;
    t = a * v1 + k;
    k = t & 0xffffffff;
    uint64_t w1 = t >> 32;

    b >>= 32;
    t = (u1 * b) + k;
    k = (t >> 32);

    // return hi + lo
    return ((a * b) + w1 + k) + ((t << 32) + w3);
}

static uint64_t bit_reverse(uint64_t val)
{
    #define ROTATE_MASK(mask, bits) \
        val = ((val >> bits) & mask) | ((val & mask) << bits)
    ROTATE_MASK(0x5555555555555555ull,  1);
    ROTATE_MASK(0x3333333333333333ull,  2);
    ROTATE_MASK(0x0F0F0F0F0F0F0F0Full,  4);
    return __builtin_bswap64(val);
    #undef ROTATE_MASK
}

#define ROTL(a,b) (((a) << (b)) | ((a) >> (64 - (b))))
static inline void interpret(uint64_t registers[8], uint16_t data)
{
    int regA = (data >> 4) & 7;
    int regB = (data >> 7) & 7;
    regA = (regA + (regA == regB)) % 8;
    unsigned long long a = registers[regA];
    unsigned long long b = registers[regB];
    switch (data & 15) {
        case OP_ADD:  b += a; break;
        case OP_SUB:  b -= a; break;
        case OP_XOR:  b ^= a; break;
        case OP_SHL:  b += (a << (data >> 10)); break;
        case OP_SHR:  b += (a >> (data >> 10)); break;
        case OP_EOR:  b += (a ^ (data >> 10)); break;
        case OP_POP:  b += __builtin_popcountll(a); break;
        case OP_CLZ:  b += __builtin_clzll(a); break;
        case OP_SWP:  b =  __builtin_bswap64(b); break;
        case OP_REV:  b =  bit_reverse(b); break;
        case OP_ROL:  b =  ROTL(b, (data >> 10)); break;
        case OP_MIL:  b += (uint64_t) ((int64_t)a * ((int64_t)b)); break;
        case OP_MUL:  b += mul_hi_plus_lo(a, b); break;
        case OP_DUV: {
            b += (b / (a | 1)) + (b % (a | 1));
            break;
        }
        case OP_DIV: {
            b += (((int64_t)b) / (((int64_t)a)|1)) + (((int64_t)b) % (((int64_t)a)|1));
            break;
        }
        case OP_CMP: {
            switch ((data >> 10) & 7) {
                case 0: b += (b < a); break;
                case 1: b += (b > a); break;
                case 2: b += ((b & 0xf) == 0); break;
                case 3: b += ((a & 0xf) == 0); break;
                case 4: b += ((b & 0xf) == (a & 0xf)); break;
                case 5: b += (((int64_t)b) < ((int64_t)a)); break;
                case 6: b += (((int64_t)a) < 0); break;
                case 7: b += (((int64_t)b) < 0); break;
            }
            break;
        }
        default:;
    }
    registers[regB] = b;
}

void Interpreter_run(uint64_t registers[8], uint16_t* program, int proglen)
{
    for (int i = 0; i < proglen; i++) { interpret(registers, program[i]); }
}

