/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#include <stdint.h>

#define MKOP_64x(rett, name, impl) \
    static inline rett name(uint32_t a0, uint32_t a1, uint32_t b0, uint32_t b1) {       \
        uint64_t a = a1; a <<= 32; a |= a0;                                             \
        uint64_t b = b1; b <<= 32; b |= b0;                                             \
        return impl(a, b);                                                              \
    }

#define MKOP_64(name, impl)  MKOP_64x(uint64_t, name, impl)
#define MKOP_64C(name, impl) MKOP_64x(uint128,  name, impl)

#define MKOP_32(name, impl) \
    static inline uint32_t name(uint32_t a, uint32_t b) { return impl(a, b); }

#define MKOP_16(name, impl) \
    static inline uint32_t name(uint32_t a, uint32_t b) { \
        return                                                                      \
            ((uint32_t)impl( ((uint16_t)(a>>16)),  ((uint16_t)(b>>16)) ) << 16) |   \
             impl( ((uint16_t)a), ((uint16_t) b) );                                 \
    }

#define MKOP_8(name, impl) \
    static inline uint16_t name ## _16(uint16_t a, uint16_t b) { \
        return                                                                      \
            ((uint16_t)impl( ((uint8_t)(a>>8)),  ((uint8_t)(b>>8)) ) << 8) |        \
             impl( ((uint8_t)a), ((uint8_t) b) );                                   \
    }                                                                               \
    MKOP_16(name, name ## _16)

#define MKOP_32C(name, impl) \
    static inline uint64_t name(uint32_t a, uint32_t b) { return impl(a, b); }

#define MKOP_16C(name, impl) \
    static inline uint64_t name(uint32_t a, uint32_t b) { \
        return                                                                      \
            ((uint64_t)impl( ((uint16_t)(a>>16)),  ((uint16_t)(b>>16)) ) << 32) |   \
             impl( ((uint16_t)a), ((uint16_t) b) );                                 \
    }

#define MKOP_8C(name, impl) \
    static inline uint32_t name ## _16C(uint16_t a, uint16_t b) { \
        return                                                                      \
            ((uint32_t)impl( ((uint8_t)(a>>8)),  ((uint8_t)(b>>8)) ) << 16) |       \
             impl( ((uint8_t)a), ((uint8_t) b) );                                   \
    }                                                                               \
    MKOP_16C(name, name ## _16C)

// 8 bit
#define FOP(name) static inline uint8_t name ## 8(uint8_t a, uint8_t b)
#define MKOP(NAME, name) MKOP_8(NAME ## 8, name ## 8)
FOP(add)    { return a + b; } MKOP(ADD, add)
FOP(sub)    { return a - b; } MKOP(SUB, sub)

FOP(shll)   { return a << (b & 7); } MKOP(SHLL, shll)
FOP(shrl)   { return a >> (b & 7); } MKOP(SHRL, shrl)
FOP(shra)   { return (uint8_t)(((int8_t)a) >> (b & 7)); } MKOP(SHRA, shra)
FOP(rotl)   { return shll8(a, b) | shrl8(a, 8 - b); } MKOP(ROTL, rotl)
FOP(rotr)   { return shll8(a, 8 - b) | shrl8(a, b); } MKOP(ROTR, rotr)

FOP(mul)    { return a * b; } MKOP(MUL, mul)
#undef FOP
#undef MKOP

// 8 bit carry
#define FOP(name) static inline uint16_t name ## 8C (uint8_t a, uint8_t b)
#define MKOP(NAME, name) MKOP_8C(NAME ## 8C, name ## 8C)
FOP(add)    { return (uint16_t)a + b; } MKOP(ADD, add)
FOP(sub)    { return (uint16_t)a - b; } MKOP(SUB, sub)

FOP(mul)    { return (int16_t)(int8_t)a * (int16_t)(int8_t)b; } MKOP(MUL, mul)
FOP(mulsu)  { return (int16_t)(int8_t)a * b; } MKOP(MULSU, mulsu)
FOP(mulu)   { return (uint16_t)a * b; } MKOP(MULU, mulu)
#undef FOP
#undef MKOP

// 16 bit
#define FOP(name) static inline uint16_t name ## 16 (uint16_t a, uint16_t b)
#define MKOP(NAME, name) MKOP_16(NAME ## 16, name ## 16)
FOP(add)    { return a + b; } MKOP(ADD, add)
FOP(sub)    { return a - b; } MKOP(SUB, sub)

FOP(shll)   { return a << (b & 15); } MKOP(SHLL, shll)
FOP(shrl)   { return a >> (b & 15); } MKOP(SHRL, shrl)
FOP(shra)   { return (uint16_t)(((int16_t)a) >> (b & 15)); } MKOP(SHRA, shra)
FOP(rotl)   { return shll16(a, b) | shrl16(a, 16 - b); } MKOP(ROTL, rotl)
FOP(rotr)   { return shll16(a, 16 - b) | shrl16(a, b); } MKOP(ROTR, rotr)

FOP(mul)    { return a * b; } MKOP(MUL, mul)
#undef FOP
#undef MKOP

// 16 bit carry
#define FOP(name) static inline uint32_t name ## 16C (uint16_t a, uint16_t b)
#define MKOP(NAME, name) MKOP_16C(NAME ## 16C, name ## 16C)
FOP(add)    { return (uint32_t)a + b; } MKOP(ADD, add)
FOP(sub)    { return (uint32_t)a - b; } MKOP(SUB, sub)

FOP(mul)    { return (int32_t)(int16_t)a * (int32_t)(int16_t)b; } MKOP(MUL, mul)
FOP(mulsu)  { return (int32_t)(int16_t)a * b; } MKOP(MULSU, mulsu)
FOP(mulu)   { return (uint32_t)a * b; } MKOP(MULU, mulu)
#undef FOP
#undef MKOP

// 32 bit
#define FOP(name) static inline uint32_t name ## 32 (uint32_t a, uint32_t b)
#define MKOP(NAME, name) MKOP_32(NAME ## 32, name ## 32)
FOP(add)    { return a + b; } MKOP(ADD, add)
FOP(sub)    { return a - b; } MKOP(SUB, sub)

FOP(shll)   { return a << (b & 31); } MKOP(SHLL, shll)
FOP(shrl)   { return a >> (b & 31); } MKOP(SHRL, shrl)
FOP(shra)   { return (uint32_t)(((int32_t)a) >> (b & 31)); } MKOP(SHRA, shra)
FOP(rotl)   { return shll32(a, b) | shrl32(a, 32 - b); } MKOP(ROTL, rotl)
FOP(rotr)   { return shll32(a, 32 - b) | shrl32(a, b); } MKOP(ROTR, rotr)

FOP(mul)    { return a * b; } MKOP(MUL, mul)
#undef FOP
#undef MKOP

// 32 bit carry
#define FOP(name) static inline uint64_t name ## 32C (uint32_t a, uint32_t b)
#define MKOP(NAME, name) MKOP_32C(NAME ## 32C, name ## 32C)
FOP(add)    { return (uint64_t)a + b; } MKOP(ADD, add)
FOP(sub)    { return (uint64_t)a - b; } MKOP(SUB, sub)

FOP(mul)    { return (int64_t)(int32_t)a * (int64_t)(int32_t)b; } MKOP(MUL, mul)
FOP(mulsu)  { return (int64_t)(int32_t)a * b; } MKOP(MULSU, mulsu)
FOP(mulu)   { return (uint64_t)a * b; } MKOP(MULU, mulu)
#undef FOP
#undef MKOP

// 64 bit
#define FOP(name) static inline uint64_t name ## 64 (uint64_t a, uint64_t b)
#define MKOP(NAME, name) MKOP_64(NAME ## 64, name ## 64)
FOP(add)    { return a + b; } MKOP(ADD, add)
FOP(sub)    { return a - b; } MKOP(SUB, sub)

FOP(shll)   { return a << (b & 63); } MKOP(SHLL, shll)
FOP(shrl)   { return a >> (b & 63); } MKOP(SHRL, shrl)
FOP(shra)   { return (uint64_t)(((int64_t)a) >> (b & 63)); } MKOP(SHRA, shra)
FOP(rotl)   { return shll64(a, b) | shrl64(a, 64 - b); } MKOP(ROTL, rotl)
FOP(rotr)   { return shll64(a, 64 - b) | shrl64(a, b); } MKOP(ROTR, rotr)

FOP(mul)    { return a * b; } MKOP(MUL, mul)
#undef FOP
#undef MKOP

// 64 bit carry
//#define HAS_UINT128 //// TODO test for this ////
#ifdef HAS_UINT128
    #ifdef __INTELLISENSE__
        // intellisense doesn't have __int128
        #define __int128 long
    #endif
    typedef unsigned __int128 uint128;
    #define MK128(lo, hi) ((((uint128)hi) << 64) | (lo))
    #define U128_0(v) ((uint32_t)v)
    #define U128_1(v) ((uint32_t)(v >> 32))
    #define U128_2(v) ((uint32_t)(v >> 64))
    #define U128_3(v) ((uint32_t)(v >> 96))
    static inline uint128 mul64C(uint64_t a, uint64_t b) {
        return (uint128) ((__int128)(int64_t)a * (__int128)(int64_t)b);
    }
    static inline uint128 mulsu64C(uint64_t a, uint64_t b) {
        return (uint128) ((__int128)(int64_t)a * (uint128)b);
    }
    static inline uint128 mulu64C(uint64_t a, uint64_t b) {
        return (uint128) ((uint128)a * (uint128)b);
    }
#else
    typedef union { uint64_t longs[2]; uint32_t ints[4]; } uint128;
    #define MK128(lo, hi) ((uint128){ .longs = { (lo), (hi) } })
    #define U128_0(v) v.ints[0]
    #define U128_1(v) v.ints[1]
    #define U128_2(v) v.ints[2]
    #define U128_3(v) v.ints[3]
    static inline uint64_t mulhu64(uint64_t a, uint64_t b)
    {
        uint32_t a0 = a;
        uint32_t a1 = a >> 32;
        uint32_t b0 = b;
        uint32_t b1 = b >> 32;

        uint64_t r00 = (uint64_t)a0 * (uint64_t)b0;
        uint64_t r01 = (uint64_t)a0 * (uint64_t)b1;
        uint64_t r10 = (uint64_t)a1 * (uint64_t)b0;
        uint64_t r11 = (uint64_t)a1 * (uint64_t)b1;

        uint64_t c = (r00 >> 32) + (uint32_t)r01 + (uint32_t)r10;
        c = (c >> 32) + (r01 >> 32) + (r10 >> 32) + (uint32_t)r11;
        uint32_t r2 = c;
        uint32_t r3 = (c >> 32) + (r11 >> 32);

        return ((uint64_t)r3 << 32) | r2;
    }
    static inline uint64_t mulh64(int64_t a, int64_t b)
    {
        int negate = (a < 0) != (b < 0);
        uint64_t res = mulhu64(a < 0 ? -a : a, b < 0 ? -b : b);
        return negate ? ~res + (a * b == 0) : res;
    }
    static inline uint64_t mulhsu64(int64_t a, uint64_t b)
    {
        int negate = a < 0;
        uint64_t res = mulhu64(a < 0 ? -a : a, b);
        return negate ? ~res + (a * b == 0) : res;
    }
    static inline uint128 mul64C(uint64_t a, uint64_t b) {
        return MK128((a * b), mulh64(a, b));
    }
    static inline uint128 mulsu64C(uint64_t a, uint64_t b) {
        return MK128((a * b), mulhsu64(a, b));
    }
    static inline uint128 mulu64C(uint64_t a, uint64_t b) {
        return MK128((a * b), mulhu64(a, b));
    }
#endif
#define FOP(name) static inline uint128 name ## 64C (uint64_t a, uint64_t b)
#define MKOP(NAME, name) MKOP_64C(NAME ## 64C, name ## 64C)
FOP(add)    { uint64_t res = a + b; return MK128(res, (res < b)); } MKOP(ADD, add)
FOP(sub)    { uint64_t res = a - b; return MK128(res, 0ull - (a < b)); } MKOP(SUB, sub)
MKOP(MUL, mul)
MKOP(MULSU, mulsu)
MKOP(MULU, mulu)
#undef FOP
#undef MKOP

// sizeless operations
static inline uint32_t XOR(uint32_t a, uint32_t b) { return a ^ b; }
static inline uint32_t  OR(uint32_t a, uint32_t b) { return a | b; }
static inline uint32_t AND(uint32_t a, uint32_t b) { return a & b; }

// single arg operations
#define MKSOP_64(name, impl) \
    static inline uint64_t name(uint32_t a, uint32_t b) { return impl((((uint64_t)b) << 32) | a); }

#define MKSOP_32(name, impl) \
    static inline uint32_t name(uint32_t a) { return impl(a); }

#define MKSOP_16(name, impl) \
    static inline uint32_t name(uint32_t a) {           \
        return                                          \
            (impl(((uint16_t)(a>>16))) << 16) |         \
             impl(((uint16_t)a));                       \
    }

#define MKSOP_8(name, impl) \
    static inline uint16_t name ## _16(uint16_t a) {    \
        return                                          \
            (impl(((uint8_t)(a>>8))) << 8) |            \
             impl( ((uint8_t)a) );                      \
    }                                                   \
    MKSOP_16(name, name ## _16)

#define FOP(name) static inline uint8_t name ## 8(uint8_t a)
#define MKOP(NAME, name) MKSOP_8(NAME ## 8, name ## 8)
FOP(popcnt)    { return __builtin_popcount(a); } MKOP(POPCNT, popcnt)
FOP(clz)       { return a ? (__builtin_clz(a)-24) : 8; } MKOP(CLZ, clz)
static inline uint32_t bswap8(uint32_t a) { return a; } MKOP(BSWAP, bswap)
FOP(ctz)       { return a ? __builtin_ctz(a) : 8; } MKOP(CTZ, ctz)
#undef FOP
#undef MKOP

#define FOP(name) static inline uint16_t name ## 16(uint16_t a)
#define MKOP(NAME, name) MKSOP_16(NAME ## 16, name ## 16)
FOP(popcnt)    { return __builtin_popcount(a); } MKOP(POPCNT, popcnt)
FOP(clz)       { return a ? (__builtin_clz(a)-16) : 16; } MKOP(CLZ, clz)
FOP(bswap)     { return __builtin_bswap16(a); } MKOP(BSWAP, bswap)
FOP(ctz)       { return a ? __builtin_ctz(a) : 16; } MKOP(CTZ, ctz)
#undef FOP
#undef MKOP

#define FOP(name) static inline uint32_t name ## 32(uint32_t a)
#define MKOP(NAME, name) MKSOP_32(NAME ## 32, name ## 32)
FOP(popcnt)    { return __builtin_popcount(a); } MKOP(POPCNT, popcnt)
FOP(clz)       { return a ? __builtin_clz(a) : 32; } MKOP(CLZ, clz)
FOP(bswap)     { return __builtin_bswap32(a); } MKOP(BSWAP, bswap)
FOP(ctz)       { return a ? __builtin_ctz(a) : 32; } MKOP(CTZ, ctz)
#undef FOP
#undef MKOP

#define FOP(name) static inline uint64_t name ## 64(uint64_t a)
#define MKOP(NAME, name) MKSOP_64(NAME ## 64, name ## 64)
FOP(popcnt)    { return __builtin_popcountll(a); } MKOP(POPCNT, popcnt)
FOP(clz)       { return a ? __builtin_clzll(a) : 64; } MKOP(CLZ, clz)
FOP(bswap)     { return __builtin_bswap64(a); } MKOP(BSWAP, bswap)
FOP(ctz)       { return a ? __builtin_ctzll(a) : 64; } MKOP(CTZ, ctz)
#undef FOP
#undef MKOP

#ifdef DEBUG
#define DEBUGF(fmt, ...) printf(fmt, __VA_ARGS__)
#else
#define DEBUGF(fmt, ...)
#endif

#define OP1(out, in) uint32_t out = in; DEBUGF("%s -> %08x\n", #in, out)
#define OP2(outA, outB, in) \
    uint32_t outA, outB;                    \
    do {                                    \
        uint64_t tmp = in;                  \
        outA = (uint32_t) tmp;              \
        outB = (uint32_t) (tmp >> 32);      \
    } while (0)
#define OP4(outA, outB, outC, outD, in) \
    uint32_t outA, outB, outC, outD;        \
    do {                                    \
        uint128 tmp = in;                   \
        outA = U128_0(tmp);                 \
        outB = U128_1(tmp);                 \
        outC = U128_2(tmp);                 \
        outD = U128_3(tmp);                 \
    } while (0)
