/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#ifndef GOLANG

#include <stdint.h>

#define uint8(x)  ((uint8_t)(x))
#define uint16(x) ((uint16_t)(x))
#define uint32(x) ((uint32_t)(x))
#define uint64(x) ((uint64_t)(x))
#define int8(x)   ((int8_t)(x))
#define int16(x)  ((int16_t)(x))
#define int32(x)  ((int32_t)(x))
#define int64(x)  ((int64_t)(x))

#define var(type, name, val) type name = val
#define lnot(val) (~val)
#ifndef bool
#define bool int
#endif
#define bint(x) (!!(x))

#ifdef DEBUG
#define DEBUGF(fmt, ...) printf(fmt, __VA_ARGS__)
#else
#define DEBUGF(fmt, ...)
#endif

#define SCOPE(x) do x while (0)

#define MKFUN4(rett, name, t0, n0, t1, n1, t2, n2, t3, n3, impl) \
    static inline rett name(t0 n0, t1 n1, t2 n2, t3 n3) impl
#define MKFUN2(rett, name, t0, n0, t1, n1, impl) \
    static inline rett name(t0 n0, t1 n1) impl
#define MKFUN1(rett, name, t0, n0, impl) \
    static inline rett name(t0 n0) impl

#define POPCOUNT8_IMPL(a) uint8(__builtin_popcount(a))
#define POPCOUNT16_IMPL(a) uint16(__builtin_popcount(a))
#define POPCOUNT32_IMPL(a) uint32(__builtin_popcount(a))

#define CLZ8_IMPL(a) ((a) ? (__builtin_clz(uint8(a))-24) : 8)
#define CLZ16_IMPL(a) ((a) ? (__builtin_clz(uint16(a))-16) : 16)
#define CLZ32_IMPL(a) ((a) ? __builtin_clz(a) : 32)

#define CTZ8_IMPL(a) ((a) ? __builtin_ctz(a) : 8)
#define CTZ16_IMPL(a) ((a) ? __builtin_ctz(a) : 16)
#define CTZ32_IMPL(a) ((a) ? __builtin_ctz(a) : 32)

#if __SIZEOF_LONG__ == 8
    #define POPCOUNT64_IMPL(a) __builtin_popcountl(a)
    #define CLZ64_IMPL(a) ((a) ? __builtin_clzl(a) : 64)
    #define CTZ64_IMPL(a) ((a) ? __builtin_clzl(a) : 64)
#elif __SIZEOF_LONG_LONG__ == 8
    #define POPCOUNT64_IMPL(a) __builtin_popcountll(a)
    #define CLZ64_IMPL(a) ((a) ? __builtin_clzll(a) : 64)
    #define CTZ64_IMPL(a) ((a) ? __builtin_ctzll(a) : 64)
#else
    #error "unknown size of 64 bit register"
#endif

#define BSWAP16_IMPL(a) __builtin_bswap16(a)
#define BSWAP32_IMPL(a) __builtin_bswap32(a)
#define BSWAP64_IMPL(a) __builtin_bswap64(a)

#endif // ndef GOLANG



#define MKOP_64x(rett, name, impl) \
    MKFUN4(rett, name, uint32_t, a0, uint32_t, a1, uint32_t, b0, uint32_t, b1, { \
        var(uint64_t, a, a1); a <<= 32; a |= uint64(a0); \
        var(uint64_t, b, b1); b <<= 32; b |= uint64(b0); \
        return impl(a, b); \
    })

#define MKOP_64(name, impl)  MKOP_64x(uint64_t, name, impl)
#define MKOP_64C(name, impl) MKOP_64x(uint128,  name, impl)

#define MKOP_32(name, impl) \
    MKFUN2(uint32_t, name, uint32_t, a, uint32_t, b, { return impl(a, b); })

#define MKOP_16(name, impl) \
    MKFUN2(uint32_t, name, uint32_t, a, uint32_t, b, { \
        return (uint32(impl( uint16(a>>16), uint16(b>>16) )) << 16) | \
            uint32(impl( uint16(a), uint16(b) )); \
    })

#define MKOP_8(name, impl) \
    MKFUN2(uint16_t, name ## _16, uint16_t, a, uint16_t, b, { \
        return (uint16(impl( uint8(a>>8), uint8(b>>8) )) << 8) | uint16(impl( uint8(a), uint8(b) )); \
    }) \
    MKOP_16(name, name ## _16)

#define MKOP_32C(name, impl) \
    MKFUN2(uint64_t, name, uint32_t, a, uint32_t, b, { return impl(a, b); })

#define MKOP_16C(name, impl) \
    MKFUN2(uint64_t, name, uint32_t, a, uint32_t, b, { \
        return (uint64(impl( uint16(a>>16), uint16(b>>16) )) << 32) | \
            uint64(impl( uint16(a), uint16(b) )); \
    })

#define MKOP_8C(name, impl) \
    MKFUN2(uint32_t, name ## _16C, uint16_t, a, uint16_t, b, { \
        return (uint32(impl( uint8(a>>8), uint8(b>>8) )) << 16) | uint32(impl( uint8(a), uint8(b) )); \
    }) \
    MKOP_16C(name, name ## _16C)

// 8 bit
#define FOP(name, impl) MKFUN2(uint8_t, name ## 8, uint8_t, a, uint8_t, b, impl)
#define MKOP(NAME, name) MKOP_8(NAME ## 8, name ## 8)
FOP(add,    { return a + b; }) MKOP(ADD, add)
FOP(sub,    { return a - b; }) MKOP(SUB, sub)

FOP(shll,   { return a << (b & 7); }) MKOP(SHLL, shll)
FOP(shrl,   { return a >> (b & 7); }) MKOP(SHRL, shrl)
FOP(shra,   { return uint8(int8(a) >> (b & 7)); }) MKOP(SHRA, shra)
FOP(rotl,   { return shll8(a, b) | shrl8(a, 8 - b); }) MKOP(ROTL, rotl)
FOP(rotr,   { return shll8(a, 8 - b) | shrl8(a, b); }) MKOP(ROTR, rotr)

FOP(mul,    { return a * b; }) MKOP(MUL, mul)
#undef FOP
#undef MKOP

// 8 bit carry
#define FOP(name, impl) MKFUN2(uint16_t, name ## 8C, uint8_t, a, uint8_t, b, impl)
#define MKOP(NAME, name) MKOP_8C(NAME ## 8C, name ## 8C)
FOP(add,    { return uint16(a) + uint16(b); }) MKOP(ADD, add)
FOP(sub,    { return uint16(a) - uint16(b); }) MKOP(SUB, sub)

FOP(mul,    { return uint16( int16(int8(a)) * int16(int8(b)) ); }) MKOP(MUL, mul)
FOP(mulu,   { return uint16(a) * uint16(b); }) MKOP(MULU, mulu)
FOP(mulsu,  { return uint16( int16(int8(a)) * int16(b) ); }) MKOP(MULSU, mulsu)
#undef FOP
#undef MKOP

// 16 bit
#define FOP(name, impl) MKFUN2(uint16_t, name ## 16, uint16_t, a, uint16_t, b, impl)
#define MKOP(NAME, name) MKOP_16(NAME ## 16, name ## 16)
FOP(add,    { return a + b; }) MKOP(ADD, add)
FOP(sub,    { return a - b; }) MKOP(SUB, sub)

FOP(shll,   { return a << (b & 15); }) MKOP(SHLL, shll)
FOP(shrl,   { return a >> (b & 15); }) MKOP(SHRL, shrl)
FOP(shra,   { return uint16(int16(a) >> (b & 15)); }) MKOP(SHRA, shra)
FOP(rotl,   { return shll16(a, b) | shrl16(a, 16 - b); }) MKOP(ROTL, rotl)
FOP(rotr,   { return shll16(a, 16 - b) | shrl16(a, b); }) MKOP(ROTR, rotr)

FOP(mul,    { return a * b; }) MKOP(MUL, mul)
#undef FOP
#undef MKOP

// 16 bit carry
#define FOP(name, impl) MKFUN2(uint32_t, name ## 16C, uint16_t, a, uint16_t, b, impl)
#define MKOP(NAME, name) MKOP_16C(NAME ## 16C, name ## 16C)
FOP(add,    { return uint32(a) + uint32(b); }) MKOP(ADD, add)
FOP(sub,    { return uint32(a) - uint32(b); }) MKOP(SUB, sub)

FOP(mul,    { return uint32( int32(int16(a)) * int32(int16(b)) ); }) MKOP(MUL, mul)
FOP(mulu,   { return uint32(a) * uint32(b); }) MKOP(MULU, mulu)
FOP(mulsu,  { return uint32( int32(int16(a)) * int32(b) ); }) MKOP(MULSU, mulsu)
#undef FOP
#undef MKOP

// 32 bit
#define FOP(name, impl) MKFUN2(uint32_t, name ## 32, uint32_t, a, uint32_t, b, impl)
#define MKOP(NAME, name) MKOP_32(NAME ## 32, name ## 32)
FOP(add,    { return a + b; }) MKOP(ADD, add)
FOP(sub,    { return a - b; }) MKOP(SUB, sub)

FOP(shll,   { return a << (b & 31); }) MKOP(SHLL, shll)
FOP(shrl,   { return a >> (b & 31); }) MKOP(SHRL, shrl)
FOP(shra,   { return uint32(int32(a) >> (b & 31)); }) MKOP(SHRA, shra)
FOP(rotl,   { return shll32(a, b) | shrl32(a, 32 - b); }) MKOP(ROTL, rotl)
FOP(rotr,   { return shll32(a, 32 - b) | shrl32(a, b); }) MKOP(ROTR, rotr)

FOP(mul,    { return a * b; }) MKOP(MUL, mul)
#undef FOP
#undef MKOP

// 32 bit carry
#define FOP(name, impl) MKFUN2(uint64_t, name ## 32C, uint32_t, a, uint32_t, b, impl)
#define MKOP(NAME, name) MKOP_32C(NAME ## 32C, name ## 32C)
FOP(add,    { return uint64(a) + uint64(b); }) MKOP(ADD, add)
FOP(sub,    { return uint64(a) - uint64(b); }) MKOP(SUB, sub)

FOP(mul,    { return uint64( int64(int32(a)) * int64(int32(b)) ); }) MKOP(MUL, mul)
FOP(mulu,   { return uint64(a) * uint64(b); }) MKOP(MULU, mulu)
FOP(mulsu,  { return uint64( int64(int32(a)) * int64(b) ); }) MKOP(MULSU, mulsu)
#undef FOP
#undef MKOP

// 64 bit
#define FOP(name, impl) MKFUN2(uint64_t, name ## 64, uint64_t, a, uint64_t, b, impl)
#define MKOP(NAME, name) MKOP_64(NAME ## 64, name ## 64)
FOP(add,    { return a + b; }) MKOP(ADD, add)
FOP(sub,    { return a - b; }) MKOP(SUB, sub)

FOP(shll,   { return a << (b & 63); }) MKOP(SHLL, shll)
FOP(shrl,   { return a >> (b & 63); }) MKOP(SHRL, shrl)
FOP(shra,   { return uint64(int64(a) >> (b & 63)); }) MKOP(SHRA, shra)
FOP(rotl,   { return shll64(a, b) | shrl64(a, 64 - b); }) MKOP(ROTL, rotl)
FOP(rotr,   { return shll64(a, 64 - b) | shrl64(a, b); }) MKOP(ROTR, rotr)

FOP(mul,    { return a * b; }) MKOP(MUL, mul)
#undef FOP
#undef MKOP

// 64 bit carry
//#define HAS_UINT128 //// TODO test for this ////
#if defined(GOLANG)
    type uint128 struct {
        bytes [16]byte
    }
    func MK128(lo, hi uint64) uint128 {
        out := uint128{}
        binary.LittleEndian.PutUint64(out.bytes[:8], (lo))
        binary.LittleEndian.PutUint64(out.bytes[8:], (hi))
        return out
    }
    func U128_0(v uint128) uint32 { return binary.LittleEndian.Uint32(v.bytes[  : 4]) }
    func U128_1(v uint128) uint32 { return binary.LittleEndian.Uint32(v.bytes[ 4: 8]) }
    func U128_2(v uint128) uint32 { return binary.LittleEndian.Uint32(v.bytes[ 8:12]) }
    func U128_3(v uint128) uint32 { return binary.LittleEndian.Uint32(v.bytes[12:16]) }
#elif defined(HAS_UINT128)
    #ifdef __INTELLISENSE__
        // intellisense doesn't have __int128
        #define __int128 long
    #endif
    typedef unsigned __int128 uint128;
    #define MK128(lo, hi) ((((uint128)hi) << 64) | (lo))
    #define U128_0(v) uint32(v)
    #define U128_1(v) uint32(v >> 32)
    #define U128_2(v) uint32(v >> 64)
    #define U128_3(v) uint32(v >> 96)
    static inline uint128 mul64C(uint64_t a, uint64_t b) {
        return (uint128) ((__int128)uint64(a) * (__int128)(int64_t)b);
    }
    static inline uint128 mulsu64C(uint64_t a, uint64_t b) {
        return (uint128) ((__int128)uint64(a) * (uint128)b);
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
#endif

#if defined(GOLANG) || !defined(HAS_UINT128)
    MKFUN2(uint64_t, mulhu64, uint64_t, a, uint64_t, b, {
        var(uint32_t, a0, a);
        var(uint32_t, a1, (a >> 32));
        var(uint32_t, b0, b);
        var(uint32_t, b1, (b >> 32));

        var(uint64_t, r00, ( uint64(a0) * uint64(b0) ));
        var(uint64_t, r01, ( uint64(a0) * uint64(b1) ));
        var(uint64_t, r10, ( uint64(a1) * uint64(b0) ));
        var(uint64_t, r11, ( uint64(a1) * uint64(b1) ));

        var(uint64_t, c, ( (r00 >> 32) + uint64(uint32(r01)) + uint64(uint32(r10)) ));

        c = (c >> 32) + (r01 >> 32) + (r10 >> 32) + uint64(uint32(r11));
        var(uint32_t, r2, c);
        var(uint32_t, r3, ( (c >> 32) + (r11 >> 32) ));

        return (uint64(r3) << 32) | uint64(r2);
    })
    MKFUN2(uint64_t, mulh64, int64_t, a, int64_t, b, {
        var(bool, negate, ( (a < 0) != (b < 0) ));
        var(uint64_t, _a, a);
        var(uint64_t, _b, b);
        SCOPE({ if (a < 0) { _a = uint64(-a); } });
        SCOPE({ if (b < 0) { _b = uint64(-b); } });
        var(uint64_t, res, mulhu64(_a, _b));
        SCOPE({
            if (negate) {
                res = lnot(res);
                if (a * b == 0) { res++; }
            }
        });
        return res;
    })
    MKFUN2(uint64_t, mulhsu64, int64_t, a, uint64_t, b, {
        var(bool, negate, (a < 0));
        var(uint64_t, _a, a);
        SCOPE({ if (a < 0) { _a = uint64(-a); } });
        var(uint64_t, res, mulhu64(_a, b));
        SCOPE({
            if (negate) {
                res = lnot(res);
                if (uint64(a) * b == 0) { res++; }
            }
        });
        return res;
    })
    MKFUN2(uint128, mul64C, uint64_t, a, uint64_t, b, {
        return MK128((a * b), mulh64(int64(a), int64(b)));
    })
    // hex(0x100000000000000000000000000000000 + ((-0x10000000000000000 + 0xb683304f1fe23f82) * 0xd5b569d81ffa2417))
    MKFUN2(uint128, mulsu64C, uint64_t, a, uint64_t, b, {
        return MK128((a * b), mulhsu64(int64(a), b));
    })
    MKFUN2(uint128, mulu64C, uint64_t, a, uint64_t, b, {
        return MK128((a * b), mulhu64(a, b));
    })
#endif
#define FOP(name, impl) MKFUN2(uint128, name ## 64C, uint64_t, a, uint64_t, b, impl)
#define MKOP(NAME, name) MKOP_64C(NAME ## 64C, name ## 64C)
FOP(add,    { var(uint64_t, res, (a + b)); return MK128(res, uint64(bint(res < b))); }) MKOP(ADD, add)
FOP(sub,    { var(uint64_t, res, (a - b)); return MK128(res, uint64(0) - uint64(bint(a < b))); }) MKOP(SUB, sub)
MKOP(MUL, mul)
MKOP(MULSU, mulsu)
MKOP(MULU, mulu)
#undef FOP
#undef MKOP

// sizeless operations
MKFUN2(uint32_t, XOR, uint32_t, a, uint32_t, b, { return a ^ b; })
MKFUN2(uint32_t,  OR, uint32_t, a, uint32_t, b, { return a | b; })
MKFUN2(uint32_t, AND, uint32_t, a, uint32_t, b, { return a & b; })

// single arg operations
#define MKSOP_64(name, impl) \
    MKFUN2(uint64_t, name, uint32_t, a, uint32_t, b, { return impl((uint64(b) << 32) | uint64(a)); })

#define MKSOP_32(name, impl) \
    MKFUN1(uint32_t, name, uint32_t, a, { return impl(a); })

#define MKSOP_16(name, impl) \
    MKFUN1(uint32_t, name, uint32_t, a, { \
        return (uint32(impl( uint16(a>>16) )) << 16) | uint32(impl( uint16(a) )); \
    })

#define MKSOP_8(name, impl) \
    MKFUN1(uint16_t, name ## _16, uint16_t, a, { \
        return (uint16(impl( uint8(a>>8) )) << 8) | uint16(impl( uint8(a) )); \
    }) \
    MKSOP_16(name, name ## _16)


#define FOP(name, impl) MKFUN1(uint8_t, name ## 8, uint8_t, a, impl)
#define MKOP(NAME, name) MKSOP_8(NAME ## 8, name ## 8)
FOP(popcnt,    { return uint8(POPCOUNT8_IMPL(a)); }) MKOP(POPCNT, popcnt)
FOP(clz,       { return uint8(CLZ8_IMPL(a)); }) MKOP(CLZ, clz)
MKFUN1(uint8_t, bswap8, uint8_t, a, { return a; }) MKOP(BSWAP, bswap)
FOP(ctz,       { return uint8(CTZ8_IMPL(a)); }) MKOP(CTZ, ctz)
#undef FOP
#undef MKOP

#define FOP(name, impl) MKFUN1(uint16_t, name ## 16, uint16_t, a, impl)
#define MKOP(NAME, name) MKSOP_16(NAME ## 16, name ## 16)
FOP(popcnt,    { return uint16(POPCOUNT16_IMPL(a)); }) MKOP(POPCNT, popcnt)
FOP(clz,       { return uint16(CLZ16_IMPL(a)); }) MKOP(CLZ, clz)
FOP(bswap,     { return BSWAP16_IMPL(a); }) MKOP(BSWAP, bswap)
FOP(ctz,       { return uint16(CTZ16_IMPL(a)); }) MKOP(CTZ, ctz)
#undef FOP
#undef MKOP

#define FOP(name, impl) MKFUN1(uint32_t, name ## 32, uint32_t, a, impl)
#define MKOP(NAME, name) MKSOP_32(NAME ## 32, name ## 32)
FOP(popcnt,    { return uint32(POPCOUNT32_IMPL(a)); }) MKOP(POPCNT, popcnt)
FOP(clz,       { return uint32(CLZ32_IMPL(a)); }) MKOP(CLZ, clz)
FOP(bswap,     { return BSWAP32_IMPL(a); }) MKOP(BSWAP, bswap)
FOP(ctz,       { return uint32(CTZ32_IMPL(a)); }) MKOP(CTZ, ctz)
#undef FOP
#undef MKOP

#define FOP(name, impl) MKFUN1(uint64_t, name ## 64, uint64_t, a, impl)
#define MKOP(NAME, name) MKSOP_64(NAME ## 64, name ## 64)
FOP(popcnt,    { return uint64(POPCOUNT64_IMPL(a)); }) MKOP(POPCNT, popcnt)
FOP(clz,       { return uint64(CLZ64_IMPL(a)); }) MKOP(CLZ, clz)
FOP(bswap,     { return BSWAP64_IMPL(a); }) MKOP(BSWAP, bswap)
FOP(ctz,       { return uint64(CTZ64_IMPL(a)); }) MKOP(CTZ, ctz)
#undef FOP
#undef MKOP

/*
#define OP1(out, in) var(uint32_t, out, (in)); DEBUGF("%s -> %08x\n", #in, out)
#define OP2(outA, outB, in) \
    var(uint32_t, outA, 0); \
    var(uint32_t, outB, 0); \
    SCOPE({ \
        var(uint64_t, tmp, (in); \
        outA = uint32(tmp); \
        outB = uint32(tmp >> 32); \
    })
#define OP4(outA, outB, outC, outD, in) \
    var(uint32_t, outA, 0); \
    var(uint32_t, outB, 0); \
    var(uint32_t, outC, 0); \
    var(uint32_t, outD, 0); \
    SCOPE({ \
        var(uint128, tmp, (in)); \
        outA = U128_0(tmp); \
        outB = U128_1(tmp); \
        outC = U128_2(tmp); \
        outD = U128_3(tmp); \
    })
*/

// comm -3 ./basic_defines.txt ot2_defines.txt | sed 's/^.*#define \([^ (]*\).*$/#undef \1/'
#undef BSWAP16_IMPL
#undef BSWAP32_IMPL
#undef BSWAP64_IMPL
#undef CLZ16_IMPL
#undef CLZ32_IMPL
#undef CLZ64_IMPL
#undef CLZ8_IMPL
#undef CTZ16_IMPL
#undef CTZ32_IMPL
#undef CTZ64_IMPL
#undef CTZ8_IMPL
#undef DEBUGF
#undef MK128
#undef MKFUN1
#undef MKFUN2
#undef MKFUN4
#undef MKOP_16
#undef MKOP_16C
#undef MKOP_32
#undef MKOP_32C
#undef MKOP_64
#undef MKOP_64C
#undef MKOP_64x
#undef MKOP_8
#undef MKOP_8C
#undef MKSOP_16
#undef MKSOP_32
#undef MKSOP_64
#undef MKSOP_8
#undef OP1
#undef OP2
#undef OP4
#undef POPCOUNT16_IMPL
#undef POPCOUNT32_IMPL
#undef POPCOUNT64_IMPL
#undef POPCOUNT8_IMPL
#undef POPCOUNT_IMPL
#undef SCOPE
//#undef U128_0
//#undef U128_1
//#undef U128_2
//#undef U128_3
#undef bint
#undef bool
#undef int16
#undef int32
#undef int64
#undef int8
#undef lnot
#undef uint16
#undef uint32
#undef uint64
#undef uint8
#undef var
