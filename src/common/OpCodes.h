#ifndef OPCODES_H
#define OPCODES_H

/*
 * Big endian representation
 *  0               1
 *  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |b|  a  |   op  |    data   | b |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Little endian representation
 *  0               1
 *  0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   data   |  b  |  a  |   op  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 
 * op   -> operation number
 * a    -> info register
 * b    -> altered register
 * data -> extra data for the instruction
 */

#define OP_ADD   0  // b += a
#define OP_SUB   1  // b -= a
#define OP_XOR   2  // b ^= a
#define OP_EOR   3  // b += (a ^ data)

#define OP_SHL   4  // b += (a << data)
#define OP_SHR   5  // b += (a >> data)

#define OP_POP   6  // b += __builtin_popcnt(a)
#define OP_CLZ   7  // b += __builtin_clzll(a)

#define OP_SWP   8  // b = __builtin_bswap64(b)
#define OP_REV   9  // b = bit_reverse(b)

#define OP_MUL  10  // b += ((int64_t)a) * ((int64_t)b)
#define OP_MIL  11  // b += ((a * b) & UINT64_MAX) + ((a * b) >> 64)
#define OP_ROL  12  // a = rotate_left(a, $num)
#define OP_DUV  13  // b += (b / (a|1)) + (b % (a|1))
#define OP_DIV  14  // b += ((int64_t)b / ((int64_t)|1)) + ((int64_t) % ((int64_t)|1))

#define OP_CMP  15  // a number of different comparison ops

#endif