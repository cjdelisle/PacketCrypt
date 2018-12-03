# RandomHash

A hash function which is different every time.

**NOTE:** This is not a secure hash function, it's a primitive for building something
larger, do not use it unless you know what you're doing.

## Why

If you use a hash function to hash a password (for example), someone who wants to figure
out your password and they happen to have the hash (from a hacked website for instance),
their best bet is to try to guess different passwords and try to hash them and compare to
the output.

With technology like GPUs (video cards), people can make thousands of guesses at the same
time because GPUs have powerful parallel processors. The way that GPUs are able to be so
effective at simple repetitive jobs like cracking passwords is because of
[SIMD](https://en.wikipedia.org/wiki/SIMD).

GPUs in particular have the ability to perform the same operation on an enormous number of
different pieces of data at the same time, and if that operation is a hash function, then
they can guess a lot of passwords really quickly.

RandomHash attempts to frustrate parallel cracking attempts by creating a wholly different
hash function for every password.

## How

The way the code works is roughly as follows:

```go
hash0 := blake2b(your_input)
var program [PROGRAM_SIZE]byte;
chacha20(program, hash0, PROGRAM_SIZE)

var registers [12]uint64;
chacha20(registers, hash0, 12 * 8)

// interpreter only touches 8 of the 12 registers,
// other 4 are for entropy

for i := 0; i < CYCLES; i++ { interpreter(registers, program) }

hash1 := blake2b(registers)
```

### How the interpreter works

The interpreter parses the program as a series of 2 byte instructions, the instructions
are handled as little endian. The interpreter is designed to use the maximum amount of
the processor that is reasonable to do, without accessing memory. It is also designed
to maximize the mixing of the data and reduce the entropy by only about 1 bit per cycle
(in order to prevent running the hash in reverse). It's not meant to be a *secure* hash
function but it is meant to be difficult to implement on faster on anything other than
an amd64 processor.

```c
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
```

### Design considerations
1. Everything is 64 bit. This is because most modern computers are 64 bit, most phones
are going to be 64 bit within a few years, but GPUs are still 32 bit.
2. It uses operations which are available on amd64 and AArch64, which are the majority
of machines in use today.
3. It avoids entropy-destroying operations such as `b |= a` because it's meant to
produce something akin to a hash function from any program that is generated.
4. It attempts to use enough operations that it would be a major annoyance to try to
implement an ASIC for crasking the hash without just implementing an actual processor.

### Compiling to assembly
While there is an interpreter, there is also a JIT compiler which converts the program
into native code. This has been written for amd64 target and will probably be written
for AArch64 (ARM).

The native version is about 13x the speed of the interpreter.