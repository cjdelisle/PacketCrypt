#include "src/OpTemplate.h"
#include "src/Constants.h"

#include <stdint.h>

#define IF_LIKELY(x) if (((uint8_t)(x) & 7) != 0)
#define IF_RANDOM(x) if (((uint8_t)(x) & 1) != 0)
#define LOOP(i, count) for (int i = 0; i < count; i++)

#define OUT(x) do { DEBUGF("out1(%08x) %d\n", (x), hashctr); hashOut[hashctr] += (x); hashctr = (hashctr + 1) % RandHash_HASH_SZ; } while (0)
#define OUT2(x,y) do { OUT(x); OUT(y); } while (0)
#define OUT4(x,y,z,a) do { OUT2(x,y); OUT2(z,a); } while (0)
#define OUT8(x,y,z,a,b,c,d,e) do { OUT4(x,y,z,a); OUT4(b,c,d,e); } while (0)
#define IN(x) hashIn[(x) & (RandHash_MEMORY_SZ - 1)]
#define MEMORY(loopVar, base, step, carry) memory[(base + ((loopVar + carry) * step)) & (RandHash_MEMORY_SZ - 1)]

#define FUNC_DECL void run

#define BEGIN \
    FUNC_DECL (uint32_t* hashOut, uint32_t* hashIn, uint32_t* memory, int cycles) { \
        for (int i = 0; i < cycles; i++) {                                          \
            int hashctr = 0;

#define END \
            uint32_t* x = hashOut; hashOut = hashIn; hashIn = x;                    \
        }                                                                           \
    }