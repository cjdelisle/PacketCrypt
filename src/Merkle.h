#ifndef MERKLE_H
#define MERKLE_H
#include "Buf.h"
#include <stdbool.h>
void Merkle__build(int depth, uint8_t* out, uint8_t* table, int itemSz);
void Merkle__getBranch(int depth, uint8_t* out, uint16_t itemNo, const uint8_t* merkle);
bool Merkle__isItemValid(int depth, const uint8_t* out, const Buf64_t* itemHash, uint16_t itemNo);
#endif


#ifndef Merkle_IMPL

#if !defined(Merkle_DEPTH) && defined(__INTELLISENSE__)
    // fill in some data to make it nice in the IDE
    #define Merkle_DEPTH 13
    #define Merkle_NAME CCMerkle
#endif

#ifndef Merkle_DEPTH
    #error Merkle_DEPTH must be specified
#endif
#ifndef Merkle_NAME
    #error Merkle_NAME must be specified
#endif

#define Merkle_GLUE(a,b) Merkle_GLUE2(a,b)
#define Merkle_GLUE2(a,b) a ## b
#define Merkle_BRANCH Merkle_GLUE(Merkle_NAME, _Branch)

typedef union {
    uint8_t bytes[sizeof(Buf64_t) * ((1<<Merkle_DEPTH) * 2 - 1)];
    Buf64_t sixtyfours[((1<<Merkle_DEPTH) * 2 - 1)];
    Buf32_t thirtytwos[((1<<Merkle_DEPTH) * 2 - 1) * 2];
} Merkle_NAME;
_Static_assert(
    sizeof(Merkle_NAME) == sizeof(Buf64_t) * ((1<<Merkle_DEPTH) * 2 - 1), "sizeof(Merkle_t)");

typedef union {
    uint8_t bytes[(Merkle_DEPTH + 1) * sizeof(Buf64_t)];
    Buf64_t sixtyfours[Merkle_DEPTH + 1];
    Buf32_t thirtytwos[(Merkle_DEPTH + 1) * 2];
} Merkle_BRANCH;
_Static_assert(
    sizeof(Merkle_GLUE(Merkle_NAME, _Branch)) == (Merkle_DEPTH + 1) * sizeof(Buf64_t), "");

static inline void Merkle_GLUE(Merkle_NAME, _build)(Merkle_NAME* out, uint8_t* table, int itemSz)
{
    Merkle__build(Merkle_DEPTH, out->bytes, table, itemSz);
}

static inline void Merkle_GLUE(Merkle_NAME, _getBranch)(
    Merkle_BRANCH* out, uint16_t itemNo, const Merkle_NAME* merkle)
{
    Merkle__getBranch(Merkle_DEPTH, out->bytes, itemNo, merkle->bytes);
}

static inline bool Merkle_GLUE(Merkle_NAME, _isItemValid)(
    const Merkle_BRANCH* branch, const Buf64_t* itemHash, uint16_t itemNo)
{
    return Merkle__isItemValid(Merkle_DEPTH, branch->bytes, itemHash, itemNo);
}

static inline uint8_t* Merkle_GLUE(Merkle_NAME, _root)(Merkle_NAME* merkle) {
    return merkle->sixtyfours[((1<<Merkle_DEPTH) * 2 - 2)].bytes;
}

#undef Merkle_DEPTH
#undef Merkle_NAME
#undef Merkle_GLUE
#undef Merkle_GLUE2
#undef Merkle_BRANCH

#endif
