/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#ifndef MERKLE_H
#define MERKLE_H
#include "Buf.h"
#include <stdbool.h>
void AnnMerkle__build(int depth, uint8_t* out, uint8_t* table, int itemSz);
void AnnMerkle__getBranch(int depth, uint8_t* out, uint16_t itemNo, const uint8_t* merkle);
bool AnnMerkle__isItemValid(int depth, const uint8_t* out, const Buf64_t* itemHash, uint16_t itemNo);
#endif


#ifndef AnnMerkle_IMPL

#if !defined(AnnMerkle_DEPTH) && defined(__INTELLISENSE__)
    // fill in some data to make it nice in the IDE
    #define AnnMerkle_DEPTH 13
    #define AnnMerkle_NAME CCAnnMerkle
#endif

#ifndef AnnMerkle_DEPTH
    #error AnnMerkle_DEPTH must be specified
#endif
#ifndef AnnMerkle_NAME
    #error AnnMerkle_NAME must be specified
#endif

#define AnnMerkle_GLUE(a,b) AnnMerkle_GLUE2(a,b)
#define AnnMerkle_GLUE2(a,b) a ## b
#define AnnMerkle_BRANCH AnnMerkle_GLUE(AnnMerkle_NAME, _Branch)

typedef union {
    uint8_t bytes[sizeof(Buf64_t) * ((1<<AnnMerkle_DEPTH) * 2 - 1)];
    Buf64_t sixtyfours[((1<<AnnMerkle_DEPTH) * 2 - 1)];
    Buf32_t thirtytwos[((1<<AnnMerkle_DEPTH) * 2 - 1) * 2];
} AnnMerkle_NAME;
_Static_assert(
    sizeof(AnnMerkle_NAME) == sizeof(Buf64_t) * ((1<<AnnMerkle_DEPTH) * 2 - 1), "sizeof(AnnMerkle_t)");

typedef union {
    uint8_t bytes[(AnnMerkle_DEPTH + 1) * sizeof(Buf64_t)];
    Buf64_t sixtyfours[AnnMerkle_DEPTH + 1];
    Buf32_t thirtytwos[(AnnMerkle_DEPTH + 1) * 2];
} AnnMerkle_BRANCH;
_Static_assert(
    sizeof(AnnMerkle_GLUE(AnnMerkle_NAME, _Branch)) == (AnnMerkle_DEPTH + 1) * sizeof(Buf64_t), "");

static inline void AnnMerkle_GLUE(AnnMerkle_NAME, _build)(AnnMerkle_NAME* out, uint8_t* table, int itemSz)
{
    AnnMerkle__build(AnnMerkle_DEPTH, out->bytes, table, itemSz);
}

static inline void AnnMerkle_GLUE(AnnMerkle_NAME, _getBranch)(
    AnnMerkle_BRANCH* out, uint16_t itemNo, const AnnMerkle_NAME* merkle)
{
    AnnMerkle__getBranch(AnnMerkle_DEPTH, out->bytes, itemNo, merkle->bytes);
}

static inline bool AnnMerkle_GLUE(AnnMerkle_NAME, _isItemValid)(
    const AnnMerkle_BRANCH* branch, const Buf64_t* itemHash, uint16_t itemNo)
{
    return AnnMerkle__isItemValid(AnnMerkle_DEPTH, branch->bytes, itemHash, itemNo);
}

static inline Buf64_t* AnnMerkle_GLUE(AnnMerkle_NAME, _root)(AnnMerkle_NAME* merkle) {
    return &merkle->sixtyfours[((1<<AnnMerkle_DEPTH) * 2 - 2)];
}

#undef AnnMerkle_DEPTH
#undef AnnMerkle_NAME
#undef AnnMerkle_GLUE
#undef AnnMerkle_GLUE2
#undef AnnMerkle_BRANCH

#endif
