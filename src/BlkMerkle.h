#ifndef BLKMERKLE_H
#define BLKMERKLE_H

#include "Buf.h"

typedef struct {
    Buf32_t hash;
    uint64_t range;
} BlkMerkle_Entry_t;
_Static_assert(sizeof(BlkMerkle_Entry_t) == 32+8, "");

typedef struct {
    uint32_t hashCount;
    uint8_t* bitfield;
    Buf32_t hashes[];
} BlkMerkle_Proof_t;

typedef struct {
    int itemCount;
    int size;
    BlkMerkle_Entry_t entries[];
} BlkMerkle_t;
_Static_assert(sizeof(BlkMerkle_t) == 8, "");

BlkMerkle_t* BlkMerkle_alloc(int itemCount);
void BlkMerkle_free(BlkMerkle_t* bm);

// This function will alter itemCount if there are items which collide
void BlkMerkle_compute(BlkMerkle_t* bm);

Buf32_t* BlkMerkle_getRoot(BlkMerkle_t* bm);

#endif
