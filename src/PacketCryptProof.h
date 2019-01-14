#ifndef PACKETCRYPTPROOF_H
#define PACKETCRYPTPROOF_H
#include "Buf.h"
#include "Hash.h"

#include <stdint.h>

#define NUM_PROOFS 4

typedef struct {
    Buf32_t hash;
    uint64_t start;
    uint64_t end;
} Entry_t;
_Static_assert(sizeof(Entry_t) == 32+8+8, "");

typedef struct {
    uint64_t totalAnnsZeroIncluded;
    Buf32_t root;
    Entry_t zeroEntry;
    Entry_t entries[];
} PacketCryptProof_Tree_t;
_Static_assert(sizeof(PacketCryptProof_Tree_t) == 8+32+sizeof(Entry_t), "");

PacketCryptProof_Tree_t* PacketCryptProof_allocTree(uint64_t totalAnns);
uint64_t PacketCryptProof_prepareTree(PacketCryptProof_Tree_t* tree);

void PacketCryptProof_computeTree(PacketCryptProof_Tree_t* tree);

void PacketCryptProof_freeTree(PacketCryptProof_Tree_t* bm);

// sizeOut is assigned to the length, freeable using free()
uint8_t* PacketCryptProof_mkProof(
    int* sizeOut,
    const PacketCryptProof_Tree_t* tree,
    const uint64_t annNumbers[static NUM_PROOFS]
);

// returns zero if the hash is valid
int PacketCryptProof_hashProof(
    Buf32_t* hashOut,
    const Buf32_t annHashes[static NUM_PROOFS],
    uint8_t* cpcp, int cpcpSize
);

#endif
