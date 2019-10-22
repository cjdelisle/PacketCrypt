/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#ifndef ANNOUNCE_H
#define ANNOUNCE_H

#include "packetcrypt/PacketCrypt.h"
#include "CryptoCycle.h"

#define Announce_ITEM_HASHCOUNT (sizeof(CryptoCycle_Item_t) / 64)

#define Announce_MERKLE_DEPTH 13

#define AnnMerkle_DEPTH Announce_MERKLE_DEPTH
#define AnnMerkle_NAME Announce_Merkle
#include "AnnMerkle.h"
_Static_assert(sizeof(Announce_Merkle_Branch) == (Announce_MERKLE_DEPTH+1)*64, "");
_Static_assert(sizeof(Announce_Merkle_Branch) == 896, "");

#define Announce_TABLE_SZ (1<<Announce_MERKLE_DEPTH)

#define Announce_lastAnnPfx_SZ \
    (1024 - sizeof(PacketCrypt_AnnounceHdr_t) - sizeof(Announce_Merkle_Branch))
_Static_assert(Announce_lastAnnPfx_SZ == 40, "");

typedef struct {
    PacketCrypt_AnnounceHdr_t hdr;
    Announce_Merkle_Branch merkleProof;
    uint8_t lastAnnPfx[Announce_lastAnnPfx_SZ];
} Announce_t;
_Static_assert(sizeof(Announce_t) == 1024, "");

union Announce_Union {
    PacketCrypt_Announce_t pcAnn;
    Announce_t ann;
};

void Announce_mkitem(uint64_t num, CryptoCycle_Item_t* item, Buf32_t* seed);

bool Announce_hasHighBits(const PacketCrypt_AnnounceHdr_t* annHdr);

int Announce_createProg(PacketCrypt_ValidateCtx_t* prog, Buf32_t* seed);

int Announce_mkitem2(uint64_t num, CryptoCycle_Item_t* item,
    Buf32_t* seed, PacketCrypt_ValidateCtx_t* ctx);

static inline void Announce_crypt(Announce_t* ann, const CryptoCycle_State_t* state) {
    int j = 0;
    for (int i = 0; i < (int)((sizeof ann->merkleProof) / 8 - 8); i++) {
        ((uint64_t*) &ann->merkleProof)[i] ^= ((uint64_t*)state)[j++];
    }
    for (int i = 0; i < (int)((sizeof ann->lastAnnPfx) / 8); i++) {
        ((uint64_t*) ann->lastAnnPfx)[i] ^= ((uint64_t*)state)[j++];
    }
}

#endif
