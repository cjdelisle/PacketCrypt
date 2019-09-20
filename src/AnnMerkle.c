/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#include "Hash.h"
#include "Buf.h"
#define AnnMerkle_IMPL
#include "AnnMerkle.h"

#include "sodium/crypto_verify_64.h"

#include <stdbool.h>
#include <string.h>
#include <assert.h>

bool AnnMerkle__isItemValid(
    int depth,
    const uint8_t* merkleBranch,
    const Buf64_t* itemHash,
    uint16_t itemNo)
{
    Buf64_t b[2];
    memcpy(&b[itemNo & 1], itemHash, 64);
    for (int i = 0; i < depth; i++) {
        memcpy(&b[!(itemNo & 1)], &merkleBranch[i * 64], 64);
        itemNo >>= 1;
        Hash_compress64(b[itemNo & 1].bytes, b[0].bytes, 128);
    }
    return !crypto_verify_64(b[itemNo & 1].bytes, &merkleBranch[64 * depth]);
}

void AnnMerkle__build(int depth, uint8_t* out, uint8_t* table, int itemSz)
{
    int odx = 0;
    for (int i = 0; i < (1<<depth); i++) {
        Hash_compress64(&out[odx * 64], &table[odx * itemSz], itemSz);
        odx++;
    }
    int idx = 0;
    for (int d = depth - 1; d >= 0; d--) {
        for (int i = 0; i < (1<<d); i++) {
            Hash_compress64(&out[odx * 64], &out[idx * 64], 128);
            odx++;
            idx += 2;
        }
    }
    assert(odx == (1<<depth) * 2 - 1);
    assert(idx == odx - 1);
}

void AnnMerkle__getBranch(int depth, uint8_t* out, uint16_t itemNo, const uint8_t* merkle)
{
    uint16_t ino = itemNo;
    int odx = 0;
    int idx = 0;
    for (int o = depth; o > 0; o--) {
        memcpy(&out[odx * 64], &(&merkle[idx * 64])[(ino ^ 1) * 64], 64);
        idx += 1<<o;
        odx++;
        ino >>= 1;
    }
    // Copy the root
    memcpy(&out[odx * 64], &merkle[idx * 64], 64);
    odx++;

    // sanity check
    assert(idx == ((1<<depth) * 2 - 2));
    assert(odx == (depth + 1));
    assert(AnnMerkle__isItemValid(depth, out, (const Buf64_t*) &merkle[itemNo * 64], itemNo));
}
