/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#ifndef POOLPROTO_H
#define POOLPROTO_H

#include "packetcrypt/PacketCrypt.h"
#include "Buf.h"

typedef struct PoolProto_Work_t {
    PacketCrypt_BlockHeader_t blkHdr;
    Buf32_t contentHash;
    uint32_t shareTarget;
    uint32_t annTarget;
    int32_t height;
    uint32_t coinbaseLen;
    uint8_t coinbaseAndMerkles[];
} PoolProto_Work_t;

static inline bool PoolProto_Work_isValid(int totalLen, PoolProto_Work_t* work) {
    if (totalLen < (int)sizeof(PoolProto_Work_t)) { return false; }
    if (totalLen < ((int)sizeof(PoolProto_Work_t) + (int)work->coinbaseLen)) { return false; }
    if ((totalLen - (int)sizeof(PoolProto_Work_t) - work->coinbaseLen) % 32) { return false; }
    return true;
}

static inline int PoolProto_Work_merkleCount(int totalLen, PoolProto_Work_t* work) {
    if (!PoolProto_Work_isValid(totalLen, work)) { return -1; }
    return (totalLen - (int)sizeof(PoolProto_Work_t) - work->coinbaseLen) / 32;
}

#endif
