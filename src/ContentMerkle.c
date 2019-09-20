/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#include "ContentMerkle.h"
#include "Hash.h"
#include "Util.h"
#include "Buf.h"

static void computeCycle(Buf32_t* outBuf, uint8_t* buf, int realLength, int chunkLength) {
    if (realLength <= 32 || chunkLength == 32) {
        Buf_OBJSET(outBuf, 0);
        memcpy(outBuf->bytes, buf, realLength);
        return;
    }
    int halfLen = chunkLength >> 1;
    if (halfLen >= realLength) {
        computeCycle(outBuf, buf, realLength, halfLen);
        return;
    }
    Buf64_t b = {{0}};
    computeCycle(&b.thirtytwos[0], buf, halfLen, halfLen),
    computeCycle(&b.thirtytwos[1], &buf[halfLen], realLength - halfLen, halfLen);
    Hash_COMPRESS32_OBJ(outBuf, &b);
}

void ContentMerkle_compute(Buf32_t* outBuf, uint8_t* buf, uint32_t length)
{
    computeCycle(outBuf, buf, length, 1 << Util_log2ceil(length));
}

const uint8_t* ContentMerkle_getProofBlock(
    uint32_t proofIdx,
    Buf32_t* buf,
    const uint8_t* content,
    uint32_t contentLen
) {
    if (contentLen <= 32) { return NULL; }
    assert(content);
    uint32_t totalBlocks = contentLen / 32;
    if (totalBlocks*32 < contentLen) { totalBlocks++; }
    uint32_t idx = (proofIdx % totalBlocks) * 32;
    if ((idx + 32) > contentLen) {
        int len = contentLen - idx;
        Buf_OBJSET(buf, 0);
        memcpy(buf->bytes, &content[idx], len);
        return buf->bytes;
    } else {
        return &content[idx];
    }
}
