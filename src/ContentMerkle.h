#ifndef CONTENTMERKLE_H
#define CONTENTMERKLE_H

#include "Buf.h"

void ContentMerkle_compute(Buf32_t* outBuf, uint8_t* buf, uint32_t length);

const uint8_t* ContentMerkle_getProofBlock(
    uint32_t proofIdx,
    Buf32_t* buf,
    const uint8_t* content,
    uint32_t contentLen
);

#endif
