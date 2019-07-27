#ifndef CONTENTMERKLE_H
#define CONTENTMERKLE_H

#include "Buf.h"

void ContentMerkle_compute(Buf32_t* outBuf, uint8_t* buf, uint32_t length);

#endif
