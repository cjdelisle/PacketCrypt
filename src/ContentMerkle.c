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

