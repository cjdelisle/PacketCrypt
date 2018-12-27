#include "CryptoCycle.h"

#include "sodium/crypto_onetimeauth_poly1305.h"
#include "sodium/utils.h"
#include "sodium/crypto_stream_chacha20.h"

#include <string.h>
#include <assert.h>

void CryptoCycle_makeFuzzable(CryptoCycle_Header_t* hdr)
{
    memcpy(&hdr->data, hdr->key_high_or_auth, 4);

    CryptoCycle_setVersion(hdr, 0);
    CryptoCycle_setFailed(hdr, 0);

    assert(CryptoCycle_isFailed(hdr) == 0);
    assert(CryptoCycle_getVersion(hdr) == 0);

    // Length must be at least 32 blocks (512 bytes) long
    CryptoCycle_setLength(hdr, CryptoCycle_getLength(hdr) | 32);
}

static inline int getLengthAndTruncate(CryptoCycle_Header_t* hdr)
{
    int len = CryptoCycle_getLength(hdr);
    int maxLen = 125 - CryptoCycle_getAddLen(hdr);
    int finalLen = (len > maxLen) ? maxLen : len;
    CryptoCycle_setTruncated(hdr, (finalLen != len));
    CryptoCycle_setLength(hdr, finalLen);
    return finalLen;
}

void CryptoCycle_crypt(CryptoCycle_Header_t* msg)
{
    if (CryptoCycle_getVersion(msg) != 0 || CryptoCycle_isFailed(msg)) {
        CryptoCycle_setFailed(msg, 1);
        return;
    }

    crypto_onetimeauth_poly1305_state state;
    {
        uint8_t block0[64U] = {0};
        crypto_stream_chacha20_ietf(
            block0, sizeof block0, (uint8_t*) &msg->nonce, msg->key_high_or_auth);
        crypto_onetimeauth_poly1305_init(&state, block0);
        sodium_memzero(block0, sizeof block0);
    }

    uint8_t* aead = (uint8_t*) &msg[1];
    uint64_t aeadLen = CryptoCycle_getAddLen(msg) * 16;
    uint64_t msgLen = getLengthAndTruncate(msg) * 16;
    uint8_t* msgContent = &aead[aeadLen];
    crypto_onetimeauth_poly1305_update(&state, aead, aeadLen);

    int decrypt = CryptoCycle_isDecrypt(msg);
    if (decrypt) {
        crypto_onetimeauth_poly1305_update(&state, msgContent, msgLen);
    }

    crypto_stream_chacha20_ietf_xor_ic(
        msgContent, msgContent, msgLen, (uint8_t*) &msg->nonce, 1U, msg->key_high_or_auth);

    if (!decrypt) {
        crypto_onetimeauth_poly1305_update(&state, msgContent, msgLen);
    }
    
    {
        uint32_t slen[4] = {0};
        slen[0] = CryptoCycle_LE(aeadLen);
        slen[2] = CryptoCycle_LE(msgLen);
        crypto_onetimeauth_poly1305_update(&state, (uint8_t*) slen, 16);
    }

    crypto_onetimeauth_poly1305_final(&state, msg->key_high_or_auth);
}
