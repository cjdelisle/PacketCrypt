#include "ChaCha.h"

#include "sodium/crypto_onetimeauth_poly1305.h"
#include "sodium/utils.h"
#include "sodium/crypto_stream_chacha20.h"

static inline int getLengthAndTruncate(ChaCha_Header_t* hdr)
{
    int len = ChaCha_getLength(hdr);
    int maxLen = 125 - ChaCha_getAddLen(hdr);
    int finalLen = (len > maxLen) ? maxLen : len;
    ChaCha_setTruncated(hdr, (finalLen != len));
    ChaCha_setLength(hdr, finalLen);
    return finalLen;
}

void ChaCha_crypt(ChaCha_Header_t* msg)
{
    if (ChaCha_getVersion(msg) != 0 || ChaCha_isFailed(msg)) {
        ChaCha_setFailed(msg, 1);
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
    uint64_t aeadLen = ChaCha_getAddLen(msg) * 16;
    uint64_t msgLen = getLengthAndTruncate(msg) * 16;
    uint8_t* msgContent = &aead[aeadLen];
    crypto_onetimeauth_poly1305_update(&state, aead, aeadLen);

    int decrypt = ChaCha_isDecrypt(msg);
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
        slen[0] = ChaCha_LE(aeadLen);
        slen[2] = ChaCha_LE(msgLen);
        crypto_onetimeauth_poly1305_update(&state, (uint8_t*) slen, 16);
    }

    crypto_onetimeauth_poly1305_final(&state, msg->key_high_or_auth);
}
