/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#include "CryptoCycle.h"
#include "RandHash.h"
#include "RandGen.h"
#include "Hash.h"

#include "sodium/crypto_onetimeauth_poly1305.h"
#include "sodium/utils.h"
#include "sodium/crypto_stream_chacha20.h"
#include "sodium/crypto_scalarmult_curve25519.h"

#include <string.h>
#include <assert.h>

void CryptoCycle_makeFuzzable(CryptoCycle_Header_t* restrict hdr)
{
    memcpy(&hdr->data, hdr->key_high_or_auth, 4);

    CryptoCycle_setVersion(hdr, 0);
    CryptoCycle_setFailed(hdr, 0);

    assert(CryptoCycle_isFailed(hdr) == 0);
    assert(CryptoCycle_getVersion(hdr) == 0);

    // Length must be at least 32 blocks (512 bytes) long
    CryptoCycle_setLength(hdr, CryptoCycle_getLength(hdr) | 32);
}

static inline int getLengthAndTruncate(CryptoCycle_Header_t* restrict hdr)
{
    int len = CryptoCycle_getLength(hdr);
    int maxLen = 125 - CryptoCycle_getAddLen(hdr);
    int finalLen = (len > maxLen) ? maxLen : len;
    CryptoCycle_setTruncated(hdr, (finalLen != len));
    CryptoCycle_setLength(hdr, finalLen);
    return finalLen;
}

void CryptoCycle_crypt(CryptoCycle_Header_t* restrict msg)
{
    if (CryptoCycle_getVersion(msg) != 0 || CryptoCycle_isFailed(msg)) {
        CryptoCycle_setFailed(msg, 1);
        return;
    }

    crypto_onetimeauth_poly1305_state state;
    {
        uint8_t block0[64U] = {0};
        crypto_stream_chacha20_ietf(block0, sizeof block0, msg->nonce, msg->key_high_or_auth);
        crypto_onetimeauth_poly1305_init(&state, block0);
        sodium_memzero(block0, sizeof block0);
    }

    uint8_t* aead = (uint8_t*) &msg[1];
    uint64_t aeadLen = CryptoCycle_getAddLen(msg) * 16;
    uint64_t msgLen = getLengthAndTruncate(msg) * 16;
    int tzc = CryptoCycle_getTrailingZeros(msg);
    int azc = CryptoCycle_getAdditionalZeros(msg);
    uint8_t* msgContent = &aead[aeadLen];
    crypto_onetimeauth_poly1305_update(&state, aead, aeadLen);

    int decrypt = CryptoCycle_isDecrypt(msg);
    if (decrypt) {
        crypto_onetimeauth_poly1305_update(&state, msgContent, msgLen);
    }

    crypto_stream_chacha20_ietf_xor_ic(
        msgContent, msgContent, msgLen, msg->nonce, 1U, msg->key_high_or_auth);

    if (!decrypt) {
        if (tzc) { memset(&msgContent[msgLen-tzc], 0, tzc); }
        crypto_onetimeauth_poly1305_update(&state, msgContent, msgLen);
    }

    {
        uint64_t slen[2] = {0};
        slen[0] = ((uint64_t)aeadLen) - azc;
        slen[1] = ((uint64_t)msgLen) - tzc;
        crypto_onetimeauth_poly1305_update(&state, (uint8_t*) slen, 16);
    }
    crypto_onetimeauth_poly1305_final(&state, msg->key_high_or_auth);
}

void CryptoCycle_init(
    CryptoCycle_State_t* restrict state,
    const Buf32_t* restrict seed,
    uint64_t nonce)
{
    Hash_expand(state->bytes, sizeof(CryptoCycle_State_t), seed->bytes, 0);
    memcpy(state->hdr.nonce, &nonce, 8);
    CryptoCycle_makeFuzzable(&state->hdr);
}

bool CryptoCycle_update(
    CryptoCycle_State_t* restrict state,
    CryptoCycle_Item_t* restrict item,
    const uint8_t* restrict contentProof,
    int randHashCycles,
    PacketCrypt_ValidateCtx_t* ctx)
{
    if (randHashCycles) {
        #ifdef NO_RANDHASH
            assert(0);
        #else
        assert(ctx);
        int ret = RandGen_generate(ctx->progbuf, &item->thirtytwos[31]);
        if (ret < 0) { return false; }
        if (RandHash_interpret(ctx->progbuf, state, item->ints, ret, sizeof *item, randHashCycles)) {
            return false;
        }
        #endif
    }

    memcpy(state->sixteens[2].bytes, item, sizeof *item);
    if (contentProof) {
        memcpy(&state->bytes[32 + sizeof *item], contentProof, 32);
    }
    CryptoCycle_makeFuzzable(&state->hdr);
    CryptoCycle_crypt(&state->hdr);
    assert(!CryptoCycle_isFailed(&state->hdr));
    return true;
}

void CryptoCycle_smul(CryptoCycle_State_t* restrict state) {
    uint8_t pubkey[crypto_scalarmult_curve25519_BYTES];
    assert(!crypto_scalarmult_curve25519_base(pubkey, state->thirtytwos[1].bytes));
    assert(!crypto_scalarmult_curve25519(
        state->thirtytwos[2].bytes, state->thirtytwos[0].bytes, pubkey));
}

void CryptoCycle_final(CryptoCycle_State_t* restrict state) {
    Hash_compress32(state->bytes, state->bytes, sizeof *state);
}
