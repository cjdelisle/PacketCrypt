/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#include "Hash.h"
#include "sodium/crypto_generichash_blake2b.h"
#include "sodium/crypto_stream_chacha20.h"
#include "sodium/crypto_hash_sha256.h"

#include <string.h>
#include <assert.h>
#include <stdio.h>

void Hash_compress64(uint8_t output[static 64], uint8_t* buff, uint32_t len) {
    assert(!crypto_generichash_blake2b(output, 64, buff, len, NULL, 0));
}

void Hash_compress32(uint8_t output[static 32], uint8_t* buff, uint32_t len) {
    assert(!crypto_generichash_blake2b(output, 32, buff, len, NULL, 0));
}

void Hash_compressDoubleSha256(uint8_t output[static 32], uint8_t* buff, uint32_t len) {
    assert(!crypto_hash_sha256(output, buff, len));
    assert(!crypto_hash_sha256(output, output, 32));
}

void Hash_expand(
    uint8_t* restrict buff, uint32_t len,
    const uint8_t* restrict seed,
    uint32_t num
) {
    uint32_t nonce[3] = { num };
    memcpy(&nonce[1], "PC_EXPND", 8);
    memset(buff, 0, len);
    assert(!crypto_stream_chacha20_ietf_xor_ic(buff, buff, len, (uint8_t*)&nonce, 0, seed));
}

void Hash_eprintHex(uint8_t* hash, int len)
{
    for (int i = 0; i < len; i++) { fprintf(stderr, "%02x", hash[i]); }
    fprintf(stderr, "\n");
}

void Hash_printHex(uint8_t* hash, int len)
{
    // little endian
    for (int i = len - 1; i >= 0; i--) { printf("%02x", hash[i]); }
    printf("\n");
}
