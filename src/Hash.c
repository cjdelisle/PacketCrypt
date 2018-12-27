#include "Hash.h"
#include "sodium/crypto_generichash_blake2b.h"
#include "sodium/crypto_stream_chacha20.h"

#include <string.h>
#include <assert.h>

void Hash_compress64(uint8_t output[64], uint8_t* buff, uint32_t len) {
    crypto_generichash_blake2b(output, 64, buff, len, "CC_HSH64", 8);
}

void Hash_compress32(uint8_t output[32], uint8_t* buff, uint32_t len) {
    crypto_generichash_blake2b(output, 32, buff, len, "CC_HSH32", 8);
}

void Hash_expand(uint8_t* buff, uint32_t len, const uint8_t seed[32], uint64_t num) {
    memset(buff, 0, len);
    crypto_stream_chacha20_xor_ic(buff, buff, len, "CC_EXPND", num, seed);
}
