#include "Hash.h"
#include "blake2/blake2.h"
#include "chacha20/ecrypt-sync.h"

#include <string.h>
#include <assert.h>

void Hash_compress(uint8_t output[32], uint8_t* buff, uint32_t len) {
    blake2(output, 32, buff, len, NULL, 0);
}

void Hash_expand(uint8_t* buff, uint32_t len, const uint8_t seed[32], const char* id) {
    ECRYPT_ctx ctx;
    memset(&ctx, 0, sizeof(ECRYPT_ctx));
    memset(buff, 0, len);
    ECRYPT_keysetup(&ctx, seed, 256, 0);
    if (id) {
        uint8_t iv[8] = { 0 };
        assert(strlen(id) <= 8);
        strncpy((char*)iv, id, strlen(id));
        ECRYPT_ivsetup(&ctx, iv);
    }
    ECRYPT_encrypt_bytes(&ctx, buff, buff, len);
}