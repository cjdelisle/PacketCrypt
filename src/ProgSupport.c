#include "Constants.h"

#include "sodium/crypto_stream_chacha20.h"
#include "sodium/crypto_generichash_blake2b.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

typedef struct {
    uint32_t cookie0;
    uint32_t hashIn[HASH_SZ];
    uint32_t cookie1;
    uint32_t hashOut[HASH_SZ];
    uint32_t cookie2;
    uint32_t memory[MEMORY_SZ];
    uint32_t cookie3;
} Context;

char* RANDHASH_SEED;

void run(uint32_t* hashOut, uint32_t* hashIn, uint32_t* memory, int cycles);

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("RandomHash program, generated from seed [%s]\n", RANDHASH_SEED);
        printf("Usage: %s <input>\n", argv[0]);
        return 100;
    }

    Context* ctx = calloc(sizeof(Context), 1);
    assert(ctx);

    crypto_generichash_blake2b(
        (uint8_t*)ctx->hashIn, sizeof ctx->hashIn,
        (uint8_t*)argv[1], strlen(argv[1]),
        (uint8_t*)"RH_ISEED", 8);

    _Static_assert(sizeof ctx->hashIn >= crypto_stream_chacha20_ietf_KEYBYTES, "");
    crypto_stream_chacha20_xor_ic(
            (uint8_t*)ctx->memory, (uint8_t*)ctx->memory, (sizeof(ctx->memory)),
            (uint8_t*)"RH_MEMRY", 0,
            (uint8_t*)ctx->hashIn);

    uint32_t cookie = ctx->hashIn[0];
    ctx->cookie0 = ctx->cookie1 = ctx->cookie2 = ctx->cookie3 = cookie;

    run(ctx->hashOut, ctx->hashIn, ctx->memory, CYCLES);

    assert(ctx->cookie0 == cookie);
    assert(ctx->cookie1 == cookie);
    assert(ctx->cookie2 == cookie);
    assert(ctx->cookie3 == cookie);

    for (int i = 0; i < HASH_SZ; i++) { printf("%08x", ctx->hashIn[i]); } printf("\n");

    free(ctx);
}
