#include "Conf.h"
#include "Buf.h"
#include "Hash.h"
#include "Time.h"
#include "RandHash.h"

#include "sodium/crypto_stream_chacha20.h"
#include "sodium/crypto_generichash_blake2b.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

typedef struct {
    Buf64_t hash;
    uint32_t memory[RandHash_MEMORY_SZ];
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
    Hash_compress64(ctx->hash.bytes, (uint8_t*)argv[1], strlen(argv[1]));
    Hash_expand((uint8_t*)ctx->memory, sizeof ctx->memory, ctx->hash.bytes, sizeof(ctx->hash));

    Time t; Time_BEGIN(t);
    run(ctx->hash.thirtytwos[1].ints, ctx->hash.thirtytwos[0].ints, ctx->memory, 4000);
    Time_END(t);

    for (int i = 0; i < RandHash_INOUT_SZ; i++) { printf("%08x", ctx->hash.ints[i]); } printf("\n");

    printf("Time spent: %llu micros\n", Time_MICROS(t));
    
    free(ctx);
}
