#include "RandGen.h"
#include "PrintProg.h"
#include "Interpreter.h"
#include "Constants.h"

#include "sodium/crypto_stream_chacha20.h"
#include "sodium/crypto_generichash_blake2b.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint32_t cookie0;
    uint32_t hashIn[HASH_SZ];
    uint32_t cookie1;
    uint32_t hashOut[HASH_SZ];
    uint32_t cookie2;
    uint32_t memory[MEMORY_SZ];
    uint32_t cookie3;
} Context;

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("Usage: randhash [-c] <program_seed> [<hash_input>]\n");
        printf("    randhash <program_seed> <hash_input> # Create a program from program_seed\n");
        printf("                                         # then execute it in the interpreter\n");
        printf("                                         # to hash hash_input\n");
        printf("    randhash -c <program_seed>           # Create a program from program_seed\n");
        printf("                                         # then output C code for the program\n");
        return 100;
    }

    char* seedStr = argv[1];
    char* input = argv[2];
    if (!strcmp(argv[1], "-c")) {
        seedStr = input;
        input = NULL;
    }

    uint8_t seed[32];
    crypto_generichash_blake2b(
        seed, 32, (uint8_t*)seedStr, strlen(seedStr), (uint8_t*)"RH_PSEED", 8);

    uint32_t insnCount = 0;
    uint32_t* insns = RandGen_generate(seed, &insnCount, MIN_INSNS, MAX_INSNS);

    if (!insns) {
        printf("No solution [%s]\n", insnCount ? "too big" : "too small");
        return 100;
    }

    if (!input) {
        printf("char* RANDHASH_SEED = \"%s\";\n", seedStr);
        PrintProg_asC(insns, insnCount);
    } else {
        Context* ctx = calloc(sizeof(Context), 1);
        assert(ctx);
        crypto_generichash_blake2b(
            (uint8_t*)ctx->hashIn, sizeof ctx->hashIn,
            (uint8_t*)input, strlen(input),
            (uint8_t*)"RH_ISEED", 8);

        _Static_assert(sizeof ctx->hashIn >= crypto_stream_chacha20_ietf_KEYBYTES, "");
        crypto_stream_chacha20_xor_ic(
                (uint8_t*)ctx->memory, (uint8_t*)ctx->memory, (sizeof(ctx->memory)),
                (uint8_t*)"RH_MEMRY", 0,
                (uint8_t*)ctx->hashIn);

        uint32_t cookie = ctx->hashIn[0];
        ctx->cookie0 = ctx->cookie1 = ctx->cookie2 = ctx->cookie3 = cookie;

        struct timeval tv0; gettimeofday(&tv0, NULL);
        int ops = Interpreter_run(insns, insnCount, ctx->hashOut, ctx->hashIn, ctx->memory, CYCLES);
        if (ops < MIN_OPS || ops > MAX_OPS) {
            printf("Too %s ops\n", (ops < MIN_OPS) ? "few" : "many");
            goto out;
        }
        struct timeval tv1; gettimeofday(&tv1, NULL);

        assert(ctx->cookie0 == cookie);
        assert(ctx->cookie1 == cookie);
        assert(ctx->cookie2 == cookie);
        assert(ctx->cookie3 == cookie);

        for (int i = 0; i < HASH_SZ; i++) { printf("%08x", ctx->hashIn[i]); } printf("\n");

        printf("Time spent: %llu micros ops: %d size: %u\n",
            ((tv1.tv_sec - tv0.tv_sec) * 1000000ull + tv1.tv_usec - tv0.tv_usec),
            ops, insnCount);

    out:
        free(ctx);
    }
    free(insns);
}
