#define _POSIX_C_SOURCE 200809L

#include "RandGen.h"
#include "PrintProg.h"
#include "RandHash.h"
#include "Hash.h"
#include "Time.h"

#include "sodium/crypto_stream_chacha20.h"
#include "sodium/crypto_generichash_blake2b.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

typedef struct {
    Buf32_t seed;
    RandHash_Program_t prog;
    int maxProg;
    Buf64_t hash;
    uint32_t memory[RandHash_MEMORY_SZ];
} Context;

static void usage(char* progname) {
    printf("Usage: %s [-c] <program_seed> [<hash_input>]\n", progname);
    printf("    %s <program_seed> <hash_input>\n", progname);
    printf("        # Create a program from program_seed then interpret it\n");
    printf("        # with hash_input as the input to hash.\n");
    printf("    %s -c <program_seed>\n", progname);
    printf("        # Create a program from program_seed\n then output C code\n");
    printf("        # for the program which will perform that hash\n");
}

static int doit(Context* ctx, bool flagC, char* seedStr, char* input) {

    ctx->prog.len = ctx->maxProg;
    int ret = RandHash_generate(&ctx->prog, &ctx->seed);
    if (ret < 0) {
        printf("No solution %s\n",
            (ret == RandHash_TOO_BIG) ? "TOO_BIG" :
                (ret == RandHash_TOO_SMALL) ? "TOO_SMALL" : "???");
        return -1;
    }

    if (flagC) {
        printf("char* RANDHASH_SEED = \"%s\";\n", seedStr);
        PrintProg_asC(ctx->prog.insns, ctx->prog.len);
    } else {
        Hash_compress64(ctx->hash.bytes, (uint8_t*)input, strlen(input));
        Hash_expand((uint8_t*)ctx->memory, RandHash_MEMORY_SZ, ctx->hash.bytes, sizeof(ctx->hash));
        int ret = RandHash_interpret(&ctx->prog, &ctx->hash, ctx->memory, sizeof ctx->memory, 2);
        if (ret) {
            printf("No solution %s\n",
                (ret == RandHash_TOO_LONG) ? "TOO_LONG" :
                    (ret == RandHash_TOO_SHORT) ? "TOO_SHORT" : "???");
            return -1;
        }
    }
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        usage(argv[0]);
        return 100;
    }

    bool flagC = false;
    bool flagS = false;

    int c = 0;
    while ((c = getopt(argc, argv, "cs")) != -1) {
        switch (c) {
            case 'c': flagC = true; break;
            case 's': flagS = true; break;
        }
    }

    int index = optind;
    char* seedStr =  (index < argc) ? argv[index++] : NULL;
    char* input =  (index < argc) ? argv[index++] : NULL;

    if (flagC && flagS) {
        printf("-c and -s cannot be used together\n");
        usage(argv[0]);
        return 100;
    } else if (!seedStr) {
        usage(argv[0]);
        return 100;
    } else if (!flagC && !input) {
        printf("2 arguments are required unless the -c flag is passed\n");
        usage(argv[0]);
        return 100;
    }

    Context* ctx = calloc(sizeof(Context), 1);
    assert(ctx);
    Hash_compress32(ctx->seed.bytes, (uint8_t*)seedStr, strlen(seedStr));
    ctx->maxProg = 2048;
    ctx->prog.insns = malloc(ctx->maxProg * sizeof(uint32_t));

    Time t;
    for (int i = 0; i < 8192*8; i++) {
        Time_BEGIN(t);
        int ret = doit(ctx, flagC, seedStr, input);
        if (!flagC) {
            if (!ret) { printf("SUCCESS\n"); }
            Hash_printHex(ctx->hash.bytes, 64);
            Time_END(t);
            printf("\nTime spent %lld microseconds\n", Time_MICROS(t));
        }
        if (!flagS) { break; }
        ctx->seed.longs[0]++;
    }

    free(ctx);
}
