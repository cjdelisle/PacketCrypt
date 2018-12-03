#if defined(__AMD64__) || defined(__X86_64__)
#define IS_AMD64
#endif

#ifdef IS_AMD64
#include "common/Codegen.h"
#endif

#include "portable/Hash.h"
#include "portable/Interpreter.h"
#include "common/Writer.h"
#include "common/Codegen.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>

static int usage() {
    printf("Usage: ./randhash value_to_hash\n");
    printf("CAUTION: See Readme.md for security considerations\n");
    return 100;
}

static void printhex(uint8_t* buff, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", buff[i]);
    }
    printf("\n");
}

#define PROGRAM_SZ 256
#define CYCLES 1000

static uint64_t native_hash(uint8_t out[32], uint8_t in[32])
{
    Codegen_Function prog = NULL;
    {
        uint16_t program[PROGRAM_SZ];
        Hash_expand((uint8_t*)program, PROGRAM_SZ * 2, in, "PROGRAM");
        uint8_t* execmem = Codegen_mmap_executable();
        prog = Codegen_mkprog(execmem, program, PROGRAM_SZ);
    }
    uint64_t registers[12];
    Hash_expand((uint8_t*)registers, 12 * 8, in, "REGISTRS");

    struct timeval tv0;
    gettimeofday(&tv0, NULL);
    prog(registers, CYCLES);
    struct timeval tv1;
    gettimeofday(&tv1, NULL);

    Hash_compress(out, (uint8_t*)registers, 12 * 8);
    return (tv1.tv_sec - tv0.tv_sec) * 1000000ull + tv1.tv_usec - tv0.tv_usec;
}

static uint64_t interpreted_hash(uint8_t out[32], uint8_t in[32])
{
    uint16_t program[PROGRAM_SZ];
    Hash_expand((uint8_t*)program, PROGRAM_SZ * 2, in, "PROGRAM");
    uint64_t registers[12];
    Hash_expand((uint8_t*)registers, 12 * 8, in, "REGISTRS");

    struct timeval tv0;
    gettimeofday(&tv0, NULL);
    for (int i = 0; i < CYCLES; i++) { Interpreter_run(registers, program, PROGRAM_SZ); }
    struct timeval tv1;
    gettimeofday(&tv1, NULL);

    Hash_compress(out, (uint8_t*)registers, 12 * 8);
    return (tv1.tv_sec - tv0.tv_sec) * 1000000ull + tv1.tv_usec - tv0.tv_usec;
}

int main(int argc, char** argv) {
    if (argc < 2) { return usage(); }
    uint8_t* input = (uint8_t*) argv[1];
    int inlen = strlen(argv[1]);

    uint8_t root[32];
    Hash_compress(root, input, inlen);

    uint8_t intr[32];
    uint64_t time_intr = interpreted_hash(intr, root);
    uint8_t native[32];
    uint64_t time_native = native_hash(native, root);

    printhex(intr, 32);
    printhex(native, 32);

    printf("Interpreted mode took: %llu microseconds\n", time_intr);
    printf("Native mode took:      %llu microseconds\n", time_native);
    return 0;
}