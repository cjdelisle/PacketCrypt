#ifndef RANDHASH_H
#define RANDHASH_H

#include "Buf.h"

#include <stdint.h>

typedef struct {
    uint32_t* insns;
    int len;
} RandHash_Program_t;

typedef struct RandHash_Compiled_s RandHash_Compiled_t;

// keep these powers of 2 because there is unsigned modulo using &
// Also be careful not to change these without also checking the buffers
// which are passed to RandHash_execute()
#define RandHash_MEMORY_SZ 256
#define RandHash_INOUT_SZ    8

// Program is too big
#define RandHash_TOO_BIG   -1

// Program is too small
#define RandHash_TOO_SMALL -2

// Overflowed the provided buffer
#define RandHash_ENOMEM    -3

// prog should contain a buffer where instructions can be placed and a length which
// is the size of the buffer in 4 byte words. If everything is ok, the result will be
// the length of the program.
int RandHash_generate(RandHash_Program_t* prog, Buf32_t* seed);

RandHash_Compiled_t* RandHash_compile(RandHash_Program_t* progs, int count);

void RandHash_freeProgram(RandHash_Compiled_t* prog);

// program cycles-to-execute errors
#define RandHash_TOO_LONG  -3
#define RandHash_TOO_SHORT -4
int RandHash_execute(
    RandHash_Compiled_t* prog,
    int programNum,
    Buf64_t* hash,
    uint32_t* memory,
    uint32_t memorySizeBytes,
    int cycles);

int RandHash_interpret(
    RandHash_Program_t* prog,
    Buf64_t* hash,
    uint32_t* memory,
    uint32_t memorySizeBytes,
    int cycles);

#endif
