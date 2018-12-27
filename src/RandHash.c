#include "RandGen.h"
#include "RandHash.h"
#include "config.h"

#define RandHash_IMPL interpreted // TODO

#ifndef RandHash_IMPL
    #error RandHash_IMPL is not defined
#endif
#define IMPL(a) _IMPL(a, RandHash_IMPL)
#define _IMPL(a,b) GLUE(RandHash_, a, _, b)
#define GLUE(a,b,c,d) a ## b ## c ## d

RandHash_Compiled_t* IMPL(compile)(RandHash_Program_t* progs, int count);
void IMPL(freeProgram)(RandHash_Compiled_t* prog);
int IMPL(execute)(
    RandHash_Compiled_t* prog,
    int programNum,
    Buf64_t* hash,
    uint32_t* memory,
    uint32_t memorySizeBytes,
    int cycles);

int RandHash_generate(RandHash_Program_t* prog, Buf32_t* seed) {
    int ret = RandGen_generate(prog->insns, prog->len, seed);
    prog->len = ret;
    return ret;
}

RandHash_Compiled_t* RandHash_compile(RandHash_Program_t* progs, int count) {
    return IMPL(compile)(progs, count);
}

void RandHash_freeProgram(RandHash_Compiled_t* prog) { IMPL(freeProgram)(prog); }

int RandHash_execute(
    RandHash_Compiled_t* prog,
    int programNum,
    Buf64_t* hash,
    uint32_t* memory,
    uint32_t memorySizeBytes,
    int cycles)
{
    return IMPL(execute)(prog, programNum, hash, memory, memorySizeBytes, cycles);
}
