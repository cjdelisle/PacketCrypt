#ifndef INTERPRETER_H
#define INTERPRETER_H

#include <stdint.h>

int Interpreter_run(
    uint32_t* prog, int progLen,
    uint32_t* hashOut, uint32_t* hashIn, uint32_t* memory, int cycles);

#endif
