#ifndef INTERPRETER_H
#define INTERPRETER_H

#include <stdint.h>

void Interpreter_run(uint64_t registers[8], uint16_t* program, int proglen);

#endif