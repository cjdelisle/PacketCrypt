#ifndef CODEGEN_H
#define CODEGEN_H

#include <stdint.h>

void Codegen_generate(struct Writer* w, uint16_t* program, int length);

typedef void (*Codegen_Function)(uint64_t registers[8], uint64_t cycles);

Codegen_Function Codegen_mkprog(uint8_t* execmem, uint16_t* insns, int len);

uint8_t* Codegen_mmap_executable();

#endif