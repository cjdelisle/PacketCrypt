#include "Writer.h"
#include "Codegen.h"

#include <sys/mman.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif
#define PROGRAM_MAX 4096 * 8

uint8_t* Codegen_mmap_executable()
{
    void* map = mmap(NULL,
        PROGRAM_MAX,
        PROT_EXEC | PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1, 0
    );
    assert(map != MAP_FAILED);
    return map;
}

void Template_begin(uint64_t registers[8], void* ctx);
void Template_insertion_point();
void Template_end();

Codegen_Function Codegen_mkprog(uint8_t* execmem, uint16_t* insns, int len)
{
    uintptr_t prefix_len = (Template_insertion_point - Template_begin);
    uintptr_t suffix_len = (Template_end - Template_insertion_point);
    memcpy(execmem, Template_begin, prefix_len);

    struct Writer w = { .buf = execmem, .offset = prefix_len, .capacity = PROGRAM_MAX };
    Codegen_generate(&w, insns, len);
    assert(w.offset + suffix_len < w.capacity);
    memcpy(execmem + w.offset, Template_insertion_point, suffix_len);
    return (Codegen_Function) execmem;
}