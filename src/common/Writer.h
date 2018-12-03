#ifndef Writer_H
#define Writer_H

#include <stdint.h>
#include <assert.h>

struct Writer {
    uint8_t* buf;
    uint32_t offset;
    uint32_t capacity;
};

struct Writer_Insn {
    uint64_t data;
    uint8_t width;
};

static inline void Writer_op(struct Writer* w, struct Writer_Insn insn)
{
    uint64_t data = insn.data;
    assert(w->offset + insn.width < w->capacity);
    switch (insn.width) {
        case 8: w->buf[w->offset++] = (data >> 56);
        case 7: w->buf[w->offset++] = (data >> 48) & 0xff;
        case 6: w->buf[w->offset++] = (data >> 40) & 0xff;
        case 5: w->buf[w->offset++] = (data >> 32) & 0xff;
        case 4: w->buf[w->offset++] = (data >> 24) & 0xff;
        case 3: w->buf[w->offset++] = (data >> 16) & 0xff;
        case 2: w->buf[w->offset++] = (data >> 8)  & 0xff;
        case 1: w->buf[w->offset++] = data & 0xff; break;
        default: assert(0);
    }
}

#endif