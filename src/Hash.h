/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#ifndef HASH_H
#define HASH_H

#include "Buf.h"

#include <stdint.h>

void Hash_compress64(uint8_t output[static 64], uint8_t* buff, uint32_t len);
void Hash_compress32(uint8_t output[static 32], uint8_t* buff, uint32_t len);
void Hash_compressDoubleSha256(uint8_t output[static 32], uint8_t* buff, uint32_t len);
void Hash_expand(uint8_t* buff, uint32_t len, const uint8_t seed[static 32], uint32_t num);
void Hash_printHex(uint8_t* hash, int len);
void Hash_eprintHex(uint8_t* hash, int len);

#define Hash_COMPRESS64_OBJ(out, obj) do {\
    _Static_assert(Buf_SIZEOF(out) == 64, ""); \
    _Static_assert(Buf_SIZEOF(obj) != sizeof(char*), "sizeof a pointer, do you really want that?"); \
    Hash_compress64((out)->bytes, (uint8_t*)(obj), Buf_SIZEOF(obj)); \
} while (0)

#define Hash_COMPRESS32_OBJ(out, obj) do {\
    _Static_assert(Buf_SIZEOF(out) == 32, ""); \
    _Static_assert(Buf_SIZEOF(obj) != sizeof(char*), "sizeof a pointer, do you really want that?"); \
    Hash_compress32((out)->bytes, (uint8_t*)(obj), Buf_SIZEOF(obj)); \
} while (0)

#define Hash_COMPRESS32_DSHA256(out, obj) do {\
    _Static_assert(Buf_SIZEOF(out) == 32, ""); \
    _Static_assert(Buf_SIZEOF(obj) != sizeof(char*), "sizeof a pointer, do you really want that?"); \
    Hash_compressDoubleSha256((out)->bytes, (uint8_t*)(obj), Buf_SIZEOF(obj)); \
} while (0)

#endif
