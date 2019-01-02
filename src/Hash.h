#ifndef HASH_H
#define HASH_H

#include <stdint.h>

void Hash_compress64(uint8_t output[static 64], uint8_t* buff, uint32_t len);
void Hash_compress32(uint8_t output[static 32], uint8_t* buff, uint32_t len);
void Hash_expand(uint8_t* buff, uint32_t len, const uint8_t seed[static 32], uint64_t num);
void Hash_printHex(uint8_t* hash, int len);
void Hash_eprintHex(uint8_t* hash, int len);

#endif
