#ifndef HASH_H
#define HASH_H

#include <stdint.h>

void Hash_compress64(uint8_t output[64], uint8_t* buff, uint32_t len);
void Hash_compress32(uint8_t output[32], uint8_t* buff, uint32_t len);
void Hash_expand(uint8_t* buff, uint32_t len, const uint8_t seed[32], uint64_t num);

#endif
