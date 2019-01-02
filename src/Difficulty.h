#ifndef DIFFICULTY_H
#define DIFFICULTY_H

#include <stdint.h>

uint32_t Difficulty_getEffectiveDifficulty(uint32_t blockTar, uint32_t annTar, uint64_t annCount);

#endif
