#ifndef DIFFICULTY_H
#define DIFFICULTY_H

#include <stdint.h>
#include <stdbool.h>

uint32_t Difficulty_getEffectiveTarget(uint32_t blockTar, uint32_t annTar, uint64_t annCount);

uint32_t Difficulty_degradeAnnouncementTarget(uint32_t annTar, uint32_t annAgeBlocks);

bool Difficulty_isMinAnnDiffOk(uint32_t target);

#endif
