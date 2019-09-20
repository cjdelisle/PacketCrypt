/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#ifndef VEC_H
#define VEC_H

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

// Vector/stack
typedef struct {
    uint32_t* elems;
    uint32_t count;
    uint32_t max;
} Vec;
static inline void Vec_init(Vec* v, int initialMax) {
    v->elems = (uint32_t*) malloc(initialMax * sizeof(uint32_t));
    assert(v->elems);
    v->max = initialMax;
    v->count = 0;
}
static inline void Vec_free(Vec* v) { free(v->elems); }
static inline void Vec_push(Vec* v, uint32_t e) {
    if (v->count >= v->max) {
        if (!v->max) { v->max = 64; }
        v->max *= 2;
        //printf("realloc\n");
        v->elems = (uint32_t*) realloc(v->elems, v->max * sizeof(uint32_t));
        assert(v->elems);
    }
    v->elems[v->count++] = e;
}
static inline uint32_t Vec_pop(Vec* v) { return v->elems[--v->count]; }

#endif
