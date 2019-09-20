/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#ifndef FilePath_H
#define FilePath_H

#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#define FilePath_NAME_SZ 256

typedef struct FilePath_s {
    uint8_t* path;
    uint8_t* name;
} FilePath_t;

static inline void FilePath_create(FilePath_t* out, const char* path) {
    int len = strlen(path) + FilePath_NAME_SZ;
    if (path[strlen(path)-1] != '/') {
        len++;
    }
    out->path = malloc(len);
    assert(out->path);
    strcpy(out->path, path);
    out->name = &out->path[strlen(path)];
    if (path[strlen(path)-1] != '/') {
        out->name[0] = '/';
        out->name = &out->name[1];
    }
}

static inline void FilePath_destroy(FilePath_t* p) {
    free(p->path);
}

#endif
