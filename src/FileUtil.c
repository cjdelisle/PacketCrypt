/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#define _GNU_SOURCE // for memmem

#include "FileUtil.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

void FileUtil_checkDir(const char* type, const char* dir) {
    DIR* d = opendir(dir);
    if (!d) {
        fprintf(stderr, "Could not access %s directory [%s] because [%s]",
            type, dir, strerror(errno));
        assert(0);
    }
    closedir(d);
}

void FileUtil_mkNonblock(int fileno) {
    // reasonably cross-platform way to check if the parent is dead
    // read from stdin and if it's an eof then exit.
    int flags = fcntl(fileno, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(fileno, F_SETFL, flags);
}

void* FileUtil_memmem(const void *haystack, size_t haystacklen,
                      const void *needle, size_t needlelen)
{
    return memmem(haystack, haystacklen, needle, needlelen);
}
