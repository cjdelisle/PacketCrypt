/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#define _POSIX_C_SOURCE 200809L

#include "Time.h"

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

void Time_nsleep(long nanos) {
    struct timespec req = { 0, nanos };
    nanosleep(&req, NULL);
}

uint64_t Time_nowMilliseconds() {
    struct timeval tv;
    if (gettimeofday(&tv, NULL)) {
        fprintf(stderr, "gettimeofday failed [%s]\n", strerror(errno));
        assert(0);
    }
    return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}
