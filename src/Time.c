/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#define _POSIX_C_SOURCE 200809L

#include "Time.h"

#include <time.h>

void Time_nsleep(long nanos) {
    struct timespec req = { 0, nanos };
    nanosleep(&req, NULL);
}
