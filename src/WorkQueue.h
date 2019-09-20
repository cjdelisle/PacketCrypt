/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#pragma once

#include "FilePath.h"

#include <stdbool.h>

enum WorkQueue_FileState {
    FileState_DONE = 0,
    FileState_TODO,
    FileState_IN_PROGRESS
};

typedef struct WorkQueue_File_s {
    enum WorkQueue_FileState fs;
    FilePath_t fp;
} WorkQueue_File_t;

#define WorkQueue_SIZE 32

typedef struct WorkQueue_s WorkQueue_t;

// Get more work to do, if work is completed then pass it as the second argument
// returns NULL if the thread should stop in an orderly mannor.
FilePath_t* WorkQueue_workerGetWork(WorkQueue_t* q, FilePath_t* completed);

void WorkQueue_start(WorkQueue_t* q, void* (workerLoop)(void*), void* workerContexts, size_t workerCtxSz);
WorkQueue_t* WorkQueue_create(const char* inDir, const char* pattern, int threadCount);

void WorkQueue_destroy(WorkQueue_t* q);

bool WorkQueue_masterScan(WorkQueue_t* q);

void WorkQueue_stop(WorkQueue_t* q);
