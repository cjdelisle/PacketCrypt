/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#include "WorkQueue.h"

#include <pthread.h>
#include <errno.h>
#include <dirent.h>
#include <stdio.h>

typedef struct WorkQueue_Master_s {
    DIR* indir;
    const char* pattern;
    int threadCount;
    pthread_t* threads;
    char slots[WorkQueue_SIZE][FilePath_NAME_SZ];
} WorkQueue_Master_t;

struct WorkQueue_s {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    WorkQueue_Master_t* mt;
    bool shouldStop;
    WorkQueue_File_t files[WorkQueue_SIZE];
};

FilePath_t* WorkQueue_workerGetWork(WorkQueue_t* q, FilePath_t* completed) {
    pthread_mutex_lock(&q->lock);
    if (completed) {
        for (int i = 0; i < WorkQueue_SIZE; i++) {
            if (&q->files[i].fp == completed) {
                q->files[i].fs = FileState_DONE;
                completed = NULL;
                break;
            }
        }
    }
    FilePath_t* next = NULL;
    while (next == NULL) {
        if (q->shouldStop) { break; }
        pthread_cond_wait(&q->cond, &q->lock);
        for (int i = 0; i < WorkQueue_SIZE; i++) {
            if (q->files[i].fs != FileState_TODO) { continue; }
            q->files[i].fs = FileState_IN_PROGRESS;
            next = &q->files[i].fp;
            break;
        }
    }
    pthread_mutex_unlock(&q->lock);
    return next;
}

WorkQueue_t* WorkQueue_create(
    const char* inDir,
    const char* pattern,
    int threadCount
) {
    DIR* d = opendir(inDir);
    assert(d);

    WorkQueue_t* q = calloc(sizeof(WorkQueue_t), 1);
    assert(q);
    q->mt = calloc(sizeof(WorkQueue_Master_t), 1);
    assert(q->mt);

    q->mt->threads = calloc(sizeof(pthread_t), threadCount);
    assert(q->mt->threads);

    q->mt->indir = d;
    q->mt->pattern = pattern;
    q->mt->threadCount = threadCount;

    for (int i = 0; i < WorkQueue_SIZE; i++) {
        FilePath_create(&q->files[i].fp, inDir);
    }

    assert(!pthread_mutex_init(&q->lock, NULL));
    assert(!pthread_cond_init(&q->cond, NULL));
    return q;
}

void WorkQueue_start(
    WorkQueue_t* q,
    void* (workerLoop)(void*),
    void* workerContexts,
    size_t workerCtxSz
) {
    uint8_t* wc = (uint8_t*)workerContexts;
    assert(wc);
    for (int i = 0; i < q->mt->threadCount; i++) {
        void* workCtx = &wc[i * workerCtxSz];
        assert(workCtx);
        assert(&q->mt->threads[i]);
        assert(!pthread_create(&q->mt->threads[i], NULL, workerLoop, workCtx));
    }
}

void WorkQueue_destroy(WorkQueue_t* q) {
    assert(!pthread_mutex_destroy(&q->lock));
    assert(!pthread_cond_destroy(&q->cond));
    for (int i = 0; i < WorkQueue_SIZE; i++) {
        FilePath_destroy(&q->files[i].fp);
    }
    closedir(q->mt->indir);
    free(q->mt->threads);
    free(q->mt);
    free(q);
}

bool WorkQueue_masterScan(WorkQueue_t* q) {
    bool newFiles = false;
    for (;;) {
        errno = 0;
        struct dirent* file = readdir(q->mt->indir);
        if (file == NULL) {
            if (errno != 0) {
                fprintf(stderr, "WorkQueue: Error reading dir because [%s]\n", strerror(errno));
            }
            rewinddir(q->mt->indir);
            if (!newFiles) { return true; }
            break;
        }
        if (strncmp(file->d_name, q->mt->pattern, 6)) { continue; }
        char* emptySlot = NULL;
        bool exists = false;
        for (int i = 0; i < WorkQueue_SIZE; i++) {
            if (!q->mt->slots[i][0]) {
                emptySlot = q->mt->slots[i];
            } else if (!strcmp(q->mt->slots[i], file->d_name)) {
                exists = true;
                break;
            }
        }
        if (!exists && emptySlot) {
            strncpy(emptySlot, file->d_name, FilePath_NAME_SZ);
        }
        newFiles |= exists;
    }

    pthread_mutex_lock(&q->lock);
    for (int i = 0; i < WorkQueue_SIZE; i++) {
        if (q->files[i].fs != FileState_DONE) { continue; }
        if (!q->mt->slots[i][0]) {
            // nothing here
        } else if (!strcmp(q->files[i].fp.name, q->mt->slots[i])) {
            // one of our files is done
            q->mt->slots[i][0] = '\0';
        } else {
            // we have a new file to add
            q->files[i].fs = FileState_TODO;
            strncpy(q->files[i].fp.name, q->mt->slots[i], FilePath_NAME_SZ);
        }
    }
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->lock);

    return false;
}

void WorkQueue_stop(WorkQueue_t* q) {
    pthread_mutex_lock(&q->lock);
    q->shouldStop = true;
    pthread_cond_broadcast(&q->cond);
    pthread_mutex_unlock(&q->lock);

    for (int i = 0; i < q->mt->threadCount; i++) {
        assert(!pthread_join(q->mt->threads[i], NULL));
    }
}
