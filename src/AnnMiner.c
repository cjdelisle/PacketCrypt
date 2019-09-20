/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#define _POSIX_C_SOURCE 200809L

#include "RandHash.h"
#include "Hash.h"
#include "Buf.h"
#include "CryptoCycle.h"
#include "Work.h"
#include "Time.h"
#include "Announce.h"
#include "packetcrypt/PacketCrypt.h"
#include "packetcrypt/AnnMiner.h"
#include "Conf.h"
#include "Util.h"
#include "packetcrypt/Validate.h"
#include "ContentMerkle.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <signal.h>

typedef struct {
    PacketCrypt_AnnounceHdr_t annHdr;
    Buf64_t hash;
} HeaderAndHash_t;

typedef struct {
    CryptoCycle_Item_t table[Announce_TABLE_SZ];

    Announce_Merkle merkle;
    Buf64_t annHash0; // hash(announce || parentBlockHash)
    Buf64_t annHash1; // hash(announce || merkleRoot)

    Buf32_t parentBlockHash;
    char* content;
    HeaderAndHash_t hah;

    pthread_rwlock_t jobLock;
    pthread_mutex_t updateLock;
} Job_t;

typedef struct Worker_s Worker_t;
struct AnnMiner_s {
    int numWorkers;
    Worker_t* workers;
    Job_t jobs[2];

    HeaderAndHash_t hah;

    int sendPtr;
    uint32_t minerId;

    int numOutFiles;
    int* outFiles;

    pthread_mutex_t lock;
    pthread_cond_t cond;
};

enum ThreadState {
    ThreadState_STOPPED,
    ThreadState_RUNNING,
    ThreadState_SHUTDOWN
};

struct Worker_s {
    Job_t* activeJob;
    Announce_t ann;
    CryptoCycle_State_t state;
    PacketCrypt_ValidateCtx_t vctx;

    AnnMiner_t* ctx;
    pthread_t thread;

    // read by the main thread
    sig_atomic_t hashesPerSecond;

    int softNonceMin;
    int softNonce;
    int softNonceMax;

    enum ThreadState reqState;
    enum ThreadState workerState;
};

static inline void setRequestedState(AnnMiner_t* ctx, Worker_t* w, enum ThreadState ts) {
    w->reqState = ts;
}
static inline enum ThreadState getRequestedState(Worker_t* w) {
    return w->reqState;
}
static inline void setState(Worker_t* w, enum ThreadState ts) {
    w->workerState = ts;
}
static inline enum ThreadState getState(AnnMiner_t* ctx, Worker_t* w) {
    return w->workerState;
}

static AnnMiner_t* allocCtx(int numWorkers)
{
    AnnMiner_t* ctx = calloc(sizeof(AnnMiner_t), 1);
    assert(ctx);
    assert(!pthread_mutex_init(&ctx->lock, NULL));
    assert(!pthread_cond_init(&ctx->cond, NULL));

    for (uint32_t i = 0; i < (sizeof(ctx->jobs) / sizeof(ctx->jobs[0])); i++) {
        pthread_rwlock_init(&ctx->jobs[i].jobLock, NULL);
        pthread_mutex_init(&ctx->jobs[i].updateLock, NULL);
    }

    ctx->numWorkers = numWorkers;
    ctx->workers = calloc(sizeof(Worker_t), numWorkers);
    assert(ctx->workers);
    for (int i = 0; i < numWorkers; i++) {
        ctx->workers[i].ctx = ctx;
    }
    return ctx;
}
static void freeCtx(AnnMiner_t* ctx)
{
    for (uint32_t i = 0; i < (sizeof(ctx->jobs) / sizeof(ctx->jobs[0])); i++) {
        pthread_rwlock_destroy(&ctx->jobs[i].jobLock);
        pthread_mutex_destroy(&ctx->jobs[i].updateLock);
    }
    assert(!pthread_cond_destroy(&ctx->cond));
    assert(!pthread_mutex_destroy(&ctx->lock));
    free(ctx->workers);
    free(ctx);
}

static void populateTable(CryptoCycle_Item_t* table, Buf64_t* annHash0) {
    for (int i = 0; i < Announce_TABLE_SZ; i++) { Announce_mkitem(i, &table[i], annHash0->bytes); }
}

// 1 means success
static int annHash(Worker_t* restrict w, uint32_t nonce) {
    CryptoCycle_init(&w->state, &w->activeJob->annHash1.thirtytwos[0], nonce);
    int itemNo = -1;
    for (int i = 0; i < 4; i++) {
        itemNo = (CryptoCycle_getItemNo(&w->state) % Announce_TABLE_SZ);
        CryptoCycle_Item_t* restrict it = &w->activeJob->table[itemNo];
        if (Util_unlikely(!CryptoCycle_update(
            &w->state, it, NULL, Conf_AnnHash_RANDHASH_CYCLES, &w->vctx)))
        {
            return 0;
        }
    }
    uint32_t target = w->activeJob->hah.annHdr.workBits;

    CryptoCycle_final(&w->state);
    if (!Work_check(w->state.bytes, target)) { return 0; }
    //if (w->ctx->test) { Hash_printHex(w->state.bytes, 32); }

    Buf_OBJCPY(&w->ann.hdr, &w->activeJob->hah.annHdr);
    Buf_OBJCPY_LDST(w->ann.hdr.softNonce, &nonce);
    Announce_Merkle_getBranch(&w->ann.merkleProof, itemNo, &w->activeJob->merkle);
    Buf_OBJCPY_LDST(w->ann.lastAnnPfx, &w->activeJob->table[itemNo]);
    //printf("itemNo %d\n", itemNo);
    return 1;
}

#define HASHES_PER_CYCLE 500

static void search(Worker_t* restrict w)
{
    Time t;
    Time_BEGIN(t);

    int nonce = w->softNonce;
    for (int i = 1; i < HASHES_PER_CYCLE; i++) {
        if (nonce > 0x00ffffff) { return; }
        if (Util_likely(!annHash(w, nonce++))) { continue; }
        // Found an ann!
        int res = Validate_checkAnn(
            NULL,
            (PacketCrypt_Announce_t*)&w->ann,
            w->activeJob->parentBlockHash.bytes,
            &w->vctx);
        if (res) {
            fprintf(stderr, "Validate_checkAnn returned [%s]\n",
                Validate_checkAnn_outToString(res));
            assert(0 && "Internal error: Validate_checkAnn() failed");
        }

        // Send the ann to an outfile segmented by it's hash so that if we are
        // submitting to a pool, the pool servers may insist that announcements
        // are only sent to different pool servers based on ann hash.
        Buf32_t hash;
        Hash_COMPRESS32_OBJ(&hash, &w->ann);
        int outFile = w->ctx->outFiles[hash.longs[0] % w->ctx->numOutFiles];

        if (w->ctx->sendPtr || w->ann.hdr.contentLength > 32) {
            ssize_t len = sizeof w->ann;
            if (w->ann.hdr.contentLength > 32) {
                len += w->ann.hdr.contentLength;
            }
            uint8_t* ann = malloc(len);
            assert(ann);
            memcpy(ann, &w->ann, sizeof w->ann);
            if (w->ann.hdr.contentLength > 32) {
                assert(w->activeJob->content);
                memcpy(&ann[1024], w->activeJob->content, w->ann.hdr.contentLength);
            }
            if (w->ctx->sendPtr) {
                PacketCrypt_Find_t f = {
                    .ptr = (uint64_t) (uintptr_t) ann,
                    .size = sizeof w->ann
                };
                ssize_t ret = write(outFile, &f, sizeof f);
                assert(ret == sizeof f || ret == -1);
            } else {
                ssize_t ret = write(outFile, ann, len);
                assert(ret == len || ret == -1);
                free(ann);
            }
        } else {
            ssize_t ret = write(outFile, &w->ann, sizeof w->ann);
            assert(ret == sizeof w->ann || ret == -1);
        }
    }
    w->softNonce = nonce;

    Time_END(t);
    w->hashesPerSecond = ((HASHES_PER_CYCLE * 1024) / (Time_MICROS(t) / 1024));
    Time_NEXT(t);

    //fprintf(stderr, "Cycle complete\n");

    return;
}

static void makeNextJob(HeaderAndHash_t* hah, Job_t* j, uint32_t nextHardNonce) {
    Buf_OBJCPY(&j->hah, hah);
    j->hah.annHdr.hardNonce = nextHardNonce;
    Hash_COMPRESS64_OBJ(&j->annHash0, &j->hah);

    populateTable(j->table, &j->annHash0);

    Announce_Merkle_build(&j->merkle, (uint8_t*)j->table, sizeof *j->table);

    Buf64_t* root = Announce_Merkle_root(&j->merkle);
    Buf_OBJCPY(&j->parentBlockHash, &j->hah.hash.thirtytwos[0]);
    Buf_OBJCPY(&j->hah.hash, root);
    Hash_COMPRESS64_OBJ(&j->annHash1, &j->hah);
}

static void getNextJob(Worker_t* w) {
    HeaderAndHash_t hah;
    Buf_OBJCPY(&hah, &w->activeJob->hah);
    Job_t* next = &w->ctx->jobs[(w->activeJob == &w->ctx->jobs[1])];
    assert(!pthread_rwlock_unlock(&w->activeJob->jobLock));

    assert(!pthread_mutex_lock(&next->updateLock));
    if (next->hah.annHdr.hardNonce != hah.annHdr.hardNonce + 1) {
        // We don't need double-checked locking here because we're holding
        // the updateLock so nobody else can be in here at the same time.
        assert(!pthread_rwlock_wrlock(&next->jobLock));
        fprintf(stderr, "AnnMiner: Updating hard_nonce\n");
        makeNextJob(&hah, next, hah.annHdr.hardNonce + 1);
        assert(!pthread_rwlock_unlock(&next->jobLock));
    }
    assert(!pthread_mutex_unlock(&next->updateLock));

    assert(!pthread_rwlock_rdlock(&next->jobLock));
    w->activeJob = next;
    w->softNonce = w->softNonceMin;
}

static bool checkStop(Worker_t* worker) {
    pthread_mutex_lock(&worker->ctx->lock);
    for (;;) {
        enum ThreadState rts = getRequestedState(worker);
        if (rts != ThreadState_STOPPED) {
            setState(worker, rts);
            pthread_mutex_unlock(&worker->ctx->lock);
            if (rts == ThreadState_SHUTDOWN) {
                pthread_rwlock_unlock(&worker->activeJob->jobLock);
                return true;
            }
            return false;
        }
        pthread_rwlock_unlock(&worker->activeJob->jobLock);
        setState(worker, rts);
        pthread_cond_wait(&worker->ctx->cond, &worker->ctx->lock);
        pthread_rwlock_rdlock(&worker->activeJob->jobLock);
    }
}

static void* thread(void* vworker) {
    Worker_t* worker = vworker;
    pthread_rwlock_rdlock(&worker->activeJob->jobLock);
    for (;;) {
        if (getRequestedState(worker) != ThreadState_RUNNING) {
            if (checkStop(worker)) { return NULL; }
        }
        search(worker);
        if (worker->softNonce + HASHES_PER_CYCLE > worker->softNonceMax) {
            if (checkStop(worker)) { return NULL; }
            getNextJob(worker);
        }
    }
}

static bool threadsStopped(AnnMiner_t* ctx) {
    for (int i = 0; i < ctx->numWorkers; i++) {
        enum ThreadState ts = getState(ctx, &ctx->workers[i]);
        if (ts == ThreadState_RUNNING) { return false; }
    }
    return true;
}

static void stopThreads(AnnMiner_t* ctx) {
    for (int i = 0; i < ctx->numWorkers; i++) {
        setRequestedState(ctx, &ctx->workers[i], ThreadState_STOPPED);
    }
}

void AnnMiner_start(AnnMiner_t* ctx, AnnMiner_Request_t* req, uint8_t* content) {
    stopThreads(ctx);
    while (!threadsStopped(ctx)) { Time_nsleep(100000); }

    HeaderAndHash_t hah;
    Buf_OBJSET(&hah, 0);
    hah.annHdr.hardNonce = ctx->minerId;
    hah.annHdr.workBits = req->workTarget;
    hah.annHdr.parentBlockHeight = req->parentBlockHeight;
    hah.annHdr.contentType = req->contentType;
    hah.annHdr.contentLength = req->contentLen;
    Buf_OBJCPY(hah.annHdr.signingKey, req->signingKey);

    Buf_OBJCPY(&hah.hash.thirtytwos[0], req->parentBlockHash);

    if (req->contentLen) {
        assert(content);
        if (req->contentLen <= 32) {
            memcpy(hah.annHdr.contentHash, content, req->contentLen);
        } else {
            ContentMerkle_compute((Buf32_t*)hah.annHdr.contentHash, content, req->contentLen);
        }
    }

    // if we're called with identical data, we should not reset the workers
    // because that will cause multiple searches of the same nonce space.
    if (Buf_OBJCMP(&ctx->hah, &hah) || !ctx->workers[0].activeJob) {
        Buf_OBJCPY(&ctx->hah, &hah);
        makeNextJob(&hah, &ctx->jobs[0], hah.annHdr.hardNonce);
        ctx->jobs[0].content = content;
        for (int i = 0; i < ctx->numWorkers; i++) {
            ctx->workers[i].activeJob = &ctx->jobs[0];
        }
    }

    for (int i = 0; i < ctx->numWorkers; i++) {
        setRequestedState(ctx, &ctx->workers[i], ThreadState_RUNNING);
    }
    pthread_cond_broadcast(&ctx->cond);

    return;
}

AnnMiner_t* AnnMiner_create(
    uint32_t minerId,
    int threads,
    int* outFiles,
    int numOutFiles,
    int sendPtr)
{
    assert(threads);
    AnnMiner_t* ctx = allocCtx(threads);
    ctx->outFiles = calloc(sizeof(int), numOutFiles);
    assert(ctx->outFiles);
    ctx->numOutFiles = numOutFiles;
    memcpy(ctx->outFiles, outFiles, sizeof(int) * numOutFiles);
    ctx->sendPtr = sendPtr;
    ctx->minerId = minerId;

    int softNonceStep = 0x00ffffff / threads;
    for (int i = 0; i < threads; i++) {
        ctx->workers[i].softNonceMin = softNonceStep * i;
        ctx->workers[i].softNonce = softNonceStep * i;
        ctx->workers[i].softNonceMax = softNonceStep * (i + 1);
        // this job is not active yet but we need to feed the threads a lock to start them up
        ctx->workers[i].activeJob = &ctx->jobs[0];
        assert(!pthread_create(&ctx->workers[i].thread, NULL, thread, &ctx->workers[i]));
    }
    return ctx;
}

void AnnMiner_stop(AnnMiner_t* ctx)
{
    stopThreads(ctx);
    while (!threadsStopped(ctx)) { Time_nsleep(100000); }
}

void AnnMiner_free(AnnMiner_t* ctx)
{
    for (int i = 0; i < ctx->numWorkers; i++) {
        setRequestedState(ctx, &ctx->workers[i], ThreadState_SHUTDOWN);
    }
    pthread_cond_broadcast(&ctx->cond);
    while (!threadsStopped(ctx)) { Time_nsleep(100000); }

    for (int i = 0; i < ctx->numWorkers; i++) {
        assert(!pthread_join(ctx->workers[i].thread, NULL));
    }

    freeCtx(ctx);
}

int64_t AnnMiner_getHashesPerSecond(AnnMiner_t* ctx)
{
    int64_t out = 0;
    for (int i = 0; i < ctx->numWorkers; i++) {
        out += ctx->workers[i].hashesPerSecond;
    }
    return out;
}
