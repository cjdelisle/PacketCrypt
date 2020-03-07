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
} Job_t;

typedef struct Worker_s Worker_t;
struct AnnMiner_s {
    int numWorkers;
    Worker_t* workers;

    HeaderAndHash_t hah;

    int sendPtr;
    bool paranoia;
    bool active;
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
    //Job_t* activeJob;
    Job_t job;

    Announce_t ann;
    CryptoCycle_State_t state;
    PacketCrypt_ValidateCtx_t vctx;

    AnnMiner_t* ctx;
    pthread_t thread;

    // read by the main thread
    sig_atomic_t microsPerAnn;

    uint32_t workerNum;

    Time timeBetweenFinds;

    uint32_t threadMinMicrosPerAnn;

    int softNonce;
    int softNonceMax;

    _Atomic enum ThreadState reqState;
    _Atomic enum ThreadState workerState;
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
    assert(!pthread_cond_destroy(&ctx->cond));
    assert(!pthread_mutex_destroy(&ctx->lock));
    free(ctx->workers);
    free(ctx);
}

static void populateTable(CryptoCycle_Item_t* table, Buf64_t* annHash0) {
    for (int i = 0; i < Announce_TABLE_SZ; i++) {
        Announce_mkitem(i, &table[i], &annHash0->thirtytwos[0]);
    }
}

// -1 means try again
static int populateTable2(Worker_t* w, Buf64_t* seed) {
    if (Announce_createProg(&w->vctx, &seed->thirtytwos[0])) {
        return -1;
    }
    for (int i = 0; i < Announce_TABLE_SZ; i++) {
        // Allow this to be interrupted in case we should stop
        if (getRequestedState(w) != ThreadState_RUNNING) { return -1; }
        if (Announce_mkitem2(i, &w->job.table[i], &seed->thirtytwos[1], &w->vctx)) {
            return -1;
        }
    }
    return 0;
}

// 1 means success
static int annHash(Worker_t* restrict w, uint32_t nonce) {
    CryptoCycle_init(&w->state, &w->job.annHash1.thirtytwos[0], nonce);
    int itemNo = -1;
    int randHashCycles = (w->job.hah.annHdr.version > 0) ? 0 : Conf_AnnHash_RANDHASH_CYCLES;
    for (int i = 0; i < 4; i++) {
        itemNo = (CryptoCycle_getItemNo(&w->state) % Announce_TABLE_SZ);
        CryptoCycle_Item_t* restrict it = &w->job.table[itemNo];
        if (Util_unlikely(!CryptoCycle_update(&w->state, it, NULL, randHashCycles, &w->vctx))) {
            return 0;
        }
    }
    uint32_t target = w->job.hah.annHdr.workBits;

    CryptoCycle_final(&w->state);
    if (!Work_check(w->state.bytes, target)) { return 0; }
    //if (w->ctx->test) { Hash_printHex(w->state.bytes, 32); }

    Buf_OBJCPY(&w->ann.hdr, &w->job.hah.annHdr);
    Buf_OBJCPY_LDST(w->ann.hdr.softNonce, &nonce);
    Announce_Merkle_getBranch(&w->ann.merkleProof, itemNo, &w->job.merkle);
    if (w->job.hah.annHdr.version > 0) {
        Buf_OBJSET(w->ann.lastAnnPfx, 0);
        Announce_crypt(&w->ann, &w->state);
        //Hash_eprintHex((uint8_t*)&w->ann, 1024);
    } else {
        Buf_OBJCPY_LDST(w->ann.lastAnnPfx, &w->job.table[itemNo]);
    }
    //printf("itemNo %d\n", itemNo);
    return 1;
}

#define HASHES_PER_CYCLE 8

static void search(Worker_t* restrict w)
{
    int nonce = w->softNonce;
    for (int i = 0; i < HASHES_PER_CYCLE; i++) {
        if (Util_likely(!annHash(w, nonce++))) { continue; }
        if (w->ctx->paranoia) {
            // Found an ann!
            PacketCrypt_Announce_t backup;
            Buf_OBJCPY(&backup, &w->ann);
            int res = Validate_checkAnn(
                NULL,
                (PacketCrypt_Announce_t*)&w->ann,
                w->job.parentBlockHash.bytes,
                &w->vctx);
            if (res) {
                fprintf(stderr, "Validate_checkAnn returned [%s]\n",
                    Validate_checkAnn_outToString(res));
                assert(0 && "Internal error: Validate_checkAnn() failed");
            }
            assert(!Buf_OBJCMP(&backup, &w->ann));
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
                assert(w->job.content);
                memcpy(&ann[1024], w->job.content, w->ann.hdr.contentLength);
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

        // update time since last find
        Time_END(w->timeBetweenFinds);
        uint64_t micros = Time_MICROS(w->timeBetweenFinds);
        // IIR with alpha of 0.25
        uint32_t mpa = w->microsPerAnn = w->microsPerAnn * 3 / 4 + (micros / 4);
        //fprintf(stderr, "Find in %llu micros (%u)\n", micros, w->microsPerAnn);
        Time_NEXT(w->timeBetweenFinds);

        //fprintf(stderr, "mpa = %u min = %u\n", mpa, w->threadMinMicrosPerAnn);
        if (mpa < w->threadMinMicrosPerAnn) {
            // Experimentation has shown that sleeping for as much time as it would take
            // to find another ann keeps the number about right.
            uint32_t sleepMicros = w->threadMinMicrosPerAnn;
            // fprintf(stderr, "Ann production too fast, sleeping for %u microseconds\n",
            //     sleepMicros);
            struct timespec ts;
            ts.tv_sec = sleepMicros / 1000000;
            sleepMicros -= ts.tv_sec * 1000000;
            ts.tv_nsec = sleepMicros * 1000;
            nanosleep(&ts, NULL);
        }
    }
    w->softNonce = nonce;

    return;
}

// If this returns non-zero then it failed, -1 means try again
static int getNextJob(Worker_t* w) {
    uint32_t hn = w->job.hah.annHdr.hardNonce;
    w->job.hah.annHdr.hardNonce = w->ctx->hah.annHdr.hardNonce;
    if (Buf_OBJCMP(&w->job.hah.annHdr, &w->ctx->hah.annHdr)) {
        Buf_OBJCPY(&w->job.hah, &w->ctx->hah);
        w->job.hah.annHdr.hardNonce += w->workerNum;
    } else {
        // Always put back the hash because it gets mangled during the mining process
        Buf_OBJCPY(&w->job.hah.hash, &w->ctx->hah.hash);
        w->job.hah.annHdr.hardNonce = hn + w->ctx->numWorkers;
    }
    Hash_COMPRESS64_OBJ(&w->job.annHash0, &w->job.hah);

    if (w->job.hah.annHdr.version > 0) {
        int pt = populateTable2(w, &w->job.annHash0);
        if (pt) { return pt; }
    } else {
        populateTable(w->job.table, &w->job.annHash0);
    }
    Announce_Merkle_build(&w->job.merkle, (uint8_t*)w->job.table, sizeof *w->job.table);

    Buf64_t* root = Announce_Merkle_root(&w->job.merkle);
    Buf_OBJCPY(&w->job.parentBlockHash, &w->job.hah.hash.thirtytwos[0]);
    Buf_OBJCPY(&w->job.hah.hash, root);
    Hash_COMPRESS64_OBJ(&w->job.annHash1, &w->job.hah);

    w->softNonceMax = Util_annSoftNonceMax(w->job.hah.annHdr.workBits);
    w->softNonce = 0;
    if (w->job.hah.annHdr.version > 0) {
        Buf64_t b[2];
        Buf_OBJCPY(&b[0], root);
        Buf_OBJCPY(&b[1], &w->job.annHash0);
        Hash_COMPRESS64_OBJ(&b[0], &b);
        int pt = populateTable2(w, &b[0]);
        if (pt) { return pt; }
    }
    return 0;
}

static bool checkStop(Worker_t* worker) {
    if (getRequestedState(worker) == ThreadState_RUNNING) {
        // This is checking a non-atomic memory address without synchronization
        // but if we don't read the most recent data, it doesn't matter, we'll
        // be back in 512 more cycles.
        return false;
    }
    pthread_mutex_lock(&worker->ctx->lock);
    for (;;) {
        enum ThreadState rts = getRequestedState(worker);
        if (rts != ThreadState_STOPPED) {
            setState(worker, rts);
            pthread_mutex_unlock(&worker->ctx->lock);
            if (rts == ThreadState_SHUTDOWN) {
                return true;
            }
            return false;
        }
        setState(worker, rts);
        pthread_cond_wait(&worker->ctx->cond, &worker->ctx->lock);
    }
}

static void* thread(void* vworker) {
    Worker_t* worker = vworker;
    for (;;) {
        if (checkStop(worker)) { return NULL; }
        if (worker->softNonce + HASHES_PER_CYCLE > worker->softNonceMax) {
            int x = 0;
            do {
                x = getNextJob(worker);
                if (checkStop(worker)) { return NULL; }
            } while (x);
        }
        search(worker);
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

void AnnMiner_start(AnnMiner_t* ctx, AnnMiner_Request_t* req, uint8_t* content, int version) {
    stopThreads(ctx);
    while (!threadsStopped(ctx)) { Time_nsleep(100000); }
    assert(version == 0 || version == 1);

    HeaderAndHash_t hah;
    Buf_OBJSET(&hah, 0);
    hah.annHdr.version = version;
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
    if (Buf_OBJCMP(&ctx->hah, &hah)) {
        Buf_OBJCPY(&ctx->hah, &hah);
        for (int i = 0; i < ctx->numWorkers; i++) {
            // Trigger the workers to rebuild the work immediately
            ctx->workers[i].softNonceMax = 0;
        }
    }

    uint32_t threadMinMicrosPerAnn = 0;
    if (req->maxAnnsPerSecond) {
        uint32_t minMicrosPerAnn = 1000000 / req->maxAnnsPerSecond;
        threadMinMicrosPerAnn = minMicrosPerAnn * ctx->numWorkers;
        //fprintf(stderr, "maps %u tmmpa = %u\n", req->maxAnnsPerSecond, threadMinMicrosPerAnn);
    }

    for (int i = 0; i < ctx->numWorkers; i++) {
        if (!ctx->active) {
            Time_BEGIN(ctx->workers[i].timeBetweenFinds);
        }
        ctx->workers[i].threadMinMicrosPerAnn = threadMinMicrosPerAnn;
        setRequestedState(ctx, &ctx->workers[i], ThreadState_RUNNING);
    }
    pthread_cond_broadcast(&ctx->cond);

    ctx->active = true;
    return;
}

AnnMiner_t* AnnMiner_create(
    uint32_t minerId,
    int threads,
    int* outFiles,
    int numOutFiles,
    enum AnnMiner_Flags flags)
{
    assert(threads);
    AnnMiner_t* ctx = allocCtx(threads);
    ctx->outFiles = calloc(sizeof(int), numOutFiles);
    assert(ctx->outFiles);
    ctx->numOutFiles = numOutFiles;
    memcpy(ctx->outFiles, outFiles, sizeof(int) * numOutFiles);
    ctx->sendPtr = (flags & AnnMiner_Flags_SENDPTR) != 0;
    ctx->paranoia = (flags & AnnMiner_Flags_PARANOIA) != 0;
    ctx->minerId = minerId;

    for (int i = 0; i < threads; i++) {
        ctx->workers[i].workerNum = i;
        assert(!pthread_create(&ctx->workers[i].thread, NULL, thread, &ctx->workers[i]));
    }
    return ctx;
}

void AnnMiner_stop(AnnMiner_t* ctx)
{
    ctx->active = false;
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

double AnnMiner_getAnnsPerSecond(const AnnMiner_t* ctx)
{
    double totalAnnsPerMicrosecond = 0.0;
    for (int i = 0; i < ctx->numWorkers; i++) {
        double mpa = ctx->workers[i].microsPerAnn;
        if (mpa == 0) { continue; }
        totalAnnsPerMicrosecond += (1.0 / mpa);
    }
    return totalAnnsPerMicrosecond * 1000000.0;
}
