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
_Static_assert(sizeof(HeaderAndHash_t) == sizeof(PacketCrypt_AnnounceHdr_t)+64, "");

typedef struct {
    CryptoCycle_Item_t table[Announce_TABLE_SZ];

    Announce_Merkle merkle;
    Buf64_t annHash0; // hash(announce || parentBlockHash)
    Buf64_t annHash1; // hash(announce || merkleRoot)

    Buf32_t parentBlockHash;
    HeaderAndHash_t hah;
} Job_t;

typedef struct Worker_s Worker_t;
struct AnnMiner_s {
    int numWorkers;
    Worker_t* workers;
    Job_t jobs[2];
    Time time;
    int inFromOut;
    int outToIn;
    int outFromIn;
    int inToOut;
    int sendPtr;

    int numOutFiles;
    int* outFiles;

    pthread_t mainThread;

    // read by the main thread
    sig_atomic_t hashesPerSecond;

    pthread_mutex_t lock;
    pthread_cond_t cond;
};

enum ThreadState {
    ThreadState_STOPPED,
    ThreadState_RUNNING,
    ThreadState_SHUTDOWN,
    ThreadState_STALLED
};

struct Worker_s {
    Job_t* activeJob;
    Announce_t ann;
    CryptoCycle_State_t state;
    PacketCrypt_ValidateCtx_t vctx;

    AnnMiner_t* ctx;
    pthread_t thread;
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
    AnnMiner_t* ctx = malloc(sizeof(AnnMiner_t));
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
            &w->state, it, Conf_AnnHash_RANDHASH_CYCLES, w->vctx.progbuf)))
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

#define CYCLES_PER_SEARCH 100

static void search(Worker_t* restrict w)
{
    int nonce = w->softNonce;
    for (int i = 1; i < CYCLES_PER_SEARCH; i++) {
        if (nonce > 0x00ffffff) { return; }
        if (Util_likely(!annHash(w, nonce++))) { continue; }
        // Found an ann!
        assert(!Validate_checkAnn(
            NULL,
            (PacketCrypt_Announce_t*)&w->ann,
            w->activeJob->parentBlockHash.bytes,
            &w->vctx));

        // Send the ann to an outfile segmented by it's hash so that if we are
        // submitting to a pool, the pool servers may insist that announcements
        // are only sent to different pool servers based on ann hash.
        Buf32_t hash;
        Hash_COMPRESS32_OBJ(&hash, &w->ann);
        int outFile = w->ctx->outFiles[hash.longs[0] % w->ctx->numOutFiles];

        if (w->ctx->sendPtr) {
            uint8_t* ann = malloc(sizeof w->ann);
            assert(ann);
            memcpy(ann, &w->ann, sizeof w->ann);
            PacketCrypt_Find_t f = {
                .ptr = (uint64_t) ann,
                .size = sizeof w->ann
            };
            ssize_t ret = write(outFile, &f, sizeof f);
            assert(ret == sizeof f || ret == -1);
        } else {
            ssize_t ret = write(outFile, &w->ann, sizeof w->ann);
            assert(ret == sizeof w->ann || ret == -1);
        }
    }
    w->softNonce = nonce;
    return;
}

static bool stop(Worker_t* worker, bool stalled) {
    pthread_mutex_lock(&worker->ctx->lock);
    for (;;) {
        enum ThreadState rts = getRequestedState(worker);
        setState(worker, rts);
        if (rts != ThreadState_STOPPED) {
            if (rts != ThreadState_SHUTDOWN && stalled) {
                setState(worker, ThreadState_STALLED);
            } else {
                pthread_mutex_unlock(&worker->ctx->lock);
                return rts == ThreadState_SHUTDOWN;
            }
        }
        pthread_cond_wait(&worker->ctx->cond, &worker->ctx->lock);
    }
}

static void* thread(void* vworker) {
    Worker_t* worker = vworker;
    for (;;) {
        if (getRequestedState(worker) != ThreadState_RUNNING) {
            if (stop(worker, false)) { return NULL; }
        }
        search(worker);
        if (worker->softNonce + CYCLES_PER_SEARCH > worker->softNonceMax) {
            if (stop(worker, true)) { return NULL; }
        }
    }
}

static bool threadsStopped(AnnMiner_t* ctx) {
    for (int i = 0; i < ctx->numWorkers; i++) {
        enum ThreadState ts = getState(ctx, &ctx->workers[i]);
        if (ts == ThreadState_RUNNING) { return false; }
        if (ts == ThreadState_STALLED) { fprintf(stderr, "Stalled thread"); }
    }
    return true;
}

static bool threadsFinished(AnnMiner_t* ctx) {
    for (int i = 0; i < ctx->numWorkers; i++) {
        if (getState(ctx, &ctx->workers[i]) != ThreadState_SHUTDOWN) { return false; }
    }
    return true;
}

static void stopThreads(AnnMiner_t* ctx) {
    for (int i = 0; i < ctx->numWorkers; i++) {
        setRequestedState(ctx, &ctx->workers[i], ThreadState_STOPPED);
    }
}

#define Command_STOP     0
#define Command_START    1
#define Command_SHUTDOWN 2
typedef struct {
    uint32_t command;
    HeaderAndHash_t hah;
} Command_t;

static int tryRead(int fileNo, Command_t* cmd, int* osP)
{
    int os = *osP;
    ssize_t r = read(fileNo, &cmd[os], (sizeof *cmd) - os);
    if (r > 0) {
        os += r;
        assert(((int)sizeof *cmd) - os >= 0);
        *osP = os;
        if (sizeof *cmd - os == 0) {
            os = 0;
            return 0;
        }
    }
    return -1;
}

static void* mainLoop(void* vctx) {
    AnnMiner_t* ctx = vctx;
    Command_t currentCmd;
    Command_t nextCmd;
    int cmdOs = 0;
    int cmd = 0;
    int firstCycle = 0;
    Time_END(ctx->time);
    for (int hardNonce = 0;;) {
        if (firstCycle) {
            assert(4 == write(ctx->inToOut, "OK\r\n", 4));
            firstCycle = 0;
        }
        for (int i = 0; i < 1000; i++) {
            if (!tryRead(ctx->inFromOut, &nextCmd, &cmdOs)) {
                cmd = nextCmd.command;
                Buf_OBJCPY(&currentCmd, &nextCmd);
                cmdOs = 0;
                firstCycle = 1;
                break;
            }
            Time_nsleep(1000000);
        }
        if (cmd == Command_STOP) {
            stopThreads(ctx);
            while (!threadsStopped(ctx)) { Time_nsleep(100000); }
            continue;
        }
        if (cmd == Command_SHUTDOWN || hardNonce >= 0x7fffffff) {
            for (int i = 0; i < ctx->numWorkers; i++) {
                setRequestedState(ctx, &ctx->workers[i], ThreadState_SHUTDOWN);
            }
            while (!threadsStopped(ctx)) { Time_nsleep(100000); }
            assert(4 == write(ctx->inToOut, "OK\r\n", 4));
            return NULL;
        }
        //Time t; Time_BEGIN(t);

        Job_t* j = &ctx->jobs[hardNonce & 1];

        currentCmd.hah.annHdr.hardNonce = hardNonce;
        hardNonce++;

        Buf_OBJCPY(&j->hah, &currentCmd.hah);
        Hash_COMPRESS64_OBJ(&j->annHash0, &j->hah);

        populateTable(j->table, &j->annHash0);

        Announce_Merkle_build(&j->merkle, (uint8_t*)j->table, sizeof *j->table);

        Buf64_t* root = Announce_Merkle_root(&j->merkle);
        Buf_OBJCPY(&j->parentBlockHash, &j->hah.hash.thirtytwos[0]);
        Buf_OBJCPY(&j->hah.hash, root);
        Hash_COMPRESS64_OBJ(&j->annHash1, &j->hah);

        stopThreads(ctx);
        while (!threadsStopped(ctx)) { Time_nsleep(100000); }
        if (threadsFinished(ctx)) { return NULL; }
        int softNonceStep = 0x00ffffff / ctx->numWorkers;
        int totalHashes = 0;
        for (int i = 0; i < ctx->numWorkers; i++) {
            ctx->workers[i].activeJob = j;
            if (ctx->workers[i].softNonce) {
                totalHashes += (ctx->workers[i].softNonce - (softNonceStep * i));
            }
            ctx->workers[i].softNonce = softNonceStep * i;
            ctx->workers[i].softNonceMax = softNonceStep * (i + 1);
            setRequestedState(ctx, &ctx->workers[i], ThreadState_RUNNING);
        }

        Time_END(ctx->time);
        ctx->hashesPerSecond =
            (sig_atomic_t)((totalHashes * 1024) / (Time_MICROS(ctx->time) / 1024));
        Time_NEXT(ctx->time);

        pthread_cond_broadcast(&ctx->cond);
    }
}

static void readOk(AnnMiner_t* ctx) {
    uint8_t ok[4];
    assert(4 == read(ctx->outFromIn, ok, 4));
    assert(!memcmp(ok, "OK\r\n", 4));
}

void AnnMiner_start(
    AnnMiner_t* ctx,
    uint8_t contentHash[32],
    uint64_t contentType,
    uint32_t workTarget,
    uint32_t parentBlockHeight,
    uint8_t parentBlockHash[32])
{
    Command_t cmd;
    Buf_OBJSET(&cmd, 0);
    memcpy(cmd.hah.annHdr.contentHash, contentHash, 32);
    cmd.hah.annHdr.contentType = contentType;
    cmd.hah.annHdr.parentBlockHeight = parentBlockHeight;
    cmd.hah.annHdr.workBits = workTarget;
    memcpy(cmd.hah.hash.bytes, parentBlockHash, 32);

    cmd.command = Command_START;
    assert(write(ctx->outToIn, &cmd, sizeof cmd) == sizeof cmd);

    readOk(ctx);
    return;
}

AnnMiner_t* AnnMiner_create(int threads, int* outFiles, int numOutFiles, int sendPtr)
{
    AnnMiner_t* ctx = allocCtx(threads);
    ctx->outFiles = calloc(sizeof(int), numOutFiles);
    assert(ctx->outFiles);
    ctx->numOutFiles = numOutFiles;
    memcpy(ctx->outFiles, outFiles, sizeof(int) * numOutFiles);
    int pipefd[2] = { -1, -1 };
    assert(!pipe(pipefd));
    ctx->inFromOut = pipefd[0];
    ctx->outToIn = pipefd[1];
    assert(!pipe(pipefd));
    ctx->outFromIn = pipefd[0];
    ctx->inToOut = pipefd[1];
    assert(fcntl(ctx->inFromOut, F_SETFL, O_NONBLOCK) != -1);
    ctx->sendPtr = sendPtr;
    for (int i = 0; i < threads; i++) {
        assert(!pthread_create(&ctx->workers[i].thread, NULL, thread, &ctx->workers[i]));
    }
    pthread_create(&ctx->mainThread, NULL, mainLoop, ctx);
    return ctx;
}

void AnnMiner_stop(AnnMiner_t* ctx)
{
    Command_t cmd;
    Buf_OBJSET(&cmd, 0);
    cmd.command = Command_STOP;
    assert(write(ctx->outToIn, &cmd, sizeof cmd) == sizeof cmd);
    readOk(ctx);
}

void AnnMiner_free(AnnMiner_t* ctx)
{
    Command_t cmd;
    Buf_OBJSET(&cmd, 0);
    cmd.command = Command_SHUTDOWN;
    assert(write(ctx->outToIn, &cmd, sizeof cmd) == sizeof cmd);
    readOk(ctx);
    for (int i = 0; i < ctx->numWorkers; i++) {
        assert(!pthread_join(ctx->workers[i].thread, NULL));
    }
    assert(!pthread_join(ctx->mainThread, NULL));
    close(ctx->outToIn);
    close(ctx->inToOut);
    close(ctx->outFromIn);
    close(ctx->inFromOut);
    freeCtx(ctx);
}

int64_t AnnMiner_getHashesPerSecond(AnnMiner_t* ctx)
{
    return ctx->hashesPerSecond;
}
