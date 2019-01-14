#define _POSIX_C_SOURCE 200809L

#include "RandHash.h"
#include "Hash.h"
#include "Buf.h"
#include "CryptoCycle.h"
#include "Work.h"
#include "Time.h"
#include "Announce.h"
#include "PacketCrypt.h"
#include "Conf.h"
#include "Compiler.h"

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

static int usage() {
    printf("Usage: ./pcann [-t] <threads>\n");
    printf("    -t           # testing, no input\n");
    printf("    <threads>    # number of threads to use for hashing\n");
    return 100;
}

#define ITEM_HASHCOUNT (sizeof(PacketCrypt_Item_t) / 64)
#define TABLE_SZ (1<<Announce_MERKLE_DEPTH)

typedef struct {
    PacketCrypt_Item_t table[TABLE_SZ];

    Announce_Merkle merkle;
    Buf64_t annHash0; // hash(announce || parentBlockHash)
    Buf64_t annHash1; // hash(announce || merkleRoot)

    Announce_Header_t annHdr;
    Buf32_t parentBlockHash;
} Job_t;

typedef struct Worker_s Worker_t;
typedef struct {
    int numWorkers;
    Worker_t* workers;
    Job_t jobs[2];
    bool test;
    Time time;

    pthread_mutex_t lock;
    pthread_cond_t cond;
} Context_t;

enum ThreadState {
    ThreadState_STOPPED,
    ThreadState_RUNNING,
    ThreadState_SHUTDOWN,
    ThreadState_STALLED
};

struct Worker_s {
    Job_t* activeJob;
    Announce_t ann;
    PacketCrypt_State_t state;

    Context_t* ctx;
    pthread_t thread;
    int softNonce;
    int softNonceMax;

    enum ThreadState reqState;
    enum ThreadState workerState;
};

static inline void setRequestedState(Context_t* ctx, Worker_t* w, enum ThreadState ts) { w->reqState = ts; }
static inline enum ThreadState getRequestedState(Worker_t* w) { return w->reqState; }
static inline void setState(Worker_t* w, enum ThreadState ts) { w->workerState = ts; }
static inline enum ThreadState getState(Context_t* ctx, Worker_t* w) { return w->workerState; }

static Context_t* allocCtx(int numWorkers)
{
    Context_t* ctx = malloc(sizeof(Context_t));
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
static void freeCtx(Context_t* ctx)
{
    assert(!pthread_cond_destroy(&ctx->cond));
    assert(!pthread_mutex_destroy(&ctx->lock));
    free(ctx->workers);
    free(ctx);
}

static inline void memocycle(Buf64_t* buf, int bufcount, int cycles) {
    Buf64_t tmpbuf[2];
    for (int cycle = 0; cycle < cycles; cycle++) {
        for (int i = 0; i < bufcount; i++) {
            int p = (i - 1 + bufcount) % bufcount;
            uint32_t q = buf[p].ints[0] % (bufcount - 1);
            int j = (i + q) % bufcount;
            Buf64_t* mP = &buf[p];
            Buf64_t* mJ = &buf[j];
            for (int k = 0; k < 8; k++) { tmpbuf[0].longs[k] = mP->longs[k]; }
            for (int k = 0; k < 8; k++) { tmpbuf[1].longs[k] = mJ->longs[k]; }
            Hash_compress64(buf[i].bytes, tmpbuf[0].bytes, sizeof tmpbuf);
        }
    }
}
static void mkitem(uint64_t num, PacketCrypt_Item_t* item, uint8_t seed[64]) {
    Hash_expand(item->bytes, 64, seed, num);
    for (uint32_t i = 1; i < ITEM_HASHCOUNT; i++) {
        Hash_compress64(item->sixtyfours[i].bytes, item->sixtyfours[i-1].bytes, 64);
    }
    memocycle(item->sixtyfours, ITEM_HASHCOUNT, Conf_AnnHash_MEMOHASH_CYCLES);
}
static void populateTable(PacketCrypt_Item_t* table, Buf64_t* annHash0) {
    for (int i = 0; i < TABLE_SZ; i++) { mkitem(i, &table[i], annHash0->bytes); }
}

static bool isAnnOk(Announce_t* ann, Buf32_t* parentBlockHash) {
    Announce_t _ann;
    Buf_OBJCPY(&_ann.hdr, &ann->hdr);
    Buf_OBJCPY(&_ann.merkleProof.thirtytwos[0], parentBlockHash);
    Buf_OBJSET(&_ann.merkleProof.thirtytwos[1], 0);
    Buf_OBJSET(_ann.hdr.softNonce, 0);

    Buf64_t annHash0;
    Hash_compress64(annHash0.bytes, (uint8_t*)&_ann,
        (sizeof _ann.hdr + sizeof _ann.merkleProof.sixtyfours[0]));

    Buf_OBJCPY(&_ann.merkleProof.sixtyfours[0], &ann->merkleProof.sixtyfours[13]);

    Buf64_t annHash1;
    Hash_compress64(annHash1.bytes, (uint8_t*)&_ann,
        (sizeof _ann.hdr + sizeof _ann.merkleProof.sixtyfours[0]));

    PacketCrypt_Item_t item;
    PacketCrypt_State_t state;
    uint32_t softNonce = 0;
    Buf_OBJCPY_LSRC(&softNonce, ann->hdr.softNonce);
    PacketCrypt_init(&state, &annHash1.thirtytwos[0], softNonce);
    int itemNo = -1;
    for (int i = 0; i < 3; i++) {
        itemNo = PacketCrypt_getNum(&state) % TABLE_SZ;
        mkitem(itemNo, &item, annHash0.bytes);
        if (!PacketCrypt_update(&state, &item, Conf_AnnHash_RANDHASH_CYCLES)) { return false; }
    }

    _Static_assert(sizeof ann->item4Prefix == ITEM4_PREFIX_SZ, "");
    if (memcmp(&item, ann->item4Prefix, sizeof ann->item4Prefix)) {
        assert(0);
        return false;
    }

    Buf64_t itemHash; Hash_compress64(itemHash.bytes, (uint8_t*)&item, sizeof item);
    if (!Announce_Merkle_isItemValid(&ann->merkleProof, &itemHash, itemNo)) {
        assert(0);
        return false;
    }

    uint32_t target = ann->hdr.workBits;
    Buf_OBJCPY(&state.sixteens[0], &state.sixteens[12]);

    //Hash_printHex(state.bytes, 32);
    return Work_check(state.bytes, target);
}

// 1 means success
static int annHash(Worker_t* restrict w, uint32_t nonce) {
    PacketCrypt_init(&w->state, &w->activeJob->annHash1.thirtytwos[0], nonce);
    int itemNo = -1;
    for (int i = 0; i < 3; i++) {
        itemNo = PacketCrypt_getNum(&w->state) % TABLE_SZ;
        PacketCrypt_Item_t* restrict it = &w->activeJob->table[itemNo];
        if (Compiler_unlikely(!PacketCrypt_update(&w->state, it, Conf_AnnHash_RANDHASH_CYCLES))) {
            return 0;
        }
    }
    uint32_t target = w->activeJob->annHdr.workBits;

    if (Compiler_likely(!Work_check(w->state.bytes, target))) { return 0; }
    PacketCrypt_final(&w->state);
    if (!Work_check(w->state.bytes, target)) { return 0; }
    if (w->ctx->test) { Hash_printHex(w->state.bytes, 32); }

    Buf_OBJCPY(&w->ann.hdr, &w->activeJob->annHdr);
    Buf_OBJCPY_LDST(w->ann.hdr.softNonce, &nonce);
    Announce_Merkle_getBranch(&w->ann.merkleProof, itemNo, &w->activeJob->merkle);
    Buf_OBJCPY_LDST(w->ann.item4Prefix, &w->activeJob->table[itemNo]);
    //printf("itemNo %d\n", itemNo);
    return 1;
}

typedef struct {
    Announce_Header_t hdr;
    Buf64_t parentBlockHash;
} Request_t;

static int buildJob(Context_t* ctx, Request_t* req, Job_t* j)
{
    Time t; Time_BEGIN(t);

    Buf_OBJCPY(&j->annHdr, &req->hdr);
    Buf_OBJCPY(&j->parentBlockHash, &req->parentBlockHash.thirtytwos[0]);
    Buf_OBJSET(&req->parentBlockHash.thirtytwos[1], 0);
    Hash_compress64(j->annHash0.bytes, (uint8_t*)req, sizeof *req);

    populateTable(j->table, &j->annHash0);

    Announce_Merkle_build(&j->merkle, (uint8_t*)j->table, sizeof *j->table);

    Buf64_t* root = Announce_Merkle_root(&j->merkle);
    Buf_OBJCPY(&req->parentBlockHash, root);
    Hash_compress64(j->annHash1.bytes, (uint8_t*)req, sizeof *req);

    Time_END(t);
    fprintf(stderr, "populateTable took:  %lu microseconds\n", (unsigned long)Time_MICROS(t));
    return 0;
}

#define CYCLES_PER_SEARCH 100

// 1 == found
static int search(Worker_t* restrict w)
{
    int nonce = w->softNonce;
    for (int i = 1; i < CYCLES_PER_SEARCH; i++) {
        if (Compiler_likely(!annHash(w, nonce++))) { continue; }
        if (nonce > 0x00ffffff) { return 0; }
        assert(isAnnOk(&w->ann, &w->activeJob->parentBlockHash));
        //fprintf(stderr, "found\n");
        if (!w->ctx->test) {
            (void) write(STDOUT_FILENO, &w->ann, sizeof w->ann);
        }
    }
    w->softNonce = nonce;
    return 0;
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

static bool threadsStopped(Context_t* ctx) {
    for (int i = 0; i < ctx->numWorkers; i++) {
        enum ThreadState ts = getState(ctx, &ctx->workers[i]);
        if (ts == ThreadState_RUNNING) { return false; }
        if (ts == ThreadState_STALLED) { fprintf(stderr, "Stalled thread"); }
    }
    return true;
}

static bool threadsFinished(Context_t* ctx) {
    for (int i = 0; i < ctx->numWorkers; i++) {
        if (getState(ctx, &ctx->workers[i]) != ThreadState_SHUTDOWN) { return false; }
    }
    return true;
}

static void stopThreads(Context_t* ctx) {
    for (int i = 0; i < ctx->numWorkers; i++) {
        setRequestedState(ctx, &ctx->workers[i], ThreadState_STOPPED);
    }
}

static void setTestVal(Request_t* req) {
    memset(req, 0, sizeof *req);
    req->hdr.parentBlockHeight = 122;
    req->hdr.workBits = 0x1e0fffff;
    Buf_OBJCPY(&req->parentBlockHash.thirtytwos[0], "abcdefghijklmnopqrstuvwxyz01234");
}

static void nsleep(long nanos) {
    struct timespec req = { 0, nanos };
    nanosleep(&req, NULL);
}

static void mainLoop(Context_t* ctx)
{
    Request_t req;
    Request_t nextReq;
    int nextReqOs = 0;
    if (ctx->test) { setTestVal(&req); }
    Time_BEGIN(ctx->time);
    for (int hardNonce = 0; hardNonce < 0x7fffffff; hardNonce++) {
        for (int i = 0; i < 1000; i++) {
            if (!ctx->test) {
                ssize_t r = read(STDIN_FILENO, &nextReq, sizeof nextReq - nextReqOs);
                if (r > 0) {
                    nextReqOs += r;
                    //fprintf(stderr, "read %ld, %d\n", r, nextReqOs);
                    assert(((int)sizeof nextReq) - nextReqOs >= 0);
                    if (sizeof nextReq - nextReqOs == 0) {
                        //Hash_eprintHex((uint8_t*)&nextReq, sizeof nextReq);
                        Buf_OBJCPY(&req, &nextReq);
                        nextReqOs = 0;
                        hardNonce = nextReq.hdr.hardNonce;
                        break;
                    }
                }
            }
            nsleep(1000000);
        }
        req.hdr.hardNonce = hardNonce;
        Job_t* j = &ctx->jobs[hardNonce & 1];

        while (buildJob(ctx, &req, j)) {
            hardNonce += 2;
            req.hdr.hardNonce = hardNonce;
        }
        fprintf(stderr, "Starting job with difficulty %08x\n", req.hdr.workBits);
        stopThreads(ctx);
        while (!threadsStopped(ctx)) { nsleep(100000); }
        if (threadsFinished(ctx)) { return; }
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
        fprintf(stderr, "%lu hashes per second\n",
            (unsigned long)((totalHashes * 1024) / (Time_MICROS(ctx->time) / 1024)));
        Time_NEXT(ctx->time);

        pthread_cond_broadcast(&ctx->cond);
        if (ctx->test) { sleep(1); }
    }
}

int main(int argc, char** argv) {

    if (argc < 2) { return usage(); }

    char* arg = argv[1];

    bool test = false;
    if (!strcmp(arg, "-t")) {
        if (argc < 3) { return usage(); }
        arg = argv[2];
        test = true;
    }

    long n = strtol(arg, NULL, 10);
    if (n < 1 || n > 0xffff) { return usage(); }

    Context_t* ctx = allocCtx(n);
    ctx->test = test;
    for (int i = 0; i < n; i++) {
        pthread_create(&ctx->workers[i].thread, NULL, thread, &ctx->workers[i]);
    }

    assert(fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK) != -1);

    mainLoop(ctx);
    freeCtx(ctx);
}
