#include "RandHash.h"
#include "Hash.h"
#include "Buf.h"
#include "CryptoCycle.h"
#include "Work.h"
#include "Time.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

static int usage() {
    printf("Usage: ./pcann [-t] <threads>\n");
    printf("    -t           # testing, no input\n");
    printf("    <threads>    # number of threads to use for hashing\n");
    return 100;
}
// 01e74a6ef3575839f197c46a54ba8546 000b273b8513fa91bff76f7efccd043c
// xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx xxx
static void printhex(uint8_t* buff, int len) {
    for (int i = len - 1; i >= 0; i--) { printf("%02x", buff[i]); }
    printf("\n");
}

#define ITEM_HASHCOUNT 16
#define CompuCrypt_HASH_SZ 64
#define DEPTH 12
#define PROGRAM_CYCLES 2

// In theory, 2**12 programs can take 33MiB because Constants.h specifies
// MAX_INSNS at 2048, however this is not likely and since there is also
// a chance of a bad program, it's better to simply allocate 16MB and hope
// that on average they're less than half of the max size.
#define PROGRAM_SPACE4 (1024 * TABLE_SZ)

#define Merkle_DEPTH DEPTH
#define Merkle_NAME CCMerkle
#include "Merkle.h"
#define TABLE_SZ (1<<DEPTH)
_Static_assert(sizeof(CCMerkle_Branch) == (DEPTH+1)*64, "");

/**
 * Announcement header:
 *
 *     0               1               2               3
 *     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  0 |    version    |                   soft_nonce                  |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  4 |                          hard_nonce                           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  8 |                          work_bits                            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 12 |                     parent_block_height                       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 16 |                                                               |
 *    +                         content_type                          +
 * 20 |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 24 |                                                               |
 *    +                                                               +
 * 28 |                                                               |
 *    +                                                               +
 * 32 |                                                               |
 *    +                                                               +
 * 36 |                                                               |
 *    +                         content_hash                          +
 * 40 |                                                               |
 *    +                                                               +
 * 44 |                                                               |
 *    +                                                               +
 * 48 |                                                               |
 *    +                                                               +
 * 52 |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 
 * 
 * Announcement:
 * 
 * [ Header 0:56 ][ Merkle proof 56:888 ][ Item 4 Prefix 888:1024 ]
 */
typedef struct {
    uint8_t version;
    uint8_t softNonce[3];
    uint32_t hardNonce;
    uint32_t workBits;
    uint32_t parentBlockHeight;

    uint64_t contentType;
    uint8_t contentHash[32];
} AnnounceHdr_t;
_Static_assert(sizeof(AnnounceHdr_t) == 56, "");

#define ITEM4_PREFIX_SZ (1024 - sizeof(AnnounceHdr_t) - sizeof(CCMerkle_Branch))
typedef struct {
    AnnounceHdr_t hdr;
    CCMerkle_Branch merkleProof;
    uint8_t item4Prefix[ITEM4_PREFIX_SZ];
} Announce_t;
_Static_assert(sizeof(Announce_t) == 1024, "");

typedef union {
    CryptoCycle_Header_t hdr;
    Buf_TYPES(2048);
    Buf16_t sixteens[128];
    Buf32_t thirtytwos[64];
    Buf64_t sixtyfours[32];
} PcState_t;

typedef struct {
    Buf64_t bufs[ITEM_HASHCOUNT];
} Item_t;

typedef struct {
    Item_t table[TABLE_SZ];

    CCMerkle merkle;
    Buf64_t annHash0; // hash(announce || parentBlockHash)
    Buf64_t annHash1; // hash(announce || merkleRoot)

    AnnounceHdr_t annHdr;
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
    PcState_t state;

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
            Hash_compress64(buf[i].bytes, tmpbuf[0].bytes, CompuCrypt_HASH_SZ * 2);
        }
    }
}
static void mkitem(uint64_t num, Item_t* item, uint8_t seed[64]) {
    Hash_expand(item[0].bufs[0].bytes, CompuCrypt_HASH_SZ, seed, num);
    for (int i = 1; i < ITEM_HASHCOUNT; i++) {
        Hash_compress64(item->bufs[i].bytes, item->bufs[i-1].bytes, CompuCrypt_HASH_SZ);
    }
    memocycle(item->bufs, ITEM_HASHCOUNT, 1);
}
static void populateTable(Item_t* table, Buf64_t* annHash0) {
    for (int i = 0; i < TABLE_SZ; i++) { mkitem(i, &table[i], annHash0->bytes); }
}

#define MEMCPY4(dst, src, dstlen, srclen) do { \
        _Static_assert((srclen) == (dstlen), "srclen != dstlen"); \
        memcpy(dst, src, srclen);                                 \
    } while (0)

static bool ccUpdateState(PcState_t* state, Item_t* item)
{
    uint32_t progbuf[2048];
    RandHash_Program_t rhp = { .insns = progbuf, .len = 2048 };
    if (RandHash_generate(&rhp, &item->bufs[15].thirtytwos[1]) < 0) { return false; }
    if (RandHash_interpret(
        &rhp, &state->sixtyfours[1], item->bufs[0].ints, sizeof *item, PROGRAM_CYCLES))
    {
        return false;
    }

    memcpy(state->sixteens[2].bytes, item, sizeof(Item_t));
    CryptoCycle_makeFuzzable(&state->hdr);
    CryptoCycle_crypt(&state->hdr);
    assert(!CryptoCycle_isFailed(&state->hdr));
    return true;
}

static void ccInitState(PcState_t* state, const Buf64_t* seed, uint64_t nonce)
{
    // Note, only using half the seed bytes...
    Hash_expand(state->bytes, sizeof(PcState_t), seed->bytes, 0);
    state->hdr.nonce = nonce;
    CryptoCycle_makeFuzzable(&state->hdr);
    CryptoCycle_crypt(&state->hdr);
    assert(!CryptoCycle_isFailed(&state->hdr));
}
static int ccItemNo(const PcState_t* state)
{
    return state->sixteens[1].shorts[0] % TABLE_SZ;
}

static bool isAnnOk(Announce_t* ann, Buf32_t* parentBlockHash) {
    Announce_t _ann;
    MEMCPY4(&_ann.hdr, &ann->hdr, sizeof _ann.hdr, sizeof ann->hdr);
    MEMCPY4(_ann.merkleProof.thirtytwos[0].bytes, parentBlockHash->bytes,
        sizeof _ann.merkleProof.thirtytwos[0], sizeof *parentBlockHash);
    memset(_ann.merkleProof.thirtytwos[1].bytes, 0, 32);
    memset(_ann.hdr.softNonce, 0, sizeof _ann.hdr.softNonce);

    Buf64_t annHash0;
    Hash_compress64(annHash0.bytes, (uint8_t*)&_ann,
        (sizeof _ann.hdr + sizeof _ann.merkleProof.sixtyfours[0]));

    memcpy(_ann.merkleProof.sixtyfours[0].bytes,
        &ann->merkleProof.bytes[(sizeof ann->merkleProof) - 64], 64);

    Buf64_t annHash1;
    Hash_compress64(annHash1.bytes, (uint8_t*)&_ann,
        (sizeof _ann.hdr + sizeof _ann.merkleProof.sixtyfours[0]));

    Item_t item;
    PcState_t state;
    uint32_t softNonce = 0;
    memcpy(&softNonce, ann->hdr.softNonce, sizeof ann->hdr.softNonce);
    ccInitState(&state, &annHash1, softNonce);
    int itemNo = -1;
    for (int i = 0; i < 3; i++) {
        itemNo = ccItemNo(&state);
        mkitem(itemNo, &item, annHash0.bytes);
        if (!ccUpdateState(&state, &item)) { return false; }
    }

    _Static_assert(sizeof ann->item4Prefix == ITEM4_PREFIX_SZ, "");
    if (memcmp(&item, ann->item4Prefix, sizeof ann->item4Prefix)) {
        assert(0);
        return false;
    }

    Buf64_t itemHash; Hash_compress64(itemHash.bytes, (uint8_t*)&item, sizeof item);
    if (!CCMerkle_isItemValid(&ann->merkleProof, &itemHash, itemNo)) {
        assert(0);
        return false;
    }

    uint32_t target = ann->hdr.workBits;
    memcpy(state.bytes, state.sixteens[12].bytes, 16);
    //printhex(state.bytes, 32);
    return Work_check(state.bytes, target);
}

// 1 means success
static int ccHash(Worker_t* w, uint32_t nonce) {
    ccInitState(&w->state, &w->activeJob->annHash1, nonce);
    int itemNo = -1;
    for (int i = 0; i < 3; i++) {
        itemNo = ccItemNo(&w->state);
        Item_t* it = &w->activeJob->table[itemNo];
        if (!ccUpdateState(&w->state, it)) { return 0; }
    }
    uint32_t target = w->activeJob->annHdr.workBits;

    if (!Work_check(w->state.bytes, target)) { return 0; }
    memcpy(w->state.bytes, w->state.sixteens[12].bytes, 16);
    if (!Work_check(w->state.bytes, target)) { return 0; }
    printhex(w->state.bytes, 32);

    memcpy(&w->ann.hdr, &w->activeJob->annHdr, sizeof w->ann.hdr);
    memcpy(w->ann.hdr.softNonce, &nonce, sizeof(w->ann.hdr.softNonce));
    CCMerkle_getBranch(&w->ann.merkleProof, itemNo, &w->activeJob->merkle);
    memcpy(w->ann.item4Prefix, &w->activeJob->table[itemNo], sizeof w->ann.item4Prefix);
    return 1;
}

typedef struct {
    AnnounceHdr_t hdr;
    Buf64_t parentBlockHash;
} Request_t;

static int buildJob(Context_t* ctx, Request_t* req, Job_t* j)
{
    Time t; Time_BEGIN(t);

    MEMCPY4(&j->annHdr, &req->hdr, sizeof j->annHdr, sizeof req->hdr);
    MEMCPY4(j->parentBlockHash.bytes, req->parentBlockHash.thirtytwos[0].bytes,
        sizeof j->parentBlockHash, sizeof req->parentBlockHash.thirtytwos[0]);
    memset(req->parentBlockHash.thirtytwos[1].bytes, 0, sizeof req->parentBlockHash.thirtytwos[1]);
    Hash_compress64(j->annHash0.bytes, (uint8_t*)req, sizeof *req);

    populateTable(j->table, &j->annHash0);

    CCMerkle_build(&j->merkle, (uint8_t*)j->table, sizeof *j->table);

    memcpy(req->parentBlockHash.bytes, CCMerkle_root(&j->merkle), 64);
    Hash_compress64(j->annHash1.bytes, (uint8_t*)req, sizeof *req);

    Time_END(t);
    fprintf(stderr, "populateTable took:  %llu microseconds\n", Time_MICROS(t));
    return 0;
}

#define CYCLES_PER_SEARCH 100

// 1 == found
static int search(Worker_t* w)
{
    int nonce = w->softNonce;
    for (int i = 1; i < CYCLES_PER_SEARCH; i++) {
        if (!ccHash(w, nonce++)) { continue; }
        if (nonce > 0x00ffffff) { return 0; }
        assert(isAnnOk(&w->ann, &w->activeJob->parentBlockHash));
        if (!w->ctx->test) { write(STDOUT_FILENO, &w->ann, sizeof w->ann); }
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
    req->hdr.workBits = 0x20000fff;
    memcpy(req->parentBlockHash.bytes, "abcdefghijklmnopqrstuvwxyz012345", 32);
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
                nextReqOs += read(STDIN_FILENO, &nextReq, sizeof nextReq - nextReqOs);
                assert(((int)sizeof nextReq) - nextReqOs >= 0);
                if (sizeof nextReq - nextReqOs == 0) {
                    memcpy(&req, &nextReq, sizeof req);
                    nextReqOs = 0;
                    hardNonce = 0;
                    break;
                }
            }
            usleep(1000);
        }
        req.hdr.hardNonce = hardNonce;
        Job_t* j = &ctx->jobs[hardNonce & 1];

        while (buildJob(ctx, &req, j)) {
            hardNonce += 2;
            req.hdr.hardNonce = hardNonce;
        }
        stopThreads(ctx);
        while (!threadsStopped(ctx)) { usleep(100); }
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
        fprintf(stderr, "%llu hashes per second\n",
            (totalHashes * 1024) / (Time_MICROS(ctx->time) / 1024));
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

    mainLoop(ctx);
    freeCtx(ctx);
}
