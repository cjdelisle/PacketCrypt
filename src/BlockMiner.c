#include "packetcrypt/BlockMiner.h"

//#include <stdint.h>

#include "Buf.h"
#include "Hash.h"
#include "PacketCryptProof.h"
#include "CryptoCycle.h"
//#include "Announce.h"
#include "Time.h"
#include "packetcrypt/PacketCrypt.h"
#include "Difficulty.h"
#include "Work.h"
#include "Util.h"

//#include <stdio.h>
//#include <string.h>
#include <stdlib.h>
#include <assert.h>
//#include <errno.h>
//#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

typedef struct Worker_s Worker_t;

typedef struct AnnounceList_s AnnounceList_t;
struct AnnounceList_s {
    PacketCrypt_Announce_t* anns;
    uint64_t count;
    AnnounceList_t* next;
};

enum ThreadState {
    ThreadState_STOPPED,
    ThreadState_RUNNING,
    ThreadState_SHUTDOWN,
};

enum State {
    State_UNLOCKED,
    State_LOCKED,
    State_MINING
};

typedef struct {
    PacketCrypt_Announce_t ann;
    uint32_t effectiveWork;
    uint64_t treePosition;
} Ann_t;

struct BlockMiner_s {
    Ann_t* anns;

    PacketCrypt_BlockHeader_t hdr;

    AnnounceList_t* queue;
    PacketCryptProof_Tree_t* tree;

    uint64_t annCapacity;
    uint64_t annCount;

    uint32_t effectiveTarget;

    enum State state;

    int fileNo;
    bool beDeterministic;

    int numWorkers;
    Worker_t* workers;

    pthread_mutex_t lock;
    pthread_cond_t cond;
};

struct Worker_s {
    CryptoCycle_State_t pcState;

    BlockMiner_t* bm;
    pthread_t thread;

    uint32_t nonceId;

    sig_atomic_t hashesPerSecond;

    enum ThreadState reqState;
    enum ThreadState workerState;
};

static inline void setRequestedState(BlockMiner_t* ctx, Worker_t* w, enum ThreadState ts) {
    w->reqState = ts;
}
static inline enum ThreadState getRequestedState(Worker_t* w) {
    return w->reqState;
}
static inline void setState(Worker_t* w, enum ThreadState ts) {
    w->workerState = ts;
}
static inline enum ThreadState getState(BlockMiner_t* ctx, Worker_t* w) {
    return w->workerState;
}

#define HASHES_PER_CYCLE 10000

typedef struct {
    PacketCrypt_BlockHeader_t hdr;
    uint64_t items[4];
    uint32_t lowNonce;
} MineResult_t;

typedef struct {
    PacketCrypt_Announce_t* anns;
    uint64_t count;
    uint32_t effectiveTarget;
    PacketCrypt_BlockHeader_t hdr;
} Job_t;

static void found(MineResult_t* res, PacketCrypt_BlockHeader_t* hdr, Worker_t* w)
{
    int proofSz = -1;
    uint8_t* proof = PacketCryptProof_mkProof(&proofSz, w->bm->tree, res->items);

    PacketCrypt_HeaderAndProof_t* output = malloc(sizeof(PacketCrypt_HeaderAndProof_t) + proofSz);
    assert(output);
    Buf_OBJCPY(&output->blockHeader, hdr);
    output->nonce2 = res->lowNonce;
    output->proofLen = proofSz;
    memcpy(output->proof, proof, proofSz);

    Buf32_t root2;
    Buf32_t hashes[PacketCrypt_NUM_ANNS];
    for (int i = 0; i < PacketCrypt_NUM_ANNS; i++) {
        Buf_OBJCPY(&output->announcements[i], &w->bm->anns[res->items[i]].ann);
        Hash_COMPRESS32_OBJ(&hashes[i], &w->bm->anns[res->items[i]].ann);
    }
    assert(!PacketCryptProof_hashProof(
        &root2, hashes, w->bm->annCount, res->items, proof, proofSz));
    assert(!Buf_OBJCMP(&root2, &w->bm->tree->root));

    // we are writing the pointer, not the content
    (void) write(w->bm->fileNo, &output, sizeof output);
    free(proof);
}

// returns true if there's a finding
static bool mine(Worker_t* w)
{
    Time t;
    Time_BEGIN(t);

    PacketCrypt_BlockHeader_t hdr;
    Buf_OBJCPY(&hdr, &w->bm->hdr);
    hdr.nonce = w->nonceId;
    hdr.timeSeconds = 0;

    uint32_t lowNonce = 0;

    for (;;) {
        if (hdr.timeSeconds != t.tv0.tv_sec && !w->bm->beDeterministic) {
            lowNonce = 0;
            hdr.timeSeconds = t.tv0.tv_sec;
        }
        Buf32_t hdrHash;
        Hash_COMPRESS32_OBJ(&hdrHash, &hdr);

        for (int i = 0; i < HASHES_PER_CYCLE; i++) {
            CryptoCycle_init(&w->pcState, &hdrHash, ++lowNonce);
            MineResult_t res;
            for (int j = 0; j < 4; j++) {
                uint64_t x = res.items[j] = PacketCrypt_getNum(&w->pcState) % w->bm->annCount;
                CryptoCycle_Item_t* it = (CryptoCycle_Item_t*) &w->bm->anns[x].ann;
                if (Util_unlikely(!CryptoCycle_update(&w->pcState, it, 0))) { continue; }
            }
            CryptoCycle_final(&w->pcState);
            if (!Work_check(w->pcState.bytes, w->bm->effectiveTarget)) { continue; }
            res.lowNonce = lowNonce;
            Buf_OBJCPY(&res.hdr, &hdr);
            found(&res, &hdr, w);
            fflush(stderr);
            return true;
        }
        Time_END(t);
        w->hashesPerSecond = ((HASHES_PER_CYCLE * 1024) / (Time_MICROS(t) / 1024));
        Time_NEXT(t);
        if (getRequestedState(w) != ThreadState_RUNNING) { return false; }
    }
}

static void* thread(void* vWorker)
{
    Worker_t* w = vWorker;
    for (;;) {
        enum ThreadState rs = getRequestedState(w);
        switch (rs) {
            case ThreadState_RUNNING: {
                if (!mine(w)) { break; }
                Util_fallthrough();
            }
            case ThreadState_STOPPED: {
                pthread_mutex_lock(&w->bm->lock);
                setState(w, ThreadState_STOPPED);
                pthread_cond_wait(&w->bm->cond, &w->bm->lock);
                pthread_mutex_unlock(&w->bm->lock);
                break;
            }
            case ThreadState_SHUTDOWN: {
                return NULL;
            }
        }
    }
}

BlockMiner_t* BlockMiner_create(
    uint64_t maxAnns, int threads, int fileNo, bool beDeterministic)
{
    Ann_t* annBuf = malloc(sizeof(Ann_t) * maxAnns);
    Worker_t* workers = calloc(sizeof(Worker_t), threads);
    PacketCryptProof_Tree_t* tree = PacketCryptProof_allocTree(maxAnns);
    BlockMiner_t* ctx = malloc(sizeof(BlockMiner_t));
    assert(annBuf && workers && tree && ctx);
    Buf_OBJSET(ctx, 0);

    for (uint64_t i = 0; i < maxAnns; i++) { annBuf[i].effectiveWork = -1; }

    assert(!pthread_mutex_init(&ctx->lock, NULL));
    assert(!pthread_cond_init(&ctx->cond, NULL));

    ctx->tree = tree;
    ctx->anns = annBuf;

    ctx->annCapacity = maxAnns;
    ctx->fileNo = fileNo;
    ctx->numWorkers = threads;
    ctx->workers = workers;
    ctx->beDeterministic = beDeterministic;
    for (int i = 0; i < threads; i++) {
        ctx->workers[i].bm = ctx;
        ctx->workers[i].nonceId = i;
        assert(!pthread_create(&ctx->workers[i].thread, NULL, thread, &ctx->workers[i]));
    }
    return ctx;
}

static void freeQueue(BlockMiner_t* ctx)
{
    AnnounceList_t* l = ctx->queue;
    while (l) {
        AnnounceList_t* ll = l->next;
        free(l->anns);
        free(l);
        l = ll;
    }
    ctx->queue = NULL;
}

void waitState(BlockMiner_t* ctx, enum ThreadState desiredState) {
    for (int i = 0; i < 10000; i++) {
        enum ThreadState ts = desiredState;
        for (int i = 0; i < ctx->numWorkers; i++) {
            enum ThreadState ts = getState(ctx, &ctx->workers[i]);
            if (ts == ThreadState_RUNNING) { break; }
        }
        if (ts == desiredState) {
            return;
        }
        Time_nsleep(100000);
    }
    assert(0 && "threads did not stop in 1 sec");
}

void BlockMiner_free(BlockMiner_t* ctx)
{
    for (int i = 0; i < ctx->numWorkers; i++) {
        setRequestedState(ctx, &ctx->workers[i], ThreadState_SHUTDOWN);
    }
    pthread_cond_broadcast(&ctx->cond);
    waitState(ctx, ThreadState_SHUTDOWN);

    free(ctx->anns);
    freeQueue(ctx);
    PacketCryptProof_freeTree(ctx->tree);
    free(ctx->workers);
    assert(!pthread_cond_destroy(&ctx->cond));
    assert(!pthread_mutex_destroy(&ctx->lock));
    free(ctx);
}

void BlockMiner_addAnns(BlockMiner_t* bm, PacketCrypt_Announce_t* anns, uint64_t count)
{
    AnnounceList_t* l = malloc(sizeof(AnnounceList_t));
    PacketCrypt_Announce_t* annsCpy = malloc(sizeof(PacketCrypt_Announce_t) * count);
    assert(l && anns);
    memcpy(annsCpy, anns, sizeof(PacketCrypt_Announce_t) * count);
    l->anns = annsCpy;
    l->count = count;
    l->next = bm->queue;
    bm->queue = l;
}

typedef struct {
    PacketCrypt_Announce_t* ann;
    uint32_t effectiveWork;
} AnnounceEffectiveWork_t;

static int ewComp(const void* negIfFirst, const void* posIfFirst) {
    const AnnounceEffectiveWork_t* nif = negIfFirst;
    const AnnounceEffectiveWork_t* pif = posIfFirst;
    return ((nif->effectiveWork > pif->effectiveWork) ? -1 :
        ((nif->effectiveWork == pif->effectiveWork) ? 0 : 1));
}
static int tpComp(const void* negIfFirst, const void* posIfFirst) {
    const Ann_t* nif = negIfFirst;
    const Ann_t* pif = posIfFirst;
    return ((nif->treePosition < pif->treePosition) ? -1 :
        ((nif->treePosition == pif->treePosition) ? 0 : 1));
}

int BlockMiner_lockForMining(
    BlockMiner_t* bm,
    PacketCrypt_Coinbase_t* commitOut,
    uint32_t nextBlockHeight,
    uint32_t nextBlockDifficulty)
{
    if (bm->state == State_MINING) {
        assert(!BlockMiner_stop(bm));
    }

    for (uint64_t i = 0; i < bm->annCount; i++) {
        bm->anns[i].effectiveWork = Difficulty_degradeAnnouncementDifficulty(
            bm->anns[i].ann.hdr.workBits,
            nextBlockHeight - bm->anns[i].ann.hdr.parentBlockHeight);
        if (bm->anns[i].effectiveWork == 0xffffffffu) {
            // This will make the hash "invalid" and then the announcement will be kicked from the tree
            bm->tree->entries[i].hash.longs[0] = UINT64_MAX;
        }
    }

    uint64_t newCount = 0;
    AnnounceList_t* l = bm->queue;
    while (l) {
        newCount += l->count;
        l = l->next;
    }
    if (newCount) {
        AnnounceEffectiveWork_t* effectiveWork = malloc(newCount * sizeof(AnnounceEffectiveWork_t));
        assert(effectiveWork);
        newCount = 0;
        AnnounceList_t* l = bm->queue;
        while (l) {
            for (uint64_t i = 0; i < l->count; i++) {
                effectiveWork[newCount].ann = &l->anns[i];
                effectiveWork[newCount].effectiveWork = Difficulty_degradeAnnouncementDifficulty(
                    l->anns[i].hdr.workBits, nextBlockHeight - l->anns[i].hdr.parentBlockHeight);
                newCount++;
            }
            l = l->next;
        }
        qsort(effectiveWork, newCount, sizeof *effectiveWork, ewComp);
        uint64_t i = 0;
        for (; i < bm->annCapacity; i++) {
            if (bm->anns[i].effectiveWork <= effectiveWork[0].effectiveWork) { continue; }
            uint64_t j = 1;
            for (; j < newCount; j++) {
                if (bm->anns[i].effectiveWork > effectiveWork[j].effectiveWork) { break; }
            }
            j--;
            bm->anns[i].effectiveWork = effectiveWork[j].effectiveWork;
            Buf_OBJCPY(&bm->anns[i].ann, effectiveWork[j].ann);
            Hash_COMPRESS32_OBJ(&bm->tree->entries[i].hash, effectiveWork[j].ann);
            newCount--;
            if (j < newCount) {
                memmove(
                    &effectiveWork[j],
                    &effectiveWork[j+1],
                    (newCount - j) * sizeof(AnnounceEffectiveWork_t));
            } else if (j == 0) {
                i++;
                break;
            }
        }
        if (i > bm->annCount) { bm->annCount = i; }
        free(effectiveWork);
        freeQueue(bm);
    }

    bm->tree->totalAnnsZeroIncluded = bm->annCount + 1;
    uint64_t nextCount = PacketCryptProof_prepareTree(bm->tree);

    if (!nextCount) { return BlockMiner_lockForMining_NO_ANNS; }

    // we need to reorder the announcements to match the order which the tree put them in
    // the tree puts the index of the announcements into the start field of the hashes
    // before sorting them.
    // We're going to invert the number and place it on the announcement itself and then
    // sort the announcements in order to get them in the right order.
    for (uint64_t i = 0; i < bm->annCount; i++) {
        bm->anns[bm->tree->entries[i].start].treePosition = i;
    }
    qsort(bm->anns, bm->annCount, sizeof *bm->anns, tpComp);

    // the entries which were to be dropped should have been sorted to the end so we can
    // just decrease the length to remove them.
    bm->annCount = nextCount;

    uint32_t minWork = 0;
    for (uint64_t i = 0; i < bm->annCount; i++) {
        minWork = minWork < bm->anns[i].effectiveWork ? bm->anns[i].effectiveWork : minWork;
    }

    commitOut->numAnns = bm->annCount;
    commitOut->annMinWork = minWork;
    commitOut->effectiveTarget =
        Difficulty_getEffectiveDifficulty(nextBlockDifficulty, minWork, bm->annCount);
    bm->effectiveTarget = commitOut->effectiveTarget;

    PacketCryptProof_computeTree(bm->tree);
    Buf_OBJCPY(commitOut->merkleRoot, &bm->tree->root);
    bm->state = State_LOCKED;
    return 0;
}

// BlockMiner_start_OK             0
// BlockMiner_start_NOT_LOCKED     1
// BlockMiner_start_ALREADY_MINING 2
int BlockMiner_start(BlockMiner_t* ctx, PacketCrypt_BlockHeader_t* blockHeader)
{
    if (ctx->state == State_UNLOCKED) { return BlockMiner_start_NOT_LOCKED; }
    if (ctx->state == State_MINING) { return BlockMiner_start_ALREADY_MINING; }
    ctx->state = State_MINING;
    Buf_OBJCPY(&ctx->hdr, blockHeader);
    for (int i = 0; i < ctx->numWorkers; i++) {
        setRequestedState(ctx, &ctx->workers[i], ThreadState_RUNNING);
    }
    pthread_cond_broadcast(&ctx->cond);
    return BlockMiner_start_OK;
}

// BlockMiner_stop_OK          0
// BlockMiner_stop_NOT_LOCKED  1
int BlockMiner_stop(BlockMiner_t* ctx)
{
    if (ctx->state == State_UNLOCKED) { return BlockMiner_stop_NOT_LOCKED; }
    if (ctx->state == State_LOCKED) {
        ctx->state = State_UNLOCKED;
        return BlockMiner_stop_OK;
    }
    for (int i = 0; i < ctx->numWorkers; i++) {
        setRequestedState(ctx, &ctx->workers[i], ThreadState_STOPPED);
    }
    waitState(ctx, ThreadState_STOPPED);
    ctx->state = State_UNLOCKED;
    return BlockMiner_stop_OK;
}
