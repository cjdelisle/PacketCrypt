#include "packetcrypt/BlockMiner.h"
#include "packetcrypt/PacketCrypt.h"
#include "Buf.h"
#include "Hash.h"
#include "PacketCryptProof.h"
#include "CryptoCycle.h"
#include "Time.h"
#include "Difficulty.h"
#include "Work.h"
#include "Util.h"
#include "Conf.h"

#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

typedef struct Worker_s Worker_t;


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

typedef struct AnnounceEffectiveWork_s AnnounceEffectiveWork_t;

typedef struct Ann_s {
    PacketCrypt_Announce_t ann;
    AnnounceEffectiveWork_t* aewPtr;
    uint8_t* content;
    uint64_t _treePosition;
} Ann_t;

struct AnnounceEffectiveWork_s {
    Ann_t* ann;
    uint32_t effectiveWork;
    uint32_t initialWork;
    uint32_t parentBlock;
    char* _pad;
};

typedef struct NextAnnounceEffectiveWork_s {
    PacketCrypt_Announce_t* ann;
    uint32_t effectiveWork;
    uint32_t initialWork;
    uint32_t parentBlock;
    uint8_t* content;
} NextAnnounceEffectiveWork_t;

// exists just in order to force same alignment
union AnnounceEffectiveWorkLike {
    AnnounceEffectiveWork_t aew;
    NextAnnounceEffectiveWork_t naew;
};

typedef struct AnnounceList_s AnnounceList_t;
struct AnnounceList_s {
    PacketCrypt_Announce_t* anns;
    uint8_t** contents;
    uint64_t count;
    AnnounceList_t* next;
};


struct BlockMiner_s {
    // This is a list of announcements, always sorted by tree position.
    // Each entry contains the index of the corrisponding AnnounceEffectiveWork_t
    Ann_t* anns;

    // This is a list of announcement work, always sorted by most work first.
    // Contains a pointer to the corrisponding Ann_t
    // note: whenever either list is sorted, the other list must be updated.
    AnnounceEffectiveWork_t* aew;

    PacketCrypt_BlockHeader_t hdr;

    // aew for the entries in the announceList queue.
    // This is sorted every time new work is added in order to make sure the best
    // announcements in the queue float up to the top.
    // If readyForBlock is -1, this is NULL.
    NextAnnounceEffectiveWork_t* nextAew;
    size_t nextAewLen;
    AnnounceList_t* queue;

    PacketCryptProof_Tree_t* tree;

    // coinbase commitment which is output with the shares
    PacketCrypt_Coinbase_t coinbase;

    size_t annCapacity;
    size_t annCount;

    uint32_t effectiveTarget;

    int32_t readyForBlock;
    uint32_t currentlyMining;

    enum State state;

    int fileNo;
    bool beDeterministic;
    bool sendPtr;

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
    uint32_t lowNonce;

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

#define HASHES_PER_CYCLE 2000

typedef struct {
    PacketCrypt_BlockHeader_t hdr;
    uint64_t items[4];
    uint32_t lowNonce;
} MineResult_t;

static void found(MineResult_t* res, PacketCrypt_BlockHeader_t* hdr, Worker_t* w)
{
    int proofSz = -1;
    uint8_t* proof = PacketCryptProof_mkProof(&proofSz, w->bm->tree, res->items);

    ssize_t outputSize = BlockMiner_Share_SIZEOF(proofSz);
    BlockMiner_Share_t* output = calloc(outputSize, 1);
    assert(output);
    output->length = outputSize;
    Buf_OBJCPY(&output->coinbase, &w->bm->coinbase);
    Buf_OBJCPY(&output->hap.blockHeader, hdr);
    output->hap.nonce2 = res->lowNonce;
    memcpy(output->hap.proof, proof, proofSz);

    Buf32_t root2;
    Buf32_t hashes[PacketCrypt_NUM_ANNS];
    for (int i = 0; i < PacketCrypt_NUM_ANNS; i++) {
        Buf_OBJCPY(&output->hap.announcements[i], &w->bm->anns[res->items[i]].ann);
        Hash_COMPRESS32_OBJ(&hashes[i], &w->bm->anns[res->items[i]].ann);
    }
    assert(!PacketCryptProof_hashProof(
        &root2, hashes, w->bm->annCount, res->items, proof, proofSz));
    assert(!Buf_OBJCMP(&root2, &w->bm->tree->root));

    if (w->bm->sendPtr) {
        // we are writing the pointer, not the content
        PacketCrypt_Find_t x = {
            .ptr = (uint64_t) output,
            .size = (uint64_t) outputSize
        };
        assert(write(w->bm->fileNo, &x, sizeof x) == sizeof x);
    } else {
        // we must make one write only and malloc is easier than awkward writev
        for (;;) {
            ssize_t written = write(w->bm->fileNo, output, outputSize);
            if (written == outputSize) { break; }
            if (written > 0) {
                assert(0 && "Partial write to out file");
            } else if (errno == EBADF) {
                // you must be using a mac (non-atomic dup2)
            } else {
                fprintf(stderr, "BlockMiner: failed write, errno = %d %s\n",
                    errno, strerror(errno));
            }
        }
        free(output);
    }

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

    uint32_t lowNonce = w->lowNonce;

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
                uint64_t x = res.items[j] = CryptoCycle_getItemNo(&w->pcState) % w->bm->annCount;
                CryptoCycle_Item_t* it = (CryptoCycle_Item_t*) &w->bm->anns[x].ann;
                assert(CryptoCycle_update(&w->pcState, it, 0, NULL));
            }
            CryptoCycle_smul(&w->pcState);
            CryptoCycle_final(&w->pcState);
            if (!Work_check(w->pcState.bytes, w->bm->effectiveTarget)) { continue; }
            res.lowNonce = lowNonce;
            Buf_OBJCPY(&res.hdr, &hdr);
            found(&res, &hdr, w);
            fflush(stderr);
            w->lowNonce = lowNonce;
            return true;
        }
        Time_END(t);
        w->hashesPerSecond = ((HASHES_PER_CYCLE * 1024) / (Time_MICROS(t) / 1024));
        Time_NEXT(t);
        if (getRequestedState(w) != ThreadState_RUNNING) {
            w->lowNonce = lowNonce;
            return false;
        }
    }
}

static void* thread(void* vWorker)
{
    //fprintf(stderr, "Thread [%ld] startup\n", (long)pthread_self());
    Worker_t* w = vWorker;
    pthread_mutex_lock(&w->bm->lock);
    for (;;) {
        enum ThreadState rs = getRequestedState(w);
        setState(w, rs);
        switch (rs) {
            case ThreadState_RUNNING: {
                pthread_mutex_unlock(&w->bm->lock);
                mine(w);
                pthread_mutex_lock(&w->bm->lock);
                break;
            }
            case ThreadState_STOPPED: {
                pthread_cond_wait(&w->bm->cond, &w->bm->lock);
                break;
            }
            case ThreadState_SHUTDOWN: {
                pthread_mutex_unlock(&w->bm->lock);
                //fprintf(stderr, "Thread [%ld] end\n", (long)pthread_self());
                return NULL;
            }
        }
    }
}

BlockMiner_t* BlockMiner_create(
    uint64_t maxAnns,
    uint32_t minerId,
    int threads,
    int fileNo,
    bool sendPtr)
{
    Ann_t* annBuf = calloc(sizeof(Ann_t), maxAnns);
    AnnounceEffectiveWork_t* aew = calloc(sizeof(AnnounceEffectiveWork_t), maxAnns);
    Worker_t* workers = calloc(sizeof(Worker_t), threads);
    PacketCryptProof_Tree_t* tree = PacketCryptProof_allocTree(maxAnns);
    BlockMiner_t* ctx = calloc(sizeof(BlockMiner_t), 1);
    assert(annBuf && aew && workers && tree && ctx);

    assert(!pthread_mutex_init(&ctx->lock, NULL));
    assert(!pthread_cond_init(&ctx->cond, NULL));

    ctx->tree = tree;
    ctx->anns = annBuf;
    ctx->aew = aew;

    ctx->sendPtr = sendPtr;
    ctx->annCapacity = maxAnns;
    ctx->fileNo = fileNo;
    ctx->numWorkers = threads;
    ctx->workers = workers;
    ctx->beDeterministic = true;
    ctx->readyForBlock = -1;

    for (int i = 0; i < threads; i++) {
        ctx->workers[i].bm = ctx;
        ctx->workers[i].nonceId = minerId + i;
        assert(!pthread_create(&ctx->workers[i].thread, NULL, thread, &ctx->workers[i]));
    }
    return ctx;
}

static void freeQueue(BlockMiner_t* ctx)
{
    AnnounceList_t* l = ctx->queue;
    while (l) {
        AnnounceList_t* ll = l->next;
        // Do not free all of the contents themselves because they get pointer-copied into
        // the Ann_t.
        // for (int i = 0, j = 0; i < l->count; i++) {
        //     if (l->anns[i].hdr.contentLength > 32) {
        //         free(l->contents[j++]);
        //     }
        // }
        free(l->contents);
        free(l->anns);
        free(l);
        l = ll;
    }
    free(ctx->nextAew);
    ctx->nextAew = NULL;
    ctx->nextAewLen = 0;
    ctx->queue = NULL;
}

static void waitState(BlockMiner_t* ctx, enum ThreadState desiredState) {
    for (int i = 0; i < 100000; i++) {
        enum ThreadState ts = desiredState;
        pthread_mutex_lock(&ctx->lock);
        for (int i = 0; i < ctx->numWorkers; i++) {
            ts = getState(ctx, &ctx->workers[i]);
            if (ts != desiredState) { break; }
        }
        pthread_mutex_unlock(&ctx->lock);
        if (ts == desiredState) {
            return;
        }
        Time_nsleep(100000);
    }
    assert(0 && "threads did not stop in 10 secs");
}

void BlockMiner_free(BlockMiner_t* ctx)
{
    pthread_mutex_lock(&ctx->lock);
    for (int i = 0; i < ctx->numWorkers; i++) {
        setRequestedState(ctx, &ctx->workers[i], ThreadState_SHUTDOWN);
    }
    pthread_mutex_unlock(&ctx->lock);
    pthread_cond_broadcast(&ctx->cond);
    waitState(ctx, ThreadState_SHUTDOWN);

    for (size_t i = 0; i < ctx->annCapacity; i++) {
        free(ctx->anns[i].content);
    }

    free(ctx->anns);
    freeQueue(ctx);
    PacketCryptProof_freeTree(ctx->tree);
    free(ctx->workers);
    assert(!pthread_cond_destroy(&ctx->cond));
    assert(!pthread_mutex_destroy(&ctx->lock));
    free(ctx);
}

// sort by most work (lowest target) first
static int ewComp(const void* negIfFirst, const void* posIfFirst) {
    const AnnounceEffectiveWork_t* nif = negIfFirst;
    const AnnounceEffectiveWork_t* pif = posIfFirst;
    return ((nif->effectiveWork < pif->effectiveWork) ? -1 :
        ((nif->effectiveWork == pif->effectiveWork) ? 0 : 1));
}

static void updateAew(
    NextAnnounceEffectiveWork_t* list,
    uint64_t length,
    uint32_t nextBlockHeight
) {
    for (uint64_t i = 0; i < length; i++) {
        NextAnnounceEffectiveWork_t* aew = &list[i];
        if (nextBlockHeight < Conf_PacketCrypt_ANN_WAIT_PERIOD) {
            // in the first 3 blocks, all announcements are valid in order to allow
            // bootstrapping the network.
            aew->effectiveWork = aew->initialWork;
        } else {
            aew->effectiveWork = Difficulty_degradeAnnouncementTarget(
                aew->initialWork,
                (nextBlockHeight - aew->parentBlock)
            );
        }
    }
}

// This prepares the announcements for the next block which will be coming.
// as soon as we know the number of the next block to mine, we can run this.
// better to run it as soon as possible so as to avoid heavy computation inside
// of lockForMining which is in the critical path (mining is stopped when it's called)
// > prepareAnns... beevis and butthead giggle...
static void prepareAnns(BlockMiner_t* bm, AnnounceList_t* list, uint32_t nextBlockHeight) {
    bm->nextAew = realloc(bm->nextAew, (bm->nextAewLen + list->count) * sizeof(bm->nextAew[0]));
    assert(bm->nextAew);
    for (size_t i = 0, j = bm->nextAewLen, k = 0; i < list->count; i++, j++) {
        PacketCrypt_Announce_t* ann = &list->anns[i];
        NextAnnounceEffectiveWork_t* aew = &bm->nextAew[j];
        aew->initialWork = ann->hdr.workBits;
        aew->parentBlock = ann->hdr.parentBlockHeight;
        aew->ann = ann;
        aew->effectiveWork = 0xffffffff;
        aew->content = (ann->hdr.contentLength > 32) ?
            (aew->content = list->contents[k++]) : NULL;
    }
    updateAew(&bm->nextAew[bm->nextAewLen], list->count, nextBlockHeight);
    bm->nextAewLen += list->count;
}

int BlockMiner_addAnns(
    BlockMiner_t* bm,
    PacketCrypt_Announce_t* anns,
    uint8_t** contents,
    uint64_t count,
    int noCopy)
{
    if (bm->state == State_LOCKED) { return BlockMiner_addAnns_LOCKED; }
    AnnounceList_t* l = calloc(sizeof(AnnounceList_t), 1);
    assert(l && anns);
    PacketCrypt_Announce_t* annsCpy = anns;
    uint8_t** contentsCpy = contents;
    if (!noCopy) {
        annsCpy = malloc(sizeof(PacketCrypt_Announce_t) * count);
        assert(annsCpy);
        memcpy(annsCpy, anns, sizeof(PacketCrypt_Announce_t) * count);
        if (contents) {
            int contentCount = 0;
            for (size_t i = 0; i < count; i++) {
                contentCount += (anns[i].hdr.contentLength > 32);
            }
            contentsCpy = malloc(sizeof(char*) * contentCount);
            assert(contentsCpy);
            for (size_t i = 0, j = 0; i < count; i++) {
                if (anns[i].hdr.contentLength <= 32) { continue; }
                contentsCpy[j] = malloc(anns[i].hdr.contentLength);
                assert(contentsCpy[j]);
                memcpy(contentsCpy[j], contents[j], anns[i].hdr.contentLength);
                j++;
            }
        }
    }
    for (size_t i = 0; i < count; i++) {
        // sanity
        assert(annsCpy[i].hdr.workBits);
    }
    l->anns = annsCpy;
    l->contents = contentsCpy;
    l->count = count;
    l->next = bm->queue;
    bm->queue = l;
    if (bm->readyForBlock >= 0) {
        prepareAnns(bm, l, bm->readyForBlock);
        qsort(bm->nextAew, bm->nextAewLen, sizeof bm->nextAew[0], ewComp);
    }
    return 0;
}

// This does whatever can be done in preparation for lockForMining() but which do not require
// all announcements to be ready. It can be called during mining, and should, because
// lockForMining is in the critical path between receiving work and beginning to mine.
static void prepareNextBlock(BlockMiner_t* bm, uint32_t nextBlockHeight) {
    if (bm->readyForBlock == (int32_t)nextBlockHeight) {
        // nothing to do, everything is setup already
        return;
    }
    // lockForMining leaves aew in a trashed state so it needs to be recreated
    for (size_t i = 0; i < bm->annCount; i++) {
        Ann_t* ann = &bm->anns[i];
        AnnounceEffectiveWork_t* aew = &bm->aew[i];
        aew->ann = ann;
        ann->aewPtr = aew;
        aew->initialWork = ann->ann.hdr.workBits;
        aew->parentBlock = ann->ann.hdr.parentBlockHeight;
    }
    updateAew((NextAnnounceEffectiveWork_t*) bm->aew, bm->annCount, nextBlockHeight);
    qsort(bm->aew, bm->annCount, sizeof bm->aew[0], ewComp);

    for (size_t i = 0; i < bm->annCount; i++) {
        // fix the reverse pointers
        bm->aew[i].ann->aewPtr = &bm->aew[i];
    }

    size_t top = bm->annCount;
    bool trash;
    for (int cycle = 0; cycle < 10; cycle++) {
        trash = false;
        size_t nextTop = top;
        for (size_t i = 1; i < top; i++) {
            // if adding the rest of the announcements with the effective work of the next
            // ann would make the result *worse* than leaving them out, then we will flip
            // a switch and begin marking them as useless so that they will be replaced.
            if (!trash) {
                uint32_t work = bm->aew[i].effectiveWork;
                uint32_t lastWork = bm->aew[i-1].effectiveWork;
                if (work == 0xffffffff) {
                    // already trashed, ignore it
                } else if (work > lastWork) {
                    uint64_t last = Difficulty_getHashRateMultiplier(lastWork, i);
                    uint64_t next = Difficulty_getHashRateMultiplier(work, top);
                    if (last > next) {
                        trash = true;
                        nextTop = i;
                    }
                }
            }
            if (trash) {
                bm->aew[i].effectiveWork = 0xffffffff;
            }
        }
        if (!trash) { break; }
        top = nextTop;
    }

    // This will be non-empty when prepareNextBlock gets called by lockForMining because
    // until lockForMining, the height of the next block was unknown.
    AnnounceList_t* l = bm->queue;
    while (l) {
        prepareAnns(bm, l, nextBlockHeight);
        l = l->next;
    }
    qsort(bm->nextAew, bm->nextAewLen, sizeof bm->nextAew[0], ewComp);
    bm->readyForBlock = nextBlockHeight;
}

// cleanup the trash left after lockForMining, lockForMining is intended to be fast
// so that start() can be called ASAP. This function runs after start or stop to clean
// up the mess left behind.
static void postLockCleanup(BlockMiner_t* bm) {
    // free the queue and nextAew
    freeQueue(bm);

    // We're going to clear readyForBlock because in theory the caller might be
    // wanting to mine an entirely different block and we could end up trashing
    // all of their announcements as they provide them.
    bm->readyForBlock = -1;
}

int BlockMiner_lockForMining(
    BlockMiner_t* bm,
    BlockMiner_Stats_t* statsOut,
    PacketCrypt_Coinbase_t* commitOut,
    uint32_t nextBlockHeight,
    uint32_t nextBlockTarget)
{
    if (bm->state == State_MINING) {
        assert(!BlockMiner_stop(bm));
    }

    prepareNextBlock(bm, nextBlockHeight);

    // At this point, the aews are sorted by work done, most to least.
    // we must scratch the announcement entries which are below the minimum
    // threshold because if one appears in a block, it's an invalid block.
    // We also have zero or more AnnounceList_t which also have aew entries as well.

    BlockMiner_Stats_t stats; Buf_OBJSET(&stats, 0);


    // 1. find the last valid entry in the nextAew list and set nextAewLen down to that
    //
    while (bm->nextAewLen > 0 && bm->nextAew[bm->nextAewLen - 1].effectiveWork == 0xffffffff) {
        stats.newExpired++;
        bm->nextAewLen--;
    }

    // 2. starting at the end of the main announcement list, search backward until either
    //    there is enough space in annCapacity to include the entire nextAew or the
    //    next announcement (searching backward) has a better effectiveWork than the first
    //    announcement in the list to be added.
    //
    // Note1: This is an approximation, the exact algorithm would need to sort the existing
    //     announcements and the new ones, but since this is a time-critical function we'll
    //     stick with using 2 presorted lists and finding the intersection point and copying.
    //
    // Note2: Even if endOfOld-1 is *invalid*, we still prefer to append announcements to the
    //        list and then strike endOfOld-1 in step 4, this is because we have to sort the
    //        announcements anyway, and appending is cheaper than replacing.
    //
    size_t endOfOld = bm->annCount;
    for (;; endOfOld--) {
        // we hit the beginning, we're definitely done
        if (endOfOld == 0) { break; }

        // we have enough empty spaces to accomidate all newly added announcements
        if (endOfOld + bm->nextAewLen <= bm->annCapacity) { break; }

        // the first announcement to add is not better than one we already have
        // with a target, > means less work.
        if (bm->nextAew[0].effectiveWork > bm->aew[endOfOld - 1].effectiveWork) { break; }

        stats.oldExpired += (bm->aew[endOfOld - 1].effectiveWork == 0xffffffff);
        stats.oldReplaced += (bm->aew[endOfOld - 1].effectiveWork < 0xffffffff);
    }

    // 3. Append/replace announcements starting one after the announcement found in 2.
    //    The only case where we will be replacing announcements is if there aren't enough
    //    announcements in annCapacity to accomidate annCount + nextAewLen.
    //
    size_t newAnnI = 0;
    size_t mainAnnI = endOfOld;
    for (; mainAnnI < bm->annCapacity && newAnnI < bm->nextAewLen; newAnnI++, mainAnnI++) {
        Ann_t* annTarget;
        Entry_t* treeEntryTarget;
        AnnounceEffectiveWork_t* aewTarget = &bm->aew[mainAnnI];
        if (mainAnnI < bm->annCount) {
            // replacement, happens only if there is no way to append all of the new anns
            // without over-running annCapacity.
            annTarget = bm->aew[mainAnnI].ann;
            treeEntryTarget = &bm->tree->entries[annTarget->_treePosition];
        } else {
            // new entry
            annTarget = &bm->anns[mainAnnI];
            treeEntryTarget = &bm->tree->entries[mainAnnI];
            annTarget->_treePosition = mainAnnI;
        }

        // copy the ann into the table
        Buf_OBJCPY(&annTarget->ann, bm->nextAew[newAnnI].ann);
        Buf_OBJCPY(aewTarget, &bm->nextAew[newAnnI]);

        free(annTarget->content);
        annTarget->content = bm->nextAew[newAnnI].content;

        // assign pointers
        annTarget->aewPtr = aewTarget;
        aewTarget->ann = annTarget;

        // put the hash in the tree
        Hash_COMPRESS32_OBJ(&treeEntryTarget->hash, &annTarget->ann);
    }

    stats.newGood = newAnnI;
    stats.newNotEnough = bm->nextAewLen - newAnnI;

    // 4. We need to go back down the list and strike any announcements which are
    //    invalid so that they will be sorted out of the tree.
    //
    for (; endOfOld > 0; endOfOld--) {
        if (bm->aew[endOfOld - 1].effectiveWork < 0xffffffff) { break; }
        // Hashes starting with 0 are forbidden so it's a convenient way to strike an entry.
        uint64_t tp = bm->aew[endOfOld - 1].ann->_treePosition;
        bm->tree->entries[tp].hash.longs[0] = 0;
        stats.oldExpired++;
    }

    stats.oldGood = endOfOld;

    // 5. The worst announcement will be found in one of two places, either at the
    //    end of the newly added announcements (mainAnnI - 1) or at the end of the
    //    old announcements, endOfOld.
    uint32_t worstEffectiveWork;
    {
        uint32_t worstOldAnn = (endOfOld > 0) ? bm->aew[endOfOld - 1].effectiveWork : 0;
        uint32_t worstNewAnn = (newAnnI > 0) ? bm->aew[newAnnI - 1].effectiveWork : 0;
        worstEffectiveWork = (worstOldAnn > worstNewAnn) ? worstOldAnn : worstNewAnn;

        // sanity check
        for (uint64_t i = 0; i < mainAnnI; i++) {
            if (bm->aew[i].effectiveWork == 0xffffffff) {
                uint64_t tp = bm->aew[i].ann->_treePosition;
                if (bm->tree->entries[tp].hash.longs[0] != 0) {
                    for (size_t i = 0; i < mainAnnI; i++) {
                        fprintf(stderr, "%08x\n", bm->aew[i].effectiveWork);
                    }
                    fprintf(stderr, "wtf2 %ld %ld %ld %ld %08x %08x %08x\n",
                        (long)i, (long)mainAnnI, endOfOld, newAnnI, bm->aew[i].effectiveWork, worstOldAnn, worstNewAnn);
                    assert(0);
                }
                continue;
            }
            if (bm->aew[i].effectiveWork > worstEffectiveWork) {
                for (size_t i = 0; i < mainAnnI; i++) {
                    fprintf(stderr, "%08x\n", bm->aew[i].effectiveWork);
                }
                fprintf(stderr, "wtf %ld %ld %ld %ld %08x %08x %08x\n",
                    (long)i, (long)mainAnnI, endOfOld, newAnnI, bm->aew[i].effectiveWork, worstOldAnn, worstNewAnn);
            }
            assert(bm->aew[i].effectiveWork <= worstEffectiveWork);
        }
    }

    // 6. Make PcP sort the tree and drop all of the entries which are invalid.
    bm->tree->totalAnnsZeroIncluded = mainAnnI + 1;
    uint64_t nextCount = PacketCryptProof_prepareTree(bm->tree);

    stats.finalCount = nextCount;

    // the entries which were to be dropped should have been sorted to the end so we can
    // just decrease the length to remove them.
    bm->annCount = nextCount;

    // 6. Reorder the announcements by their position in the tree, start by flagging each
    //    announcement with it's proper tree position, then iterate over the tree from
    //    begginning to end, swapping announcements as we go to put them in the right
    //    order.
    // Note: When we swap 2 announcements, two tree entry nolonger have the right index so
    //    we need to fix up at least one of them (the other we will never visit again).
    for (uint64_t i = 0; i < mainAnnI; i++) {
        bm->anns[i]._treePosition = UINT64_MAX;
    }
    for (uint64_t i = 0; i < nextCount; i++) {
        bm->anns[bm->tree->entries[i].start]._treePosition = i;
    }
    for (uint64_t i = 0; i < nextCount; i++) {
        //fprintf(stderr, "i = %ld  tp = %ld\n", (long)i, (long)bm->anns[i]._treePosition);
        assert(bm->anns[i]._treePosition >= i);
        if (bm->anns[i]._treePosition == i) { continue; }
        Ann_t ann;
        uint64_t b = bm->tree->entries[i].start;
        //fprintf(stderr, "    ix = %ld tpx = %ld\n", (long)b, (long)bm->anns[b]._treePosition);
        assert(bm->anns[b]._treePosition == i);
        Buf_OBJCPY(&ann, &bm->anns[i]);
        Buf_OBJCPY(&bm->anns[i], &bm->anns[b]);
        Buf_OBJCPY(&bm->anns[b], &ann);
        bm->tree->entries[ann._treePosition].start = b;
        //bm->tree->entries[i].start = i; // never accessed again

        // fixup the pointer in the aew
        bm->anns[i].aewPtr->ann = &bm->anns[i];
    }

    if (statsOut) { Buf_OBJCPY(statsOut, &stats); }

    if (!nextCount) {
        // we're not transitioning into locked state so we need to clean up our mess
        postLockCleanup(bm);
        prepareNextBlock(bm, nextBlockHeight);
        return BlockMiner_lockForMining_NO_ANNS;
    }

    PacketCryptProof_computeTree(bm->tree);
    bm->coinbase.magic = PacketCrypt_Coinbase_MAGIC;
    bm->coinbase.numAnns = bm->annCount;
    bm->coinbase.annLeastWorkTarget = worstEffectiveWork;
    Buf_OBJCPY(bm->coinbase.merkleRoot, &bm->tree->root);
    Buf_OBJCPY(commitOut, &bm->coinbase);

    bm->effectiveTarget = Difficulty_getEffectiveTarget(
        nextBlockTarget, worstEffectiveWork, bm->annCount);
    bm->currentlyMining = nextBlockHeight;
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

    postLockCleanup(ctx);

    prepareNextBlock(ctx, ctx->currentlyMining + 1);

    return BlockMiner_start_OK;
}

// BlockMiner_stop_OK          0
// BlockMiner_stop_NOT_LOCKED  1
int BlockMiner_stop(BlockMiner_t* ctx)
{
    if (ctx->state == State_UNLOCKED) { return BlockMiner_stop_NOT_LOCKED; }
    if (ctx->state == State_LOCKED) {
        ctx->state = State_UNLOCKED;
        ctx->currentlyMining = 0;
        postLockCleanup(ctx);
        return BlockMiner_stop_OK;
    }
    for (int i = 0; i < ctx->numWorkers; i++) {
        setRequestedState(ctx, &ctx->workers[i], ThreadState_STOPPED);
    }
    waitState(ctx, ThreadState_STOPPED);
    ctx->state = State_UNLOCKED;
    ctx->currentlyMining = 0;

    return BlockMiner_stop_OK;
}

int64_t BlockMiner_getHashesPerSecond(BlockMiner_t* ctx) {
    int64_t out = 0;
    for (int i = 0; i < ctx->numWorkers; i++) {
        out += ctx->workers[i].hashesPerSecond;
    }
    return out;
}

double BlockMiner_getEffectiveHashRate(BlockMiner_t* bm) {
    double realRate = (double) BlockMiner_getHashesPerSecond(bm);
    double hrm = (double) Difficulty_getHashRateMultiplier(
        bm->coinbase.annLeastWorkTarget, bm->coinbase.numAnns);
    return realRate * hrm;
}
