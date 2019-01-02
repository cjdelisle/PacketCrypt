#include "Buf.h"
#include "Hash.h"
#include "BlkMerkle.h"
#include "Announce.h"
#include "Time.h"
#include "PacketCrypt.h"
#include "Difficulty.h"
#include "Compiler.h"
#include "Work.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

/**
 * Block header:
 *
 *     0               1               2               3
 *     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  0 |                           version                             |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  4 |                                                               |
 *    +                                                               +
 *  8 |                                                               |
 *    +                                                               +
 * 12 |                                                               |
 *    +                                                               +
 * 16 |                                                               |
 *    +                         hashPrevBlock                         +
 * 20 |                                                               |
 *    +                                                               +
 * 24 |                                                               |
 *    +                                                               +
 * 28 |                                                               |
 *    +                                                               +
 * 32 |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 36 |                                                               |
 *    +                                                               +
 * 40 |                                                               |
 *    +                                                               +
 * 44 |                                                               |
 *    +                                                               +
 * 48 |                                                               |
 *    +                        hashMerkleRoot                         +
 * 52 |                                                               |
 *    +                                                               +
 * 56 |                                                               |
 *    +                                                               +
 * 60 |                                                               |
 *    +                                                               +
 * 64 |                                                               |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 68 |                          timeSeconds                          |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 72 |                           workBits                            |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 76 |                             nonce                             |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 80
 */
typedef struct {
    uint32_t version;
    uint32_t hashPrevBlock[8];
    uint32_t hashMerkleRoot[8];
    uint32_t timeSeconds;
    uint32_t workBits;
    uint32_t nonce;
} BlockHeader_t;
_Static_assert(sizeof(BlockHeader_t) == 80, "");

typedef struct {
    uint32_t items[4];
    uint32_t nonce;
} Result_t;

#define HASHES_PER_CYCLE 10000

static Result_t mine(BlockHeader_t* hdr, Announce_t* anns, uint32_t count, uint32_t target) {
    PacketCrypt_State_t pcState;
    uint32_t nonce = hdr->nonce;
    hdr->nonce = 0;
    Time t;
    Time_BEGIN(t);

    for (;;) {
        hdr->timeSeconds = t.tv0.tv_sec;
        Buf32_t hdrHash;
        Hash_compress32(hdrHash.bytes, (uint8_t*)hdr, sizeof *hdr);
        for (int i = 0; i < HASHES_PER_CYCLE; i++) {
            PacketCrypt_init(&pcState, &hdrHash, nonce++);
            Result_t res;
            for (int j = 0; j < 4; j++) {
                res.items[j] = PacketCrypt_getNum(&pcState) % count;
                PacketCrypt_Item_t* it = (PacketCrypt_Item_t*) &anns[res.items[j]];
                if (Compiler_unlikely(!PacketCrypt_update(&pcState, it, 0))) { continue; }
            }
            if (Compiler_likely(!Work_check(pcState.bytes, target))) { continue; }
            PacketCrypt_final(&pcState);
            if (!Work_check(pcState.bytes, target)) { continue; }
            Hash_printHex(pcState.bytes, 32);
            res.nonce = nonce;
            return res;
        }
        Time_END(t);
        fprintf(stderr, "%lld hashes per second\n",
            (HASHES_PER_CYCLE * 1024) / (Time_MICROS(t) / 1024));
        Time_NEXT(t);
    }
}

int main(int argc, char** argv) {
    uint32_t count = 0;
    if (!fread(&count, 4, 1, stdin)) {
        fprintf(stderr, "error reading length [%s]\n", errno ? strerror(errno) : "EOF");
        return 100;
    }

    Announce_t* anns = malloc(sizeof(Announce_t) * count);
    assert(anns);

    if (fread(anns, sizeof(Announce_t), count, stdin) != count) {
        fprintf(stderr, "error reading announcements [%s]\n", errno ? strerror(errno) : "EOF");
        return 100;
    }

    BlkMerkle_t* bm = BlkMerkle_alloc(count);
    for (uint32_t i = 0; i < count; i++) {
        Hash_compress32(bm->entries[i].hash.bytes, (uint8_t*) &anns[i], sizeof anns[i]);
    }
    BlkMerkle_compute(bm);

    assert(fwrite(BlkMerkle_getRoot(bm)->bytes, 32, 1, stdout) == 1);
    fflush(stdout);

    uint32_t minAnnounceWork = 0;
    for (uint32_t i = 0; i < count; i++) {
        //fprintf(stderr, "ann work %08x\n", anns[i].hdr.workBits);
        minAnnounceWork = (anns[i].hdr.workBits > minAnnounceWork) ?
            anns[i].hdr.workBits : minAnnounceWork;
    }

    fprintf(stderr, "awaiting block header\n");
    BlockHeader_t hdr;
    if (!fread(&hdr, sizeof hdr, 1, stdin)) {
        fprintf(stderr, "error reading BlockHeader [%s]", errno ? strerror(errno) : "EOF");
        return 100;
    }
    fprintf(stderr, "got block header\n");

    uint32_t effectiveTarget =
        Difficulty_getEffectiveDifficulty(hdr.workBits, minAnnounceWork, count);
    fprintf(stderr, "Block target     %08x\n", hdr.workBits);
    fprintf(stderr, "Ann target       %08x\n", minAnnounceWork);
    fprintf(stderr, "Ann count        %08x\n", count);
    fprintf(stderr, "Effective target %08x\n", effectiveTarget);
    Result_t res = mine(&hdr, anns, count, effectiveTarget);
    fprintf(stderr, "found! %d %d %d %d %d\n",
        res.items[0], res.items[1], res.items[2], res.items[3], res.nonce);

    BlkMerkle_free(bm);
    free(anns);
}
