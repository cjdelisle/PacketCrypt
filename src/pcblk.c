#include "Buf.h"
#include "Hash.h"
#include "PacketCryptProof.h"
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
    uint64_t items[4];
    uint32_t nonce;
} Result_t;

#define HASHES_PER_CYCLE 10000

static Result_t mine(BlockHeader_t* hdr, Announce_t* anns, uint32_t count, uint32_t target, int testing) {
    PacketCrypt_State_t pcState;
    Buf_OBJSET(&pcState, 0);
    uint32_t nonce = hdr->nonce;
    hdr->nonce = 0;
    Time t;
    Time_BEGIN(t);

    for (;;) {
        if (!testing) { hdr->timeSeconds = t.tv0.tv_sec; }
        Buf32_t hdrHash;
        Hash_COMPRESS32_OBJ(&hdrHash, hdr);
        for (int i = 0; i < HASHES_PER_CYCLE; i++) {
            PacketCrypt_init(&pcState, &hdrHash, nonce++);
            Result_t res;
            for (int j = 0; j < 4; j++) {
                res.items[j] = PacketCrypt_getNum(&pcState) % count;
                PacketCrypt_Item_t* it = (PacketCrypt_Item_t*) &anns[res.items[j]];
                if (Compiler_unlikely(!PacketCrypt_update(&pcState, it, 0))) { continue; }
                Hash_compress64(pcState.sixtyfours[0].bytes, (uint8_t*) &pcState, sizeof(PacketCrypt_State_t));
            }
            if (Compiler_likely(!Work_check(pcState.bytes, target))) { continue; }
            PacketCrypt_final(&pcState);
            if (!Work_check(pcState.bytes, target)) { continue; }
            //Hash_printHex(pcState.bytes, 32);
            res.nonce = nonce;
            return res;
        }
        Time_END(t);
        fprintf(stderr, "%lld hashes per second\n",
            (HASHES_PER_CYCLE * 1024) / (Time_MICROS(t) / 1024));
        Time_NEXT(t);
    }
}


static int getAnns(Announce_t** annsP, uint64_t* countP, bool testing) {
    FILE* f = stdin;
    if (testing) {
        fprintf(stderr, "testing mode, searching for ./announcements.bin\n");
        f = fopen("./announcements.bin", "r");
        assert(f);
        fseek(f, 0, SEEK_END);
        *countP = ftell(f) / sizeof(Announce_t);
        rewind(f);
    } else {
        if (!fread(countP, sizeof *countP, 1, f)) {
            fprintf(stderr, "error reading length [%s]\n", errno ? strerror(errno) : "EOF");
            return -1;
        }
    }
    uint64_t count = *countP;

    Announce_t* anns = malloc(sizeof(Announce_t) * count);
    assert(anns);
    *annsP = anns;

    if (fread(anns, sizeof(Announce_t), count, f) != count) {
        fprintf(stderr, "error reading announcements [%s]\n", errno ? strerror(errno) : "EOF");
        return -1;
    }
    if (testing) {
        fclose(f);
    }
    return 0;
}

static int getBlockHdr(BlockHeader_t* hdrOut, bool testing) {
    if (testing) {
        // fill in a fake header.
        Buf_OBJSET(hdrOut, 0);
        hdrOut->workBits = 0x2000ffff;
        return 0;
    }
    fprintf(stderr, "awaiting block header\n");
    if (!fread(&hdrOut, sizeof *hdrOut, 1, stdin)) {
        fprintf(stderr, "error reading BlockHeader [%s]", errno ? strerror(errno) : "EOF");
        return -1;
    }
    fprintf(stderr, "got block header\n");
    return 0;
}

static void test(
    uint32_t effectiveTarget,
    BlockHeader_t* hdr,
    PacketCryptProof_Tree_t* tree,
    Announce_t* anns
) {
    hdr->timeSeconds = 0;
    tree->totalAnns = 16384;
    for(;;) {
        printf("Set tree size %llu\n", tree->totalAnns);
        //PacketCryptProof_prepareTree(tree);
        PacketCryptProof_computeTree(tree);
        for (int i = 0; i < 50; i++) {
            fprintf(stderr, "Time             %08x\n", hdr->timeSeconds);
            fprintf(stderr, "Ann count        %lu\n", (unsigned long)tree->totalAnns);
            Result_t res = mine(hdr, anns, (uint32_t) tree->totalAnns, effectiveTarget, true); //todo count 64
            fprintf(stderr, "found! %lu %lu %lu %lu %d\n",
                (unsigned long)res.items[0],
                (unsigned long)res.items[1],
                (unsigned long)res.items[2],
                (unsigned long)res.items[3], res.nonce);

            int proofSz = -1;
            uint8_t* proof = PacketCryptProof_mkProof(&proofSz, tree, res.items);

            Buf32_t root2;
            Buf32_t hashes[NUM_PROOFS];
            for (int i = 0; i < NUM_PROOFS; i++) {
                Hash_COMPRESS32_OBJ(&hashes[i], &anns[res.items[i]]);
            }
            assert(!PacketCryptProof_hashProof(&root2, hashes, proof, proofSz));
            assert(!Buf_OBJCMP(&root2, &tree->root));

            hdr->timeSeconds++;
        }
        tree->totalAnns--;
    }
}

int main(int argc, char** argv) {
    bool testing = false;
    for (int i = 0; i < argc; i++) { testing |= !strcmp(argv[i], "-t"); }

    Announce_t* anns = NULL;
    uint64_t count = 0;
    if (getAnns(&anns, &count, testing)) {
        return 100;
    }

    PacketCryptProof_Tree_t* tree = PacketCryptProof_allocTree(count);
    for (uint64_t i = 0; i < count; i++) {
        Hash_compress32(tree->entries[i].hash.bytes, (uint8_t*) &anns[i], sizeof anns[i]);
    }

    count = PacketCryptProof_prepareTree(tree);

    // Order tbe big buffer
    Announce_t* anns2 = malloc(sizeof(Announce_t) * tree->totalAnns);
    for (uint64_t i = 0; i < tree->totalAnns; i++) {
        Buf_OBJCPY(&anns2[i], &anns[tree->entries[i].start]);
    }
    free(anns);
    anns = anns2;

    PacketCryptProof_computeTree(tree);

    if (!testing) { assert(fwrite(tree->root.bytes, 32, 1, stdout) == 1); }
    fflush(stdout);

    uint32_t minAnnounceWork = 0;
    for (uint64_t i = 0; i < tree->totalAnns; i++) {
        //fprintf(stderr, "ann work %08x\n", anns[i].hdr.workBits);
        minAnnounceWork = (anns[i].hdr.workBits > minAnnounceWork) ?
            anns[i].hdr.workBits : minAnnounceWork;
    }

    BlockHeader_t hdr;
    if (getBlockHdr(&hdr, testing)) { return 100; }

    uint32_t effectiveTarget =
        Difficulty_getEffectiveDifficulty(hdr.workBits, minAnnounceWork, tree->totalAnns);

    fprintf(stderr, "Effective target %08x\n", effectiveTarget);

    if (testing) {
        test(effectiveTarget, &hdr, tree, anns);
    } else {
        Result_t res = mine(&hdr, anns, (uint32_t) tree->totalAnns, effectiveTarget, testing); //todo count 64

        int proofSz = -1;
        uint8_t* proof = PacketCryptProof_mkProof(&proofSz, tree, res.items);

        Buf32_t root2;
        Buf32_t hashes[NUM_PROOFS];
        for (int i = 0; i < NUM_PROOFS; i++) {
            Hash_COMPRESS32_OBJ(&hashes[i], &anns[res.items[i]]);
        }
        assert(!PacketCryptProof_hashProof(&root2, hashes, proof, proofSz));
        assert(!Buf_OBJCMP(&root2, &tree->root));
        assert(fwrite(proof, proofSz, 1, stdout) == 1);
        fflush(stdout);
    }

    PacketCryptProof_freeTree(tree);
    free(anns);
}
