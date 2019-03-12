#include "Buf.h"
#include "packetcrypt/PacketCrypt.h"
#include "packetcrypt/BlockMiner.h"
#include "packetcrypt/Validate.h"

#include "Hash.h"

#include <stdbool.h>
#include <stdio.h>
//#include <string.h>
#include <stdlib.h>
#include <assert.h>
//#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static void getAnns(BlockMiner_t* bm, bool testing) {
    int f = STDIN_FILENO;
    if (testing) {
        fprintf(stderr, "testing mode, searching for ./announcements.bin\n");
        f = open("./announcements.bin", O_NONBLOCK, O_RDONLY);
        assert(f > -1);
    } else {
        assert(fcntl(f, F_SETFL, O_NONBLOCK) != -1);
    }

    #define ANN_BLK_SZ 8

    int numRead = 0;
    for (;;) {
        PacketCrypt_Announce_t* anns = malloc(sizeof(PacketCrypt_Announce_t) * ANN_BLK_SZ);
        assert(anns);
        size_t len = read(f, anns, sizeof(PacketCrypt_Announce_t) * ANN_BLK_SZ);
        if (len == 0) {
            fprintf(stderr, "Read in %d announcements\n", numRead);
            free(anns);
            if (testing) { close(f); }
            return;
        }
        if (len % sizeof(PacketCrypt_Announce_t)) {
            assert(!"partial read");
        }
        numRead += len / sizeof(PacketCrypt_Announce_t);
        BlockMiner_addAnns(bm, anns, len / sizeof(PacketCrypt_Announce_t), 1);
    }
}

#define WORK_TARGET 0x200fffff
#define BLOCK_HEIGHT 125

static void lockForMining(BlockMiner_t* bm, PacketCrypt_Coinbase_t* coinbase, bool testing)
{
    if (testing) {
        assert(!BlockMiner_lockForMining(bm, coinbase, NULL, BLOCK_HEIGHT, WORK_TARGET));
        return;
    }
    assert(0 && "not implemented");
}

static void getBlockHdr(PacketCrypt_BlockHeader_t* bmOut, bool testing)
{
    Buf_OBJSET(bmOut, 0);
    if (testing) {
        bmOut->workBits = WORK_TARGET;
        bmOut->hashMerkleRoot[0] = 18;
        return;
    }
    assert(0 && "not implemented");
}

static int usage() {
    fprintf(stderr, "Usage: ./pcblk OPTIONS\n");
    fprintf(stderr, "    --mem <X>     # Try to limit memory usage to about X megibytes\n");
    fprintf(stderr, "    --threads <X> # number of threads to use, default is 1\n");
    return 100;
}

int main(int argc, char** argv) {
    bool testing = true;
    long long mem = 1024;
    int threads = 1;
    for (int i = 1; i < argc; i++) {
        if (mem < 0) {
            mem = strtoll(argv[i], NULL, 10);
            if (mem < 1) {
                fprintf(stderr, "Could not parse --mem value [%s]\n", argv[i]);
                return usage();
            }
        } else if (threads < 0) {
            threads = strtol(argv[i], NULL, 10);
            if (threads < 1) {
                fprintf(stderr, "Could not parse --threads value [%s]\n", argv[i]);
                return usage();
            }
        } else if (!strcmp(argv[i], "--mem")) {
            mem = -1;
        } else if (!strcmp(argv[i], "--threads")) {
            threads = -1;
        } else {
            fprintf(stderr, "I do not understand the flag %s\n", argv[i]);
            return usage();
        }
    }

    // consider that memory usage is about 2x the size of the announcements themselves
    uint64_t maxAnns = mem * 512;

    int fileNos[2];
    assert(!pipe(fileNos));

    BlockMiner_t* bm = BlockMiner_create(maxAnns, threads, fileNos[1], true);

    getAnns(bm, testing);
    PacketCrypt_Coinbase_t coinbase;
    lockForMining(bm, &coinbase, testing);

    PacketCrypt_BlockHeader_t blockHdr;
    getBlockHdr(&blockHdr, testing);
    assert(!BlockMiner_start(bm, &blockHdr));

    PacketCrypt_HeaderAndProof_t* hap = NULL;
    PacketCrypt_Find_t f;
    assert(sizeof f == read(fileNos[0], &f, sizeof f));
    assert(f.size >= sizeof(PacketCrypt_HeaderAndProof_t));
    assert(f.ptr);
    hap = (PacketCrypt_HeaderAndProof_t*)f.ptr;

    Buf32_t blockHashes[PacketCrypt_NUM_ANNS];
    for (int i = 0; i < PacketCrypt_NUM_ANNS; i++) {
        Buf_OBJCPY(&blockHashes[i], "abcdefghijklmnopqrstuvwxyz01234");
    }

    PacketCrypt_ValidateCtx_t vctx;
    assert(!Validate_checkBlock(hap, BLOCK_HEIGHT, &coinbase, (uint8_t*)blockHashes, &vctx));
    free(hap);

    BlockMiner_free(bm);

    close(fileNos[0]);
    close(fileNos[1]);

    return 0;
}
