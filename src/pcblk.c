/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#define _POSIX_C_SOURCE 200809L
#include "packetcrypt/PacketCrypt.h"
#include "packetcrypt/BlockMiner.h"
#include "FilePath.h"
#include "Buf.h"
#include "PoolProto.h"
#include "FileUtil.h"
#include "Conf.h"
#include "Difficulty.h"
#include "config.h"

#include "sodium/crypto_hash_sha256.h"
#include "sodium/core.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <math.h>
#include <time.h>

#define DEBUGF(...) fprintf(stderr, "pcblk: " __VA_ARGS__)

static const int PROTOCOL_VERSION = (
    #ifdef PCP2
        2
    #else
        1
    #endif
);

static int usage() {
    fprintf(stderr, "Usage: ./pcblk OPTIONS <wrkdir>"
#ifndef PCP2
    " <contentdir>"
#endif
        "\n"
        "PacketCrypt Block Miner: Protocol Version %d\n"
        "    OPTIONS:\n"
        "        --maxanns <n> # Maximum number of announcements to use when mining\n"
        "        --threads <n> # number of threads to use, default is 1\n"
        "        --minerId <n> # Numeric ID of the miner, if you have multiple miners with the\n"
        "                      # exact same set of announcements, this ID will prevent them\n"
        "                      # from mining duplicate shares, default is 0\n"
        "        --slowStart   # sleep for 10 seconds when starting up (time to attach gdb)\n"
        "    <wrkdir>          # a dir containing announcements grouped by parent block\n"
#ifndef PCP2
        "    <contentdir>      # a dir containing any announcement content which is needed\n"
#endif
        "\n"
        "    See: https://github.com/cjdelisle/PacketCrypt/blob/master/docs/pcblk.md\n"
        "    for more information\n", PROTOCOL_VERSION);
    return 100;
}

// If the stdin command has this bit set, we'll open a new output file
#define CMD_OPEN_NEW_FILE 1

typedef struct Context_s {
    // Only read 1/2 the total possible anns in one cycle, this way we avoid
    // using too much memory.
    int64_t availableAnns;
    int64_t maxAnns;

    FilePath_t filepath;
#ifndef PCP2
    FilePath_t contentpath;
#endif
    BlockMiner_t* bm;

    PoolProto_Work_t* currentWork;
    PacketCrypt_Coinbase_t* coinbaseCommit;
    bool mining;
    int currentWorkProofSz;
} Context_t;


static int loadFile(Context_t* ctx, const char* fileName) {
    if (ctx->availableAnns < 0) { return 0; }
    strncpy(ctx->filepath.name, fileName, FilePath_NAME_SZ);

    int fileno = open(ctx->filepath.path, O_RDONLY);
    if (fileno < 0) {
        DEBUGF("Failed to open [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
        return 0;
    }
    struct stat st;
    if (fstat(fileno, &st)) {
        DEBUGF("Failed to fstat [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
        close(fileno);
        return 0;
    }
    uint64_t numAnns = st.st_size / sizeof(PacketCrypt_Announce_t);
    if ((off_t)(numAnns * sizeof(PacketCrypt_Announce_t)) != st.st_size) {
        DEBUGF("Size of ann file [%s] is [%lld], not a multiple of ann size. "
            "I don't trust this file\n", ctx->filepath.path, (long long)st.st_size);
        close(fileno);
        if (unlink(ctx->filepath.path)) {
            // Delete the file so that we don't continuously cycle around trying to access it.
            DEBUGF("Failed to delete [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
            return 0;
        }
        return 0;
    }
    PacketCrypt_Announce_t* anns = malloc(st.st_size);
    if (!anns) {
        DEBUGF("Unable to allocate memory for [%s], will be skipped\n", ctx->filepath.path);
        close(fileno);
        return 0;
    }
    if (st.st_size != read(fileno, anns, st.st_size)) {
        DEBUGF("Failed to read [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
        close(fileno);
        free(anns);
        return 0;
    }

    close(fileno);

#ifndef PCP2
    size_t numContents = 0;
    for (size_t i = 0; i < numAnns; i++) {
        numContents += (anns[i].hdr.contentLength > 32);
    }

    uint8_t** contents = NULL;
    ssize_t bytes = st.st_size;
    bool missingContent = false;

    if (numContents) {
        contents = calloc(sizeof(uint8_t*), numContents);
        assert(contents);
    }
    for (size_t i = 0, c = 0; numContents && i < numAnns; i++) {
        if (anns[i].hdr.contentLength <= 32) { continue; }
        uint8_t* content = contents[c++] = malloc(anns[i].hdr.contentLength);
        assert(content);
        bytes += anns[i].hdr.contentLength;
        uint8_t b[65];
        for (int j = 0; j < 32; j++) {
            sprintf(&b[j*2], "%02x", anns[i].hdr.contentHash[j]);
        }
        snprintf(ctx->contentpath.name, FilePath_NAME_SZ, "ann_%s.bin", b);
        fileno = open(ctx->contentpath.path, O_RDONLY);
        if (fileno < 0) {
            if (errno == ENOENT) {
                missingContent = true;
                // we're going to fail the entire group of anns as one
                DEBUGF("Content [%s] for announcement file [%s] idx [%d] is missing\n",
                    ctx->contentpath.path, ctx->filepath.path, (int)i);
                break;
            } else {
                DEBUGF("Failed to open announcement content [%s] for [%s] errno=[%s]\n",
                    ctx->contentpath.path, ctx->filepath.path, strerror(errno));
                free(anns);
                return 0;
            }
        }
        ssize_t ret = read(fileno, content, anns[i].hdr.contentLength);
        if (ret == (ssize_t)anns[i].hdr.contentLength) {
            close(fileno);
            continue;
        }
        DEBUGF("Failed to read announcement content [%s] for [%s] errno=[%s]\n",
            ctx->contentpath.path, ctx->filepath.path, strerror(errno));
        free(anns);
        return 0;
    }
#endif
    if (unlink(ctx->filepath.path)) {
        // make sure we can delete it before we add the announcements,
        // better to lose the announcements than to fill the miner to the moon with garbage.
        DEBUGF("Failed to delete [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
        free(anns);
        return 0;
    }

#ifndef PCP2
    if (missingContent) {
        free(anns);
        return 0;
    }

    // DEBUGF("Loading [%llu] announcements from [%s]\n",
    //     (unsigned long long)numAnns, ctx->filepath.path);
    int ret = BlockMiner_addAnns(ctx->bm, anns, contents, numAnns, true);
#else
    int ret = BlockMiner_addAnns(ctx->bm, anns, NULL, numAnns, false);
#endif
    if (ret) {
        if (ret == BlockMiner_addAnns_LOCKED) {
            DEBUGF("Could not add announcements, miner is locked\n");
        } else {
            DEBUGF("Could not add announcements, unknown error [%d]\n", ret);
        }
    } else {
        ctx->availableAnns -= numAnns;
    }
    return numAnns;
}

static void resetAvailableAnns(Context_t* ctx) {
    // keep reading directories until at least half of maxAnns have been loaded
    // this isn't perfect because there might be one block period which creates more
    // than maxAnns and then there will be more than max memory used but it should be ok
    // in most cases...
    ctx->availableAnns = ctx->maxAnns / 2;
}

static const char* COMMIT_PATTERN =
    "\x6a\x30\x09\xf9\x11\x02\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc"
    "\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc"
    "\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc\xfc"
    "\xfc\xfc";

static const int COMMIT_PATTERN_SZ = 50;
static const int COMMIT_PATTERN_OS = 2;

static bool loadWork(Context_t* ctx) {
    snprintf(ctx->filepath.name, FilePath_NAME_SZ, "work.bin");

    int workfileno = open(ctx->filepath.path, O_RDONLY);
    if (workfileno < 0) {
        if (errno == ENOENT) { return false; }
        DEBUGF("Could not open [%s] for reading errno=[%s]\n",
            ctx->filepath.path, strerror(errno));
        // we won't crash but it's just going to loop and try again...
        return false;
    }

    struct stat st;
    if (fstat(workfileno, &st)) {
        DEBUGF("Could not stat [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
        close(workfileno);
        return false;
    }

    PoolProto_Work_t* work = malloc(st.st_size);
    assert(work);
    if (st.st_size != read(workfileno, work, st.st_size)) {
        DEBUGF("Invalid read of [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
        close(workfileno);
        free(work);
        return false;
    }
    close(workfileno);

    int proofSz = st.st_size - sizeof(PoolProto_Work_t) - work->coinbaseLen;
    if (proofSz < 0 || proofSz % 32) {
        DEBUGF("coinbaseLen [%d] of work.bin size [%d] is insane\n", proofSz, (int)st.st_size);
        free(work);
        return false;
    }

    // make sure we can delete work.bin because otherwise we might get in a busy loop
    if (unlink(ctx->filepath.path)) {
        DEBUGF("Failed to unlink [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
        free(work);
        return false;
    }

    uint8_t* ptr = FileUtil_memmem(work->coinbaseAndMerkles, work->coinbaseLen,
        COMMIT_PATTERN, COMMIT_PATTERN_SZ);
    if (!ptr) {
        DEBUGF("Coinbase doesn't contain commit pattern\n");
        free(work);
        return false;
    }

    free(ctx->currentWork);
    ctx->currentWork = work;
    ctx->currentWorkProofSz = proofSz;
    ctx->coinbaseCommit = (PacketCrypt_Coinbase_t*) (&ptr[COMMIT_PATTERN_OS]);
    ctx->mining = false;
    DEBUGF("Loaded new work (height: [%d])\n", work->height);
    return true;
}

static void beginMining(Context_t* ctx)
{
    assert(ctx->currentWork);
    ctx->coinbaseCommit->annLeastWorkTarget = 0xffffffff;
    DEBUGF("Begin BlockMiner_lockForMining()\n");
    int res = BlockMiner_lockForMining(ctx->bm, ctx->coinbaseCommit,
        ctx->currentWork->height, ctx->currentWork->shareTarget);
    uint64_t hrm = Difficulty_getHashRateMultiplier(
        ctx->coinbaseCommit->annLeastWorkTarget,
        ctx->coinbaseCommit->numAnns);
    DEBUGF("BlockMiner_lockForMining(): count: %ld minTarget: %08x hashrateMultiplier: %ld\n",
        (long)ctx->coinbaseCommit->numAnns, ctx->coinbaseCommit->annLeastWorkTarget,
        (long)hrm);

    // Even if it failed, we can safely begin allocating announcements again
    // because all of the to-be-added announcements were freed, or will be when
    // BlockMiner_start() is called.
    resetAvailableAnns(ctx);

    if (res) {
        if (res == BlockMiner_lockForMining_NO_ANNS) {
            DEBUGF("Unable to begin mining because we have no valid announcements\n");
        } else {
            DEBUGF("Failed BlockMiner_lockForMining() error [%d]", res);
        }
        return;
    }

    uint8_t* merkles = &ctx->currentWork->coinbaseAndMerkles[ctx->currentWork->coinbaseLen];

    Buf64_t hashbuf;
    crypto_hash_sha256(hashbuf.thirtytwos[0].bytes,
        ctx->currentWork->coinbaseAndMerkles, ctx->currentWork->coinbaseLen);
    crypto_hash_sha256(hashbuf.thirtytwos[0].bytes, hashbuf.thirtytwos[0].bytes, 32);

    for (int i = 0; i < ctx->currentWorkProofSz; i+= 32) {
        memcpy(hashbuf.thirtytwos[1].bytes, &merkles[i], 32);
        crypto_hash_sha256(hashbuf.bytes, hashbuf.bytes, sizeof(hashbuf));
        crypto_hash_sha256(hashbuf.thirtytwos[0].bytes, hashbuf.thirtytwos[0].bytes, 32);
    }

    Buf_OBJCPY(&ctx->currentWork->blkHdr.hashMerkleRoot, &hashbuf.thirtytwos[0]);

    res = BlockMiner_start(ctx->bm, &ctx->currentWork->blkHdr);
    if (res) {
        if (res == BlockMiner_start_NOT_LOCKED) {
            DEBUGF("BlockMiner_start() -> BlockMiner_start_NOT_LOCKED\n");
        } else if (res == BlockMiner_start_ALREADY_MINING) {
            DEBUGF("BlockMiner_start() -> BlockMiner_start_ALREADY_MINING\n");
        } else {
            DEBUGF("BlockMiner_start() -> unknown error [%d]\n", res);
        }
        assert(0 && "error from blockminer");
    }
    ctx->mining = true;
}

int main(int argc, char** argv) {
    assert(!sodium_init());
    long long maxAnns = 1024*1024;
    int threads = 1;
    int64_t minerId = 0;
    bool slowStart = false;
    const char* wrkdirName = NULL;
#ifndef PCP2
    const char* contentdirName = NULL;
#endif
    for (int i = 1; i < argc; i++) {
        if (maxAnns < 0) {
            maxAnns = strtoll(argv[i], NULL, 10);
            if (maxAnns < 1) {
                DEBUGF("Could not parse --maxanns value [%s]\n", argv[i]);
                return usage();
            }
        } else if (threads < 0) {
            threads = strtol(argv[i], NULL, 10);
            if (threads < 1) {
                DEBUGF("Could not parse --threads value [%s]\n", argv[i]);
                return usage();
            }
        } else if (minerId < 0) {
            minerId = strtol(argv[i], NULL, 10);
            if (minerId < 0) {
                DEBUGF("Could not parse --minerId value [%s]\n", argv[i]);
                return usage();
            }
        } else if (!strcmp(argv[i], "--maxanns")) {
            maxAnns = -1;
        } else if (!strcmp(argv[i], "--threads")) {
            threads = -1;
        } else if (!strcmp(argv[i], "--minerId")) {
            minerId = -1;
        } else if (!strcmp(argv[i], "--slowStart")) {
            slowStart = true;
        } else if (!wrkdirName) {
            wrkdirName = argv[i];
#ifndef PCP2
        } else if (!contentdirName) {
            contentdirName = argv[i];
#endif
        } else {
            DEBUGF("I do not understand the argument %s\n", argv[i]);
            return usage();
        }
    }

    if (!wrkdirName || maxAnns < 1 || threads < 1) { return usage(); }

#ifndef PCP2
    if (!contentdirName) { return usage(); }
#endif

    if (slowStart) {
        for (int i = 0; i < 10; i++) {
            sleep(1);
        }
    }

    // reasonably cross-platform way to check if the parent is dead
    // read from stdin and if it's an eof then exit.
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(STDIN_FILENO, F_SETFL, flags);

    DIR* wrkdir = opendir(wrkdirName);
    if (!wrkdir) {
        DEBUGF("Could not open [%s] as a directory errno=[%s]\n", wrkdirName, strerror(errno));
        return 100;
    }

    Context_t* ctx = calloc(sizeof(Context_t), 1);
    assert(ctx);

    // keep reading directories until at least half of maxAnns have been loaded
    // this isn't perfect because there might be one block period which creates more
    // than maxAnns and then there will be more than max memory used but it should be ok
    // in most cases...
    ctx->maxAnns = maxAnns;
    resetAvailableAnns(ctx);

    // for the specific numbered directories inside of the input dir
    FilePath_create(&ctx->filepath, wrkdirName);
#ifndef PCP2
    FilePath_create(&ctx->contentpath, contentdirName);
#endif

    snprintf(ctx->filepath.name, FilePath_NAME_SZ, "shares_0.bin");
    int outfile = open(ctx->filepath.path, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (outfile < 0) {
        DEBUGF("Could not open [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
        return 100;
    }

    ctx->bm = BlockMiner_create(maxAnns, minerId, threads, outfile, false);

    int top = 100;
    int32_t outFileNo = 1;
    for (uint32_t i = 0;; i++) {
        uint32_t command = 0;
        for (int j = 0; j < top; j++) {
            if (4 == read(STDIN_FILENO, &command, 4)) {
                // drop out
            } else if (EAGAIN != errno) {
                DEBUGF("Stdin is nolonger connected, exiting\n");
                return 0;
            } else {
                struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000 };
                nanosleep(&ts, NULL);
            }
        }
        top = 100;

        // if we get sighup'd, open a new file and dup2 it so we will begin writing there.
        if (command & CMD_OPEN_NEW_FILE) {
            snprintf(ctx->filepath.name, FilePath_NAME_SZ, "shares_%d.bin", outFileNo++);
            int nextOutfile = open(ctx->filepath.path, O_WRONLY | O_CREAT | O_EXCL, 0222);
            if (nextOutfile < 0) {
                DEBUGF("Failed to open [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
                return 100;
            }
            if (dup2(nextOutfile, outfile) != outfile) {
                DEBUGF("Failed to dup2 [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
                return 100;
            }
            close(nextOutfile);
            if (chmod(ctx->filepath.path, 0666)) {
                DEBUGF("Failed to chmod [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
                return 100;
            }
            DEBUGF("Created new file [%s]\n", ctx->filepath.path);
        }

        // Check if there's a work.bin file for us
        if (!loadWork(ctx)) {
            // no new work, we potentially swapped files because of a signal but we
            // need not restart the miner.
            continue;
        }

        // Only applicable before we receive our first work, we can't really load
        // any anns because we don't know which ones might be useful.
        if (!ctx->currentWork) {
            continue;
        }

        // Stop mining ASAP, it will take some time before the miner threads realize they
        // need to stop so while they're doing that, we can be loading anns in.
        if (!ctx->mining) { BlockMiner_stop(ctx->bm); }

        // Load whatever anns we can use in the next mining cycle
        // If mining == false then we're not yet locked, quickly grab up
        // all of the announcements which are usable in the block and then lock and mine.
        // If mining == true then we're currently mining but we can prepare for the next
        // block by scooping up any announcements which will be usable by that block.
        int files = 0;
        int announcements = 0;
        DEBUGF("Loading announcements\n");
        for (;;) {
            errno = 0;
            struct dirent* file = readdir(wrkdir);
            if (file == NULL) {
                if (errno != 0) { DEBUGF("Error reading dir errno=[%s]\n", strerror(errno)); }
                rewinddir(wrkdir);
                break;
            }
            if (strncmp(file->d_name, "anns_", 5)) { continue; }
            long fileNum = strtol(&file->d_name[5], NULL, 10);
            // if ctx->mining is true then we are currently mining ctx->currentWork->height
            // otherwise we are waiting to mine it.
            // height (next block) 5
            // any announcement with parent < 3 is valid for 5
            // but if we're already mining 5, anything with parent < 4 is valid for next block
            if (ctx->currentWork->height <= Conf_PacketCrypt_ANN_WAIT_PERIOD) {
                // first 3 blocks are special
            } else if (fileNum >= (ctx->currentWork->height - 2 - (!ctx->mining))) {
                continue;
            }
            int anns = loadFile(ctx, file->d_name);
            announcements += anns;
            // DEBUGF("Loaded [%d] announcements from [%s]\n", anns, file->d_name);
            files++;
            if (ctx->availableAnns < 0) {
                DEBUGF("We have reached our --maxAnns limit\n");
                break;
            }
        }
        DEBUGF("Loaded [%d] announcements from [%d] files\n", announcements, files);

        if (!ctx->mining) { beginMining(ctx); }

        // wait for announcements and don't spam the logs too hard...
        // wait 6 seconds
        if (!ctx->mining) { top = 600; }

        if (!(i % 4)) {
            uint64_t hps = BlockMiner_getHashesPerSecond(ctx->bm);
            if (hps) {
                double ehps = BlockMiner_getEffectiveHashRate(ctx->bm);
                int i = 0;
                for (; ehps > 10000; i++) { ehps = floor(ehps / 1000); }
                const char* xx[] = { "h", "Kh", "Mh", "Gh", "Th", "Ph", "Zh", "??" };
                if (i > 7) { i = 7; }
                DEBUGF("%luh real hashrate - %.f%s effective hashrate\n",
                    (unsigned long)hps, ehps, xx[i]);
            }
        }
    }
}
