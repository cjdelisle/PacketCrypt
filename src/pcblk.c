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
#include "Time.h"
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
#include <inttypes.h>

#define DEBUGF(...) fprintf(stderr, "pcblk: " __VA_ARGS__)

static const int PROTOCOL_VERSION = 2;

static int usage() {
    fprintf(stderr, "Usage: ./pcblk OPTIONS <wrkdir>"
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
    int64_t maxAnns;

    PacketCrypt_Announce_t* annBuf;
    int64_t annBufSz;
    int64_t nextAnn;

    int64_t timeOfLastLock;

    FilePath_t filepath;
    BlockMiner_t* bm;

    PoolProto_Work_t* currentWork;
    PacketCrypt_Coinbase_t* coinbaseCommit;
    int currentWorkProofSz;
    int isMining;
} Context_t;

static PacketCrypt_Announce_t* nextBuf(Context_t* ctx, int count) {
    if (ctx->nextAnn < 0 || ctx->nextAnn + count > ctx->annBufSz) {
        ctx->nextAnn = -1;
        return NULL;
    }
    PacketCrypt_Announce_t* out = &ctx->annBuf[ctx->nextAnn];
    ctx->nextAnn += count;
    return out;
}

static int loadFile(Context_t* ctx, const char* fileName) {
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
    PacketCrypt_Announce_t* anns = nextBuf(ctx, numAnns);
    if (!anns) {
        // This is a really common occurrance
        close(fileno);
        return 0;
    }
    if (st.st_size != read(fileno, anns, st.st_size)) {
        DEBUGF("Failed to read [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
        close(fileno);
        ctx->nextAnn -= numAnns;
        return 0;
    }

    close(fileno);

    if (unlink(ctx->filepath.path)) {
        // make sure we can delete it before we add the announcements,
        // better to lose the announcements than to fill the miner to the moon with garbage.
        DEBUGF("Failed to delete [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
        ctx->nextAnn -= numAnns;
        return 0;
    }
    return numAnns;
}

static int shouldWakeup() {
    int gotMessage = 0;
    uint32_t x = 0;
    for (;;) {
        if (4 == read(STDIN_FILENO, &x, 4)) {
            // drop out
            gotMessage = 1;
        } else if (EAGAIN != errno) {
            DEBUGF("Stdin is nolonger connected, exiting\n");
            exit(0);
        } else {
            return gotMessage;
        }
    }
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
    DEBUGF("Loaded new work (height: [%d])\n", work->height);
    return true;
}

// start or re-start miner, return whether we are currently mining
static bool restartMiner(Context_t* ctx)
{
    // First we stop the miner in case it's running
    BlockMiner_stop(ctx->bm);

    assert(ctx->currentWork);
    ctx->coinbaseCommit->annLeastWorkTarget = 0xffffffff;
    DEBUGF("Begin BlockMiner_lockForMining()\n");
    int res = BlockMiner_lockForMining(ctx->bm, ctx->coinbaseCommit,
        ctx->currentWork->height, ctx->currentWork->shareTarget);

    if (res) {
        if (res == BlockMiner_lockForMining_NO_ANNS) {
            DEBUGF("Unable to begin mining because we have no valid announcements\n");
        } else {
            DEBUGF("Failed BlockMiner_lockForMining() error [%d]", res);
        }
        ctx->nextAnn = 0;
        return false;
    }
    
    uint64_t hrm = Difficulty_getHashRateMultiplier(
        ctx->coinbaseCommit->annLeastWorkTarget,
        ctx->coinbaseCommit->numAnns);
    DEBUGF("BlockMiner_lockForMining(): count: %ld minTarget: %08x hashrateMultiplier: %ld\n",
        (long)ctx->coinbaseCommit->numAnns, ctx->coinbaseCommit->annLeastWorkTarget,
        (long)hrm);

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
        return false;
    } else {
        ctx->nextAnn = 0;
        return true;
    }
}

int main(int argc, char** argv) {
    assert(!sodium_init());
    long long maxAnns = 1024*1024;
    int threads = 1;
    int64_t minerId = 0;
    bool slowStart = false;
    const char* wrkdirName = NULL;
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
        } else {
            DEBUGF("I do not understand the argument %s\n", argv[i]);
            return usage();
        }
    }

    if (!wrkdirName || maxAnns < 1 || threads < 1) { return usage(); }

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
    ctx->annBufSz = maxAnns / 2;
    ctx->annBuf = malloc(sizeof(PacketCrypt_Announce_t) * ctx->annBufSz);

    // for the specific numbered directories inside of the input dir
    FilePath_create(&ctx->filepath, wrkdirName);

    snprintf(ctx->filepath.name, FilePath_NAME_SZ, "shares_0.bin");
    int outfile = open(ctx->filepath.path, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (outfile < 0) {
        DEBUGF("Could not open [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
        return 100;
    }

    ctx->bm = BlockMiner_create(maxAnns, minerId, threads, outfile, false);

    int top = 100;
    int32_t outFileNo = 1;
    int files = 0;
    int reportAnns = 0;
    int reportFiles = 0;
    uint64_t lastReport = Time_nowMilliseconds();
    for (uint32_t i = 0;; i++) {
        for (int j = 0; j < top; j++) {
            if (files > 100 || shouldWakeup()) {
                // drop out
                break;
            } else {
                struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000 };
                nanosleep(&ts, NULL);
            }
        }
        top = 100;

        // if a thread has written to the file, go on and create a new one
        struct stat st;
        if (fstat(outfile, &st)) {
            DEBUGF("Failed to stat share file errno=[%s]\n", strerror(errno));
        } else if (st.st_size) {
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
            //DEBUGF("Created new file [%s]\n", ctx->filepath.path);
        }

        // Load whatever anns we can use in the next mining cycle
        // If mining == false then we're not yet locked, quickly grab up
        // all of the announcements which are usable in the block and then lock and mine.
        // If mining == true then we're currently mining but we can prepare for the next
        // block by scooping up any announcements which will be usable by that block.
        files = 0;
        int announcements = 0;
        PacketCrypt_Announce_t* annsBuf = nextBuf(ctx, 0);
        if (i == 0) {
            DEBUGF("Loading announcements\n");
        }
        uint64_t startProcessing = 0;
        while (ctx->nextAnn >= 0) {
            uint64_t now = Time_nowMilliseconds();
            if (!startProcessing) {
                startProcessing = now;
            } else if (i == 0) {
                // fall through, load as many anns as possible in the first cycle
            } else if (now - startProcessing > 5000 || shouldWakeup()) {
                // don't load files for more than 5 seconds at a time
                break;
            }
            errno = 0;
            struct dirent* file = readdir(wrkdir);
            if (file == NULL) {
                if (errno != 0) { DEBUGF("Error reading dir errno=[%s]\n", strerror(errno)); }
                rewinddir(wrkdir);
                break;
            }
            if (strncmp(file->d_name, "anns_", 5)) { continue; }
            long fileNum = strtol(&file->d_name[5], NULL, 10);
            // if ctx->isMining is true then we are currently mining ctx->currentWork->height
            // otherwise we are waiting to mine it.
            // height (next block) 5
            // any announcement with parent < 3 is valid for 5
            // but if we're already mining 5, anything with parent < 4 is valid for next block
            if (!ctx->currentWork) {
                // no current work
            } else if (ctx->currentWork->height <= Conf_PacketCrypt_ANN_WAIT_PERIOD) {
                // first 3 blocks are special
            } else if (fileNum >= (ctx->currentWork->height - 2 - (!ctx->isMining))) {
                continue;
            }
            int anns = loadFile(ctx, file->d_name);
            announcements += anns;
            // DEBUGF("Loaded [%d] announcements from [%s]\n", anns, file->d_name);
            files++;
        }
        if (files) {
            int ret = BlockMiner_addAnns(ctx->bm, annsBuf, announcements, true);
            if (ret) {
                if (ret == BlockMiner_addAnns_LOCKED) {
                    DEBUGF("Could not add announcements, miner is locked\n");
                } else {
                    DEBUGF("Could not add announcements, unknown error [%d]\n", ret);
                }
            }
            reportAnns += announcements;
            reportFiles += files;
        }
        uint64_t now = Time_nowMilliseconds();
        if (now - lastReport > 5000) {
            uint64_t hps = BlockMiner_getHashesPerSecond(ctx->bm);
            if (!ctx->isMining) { hps = 0; }
            double ehps = 0;
            const char* unit = "";
            if (hps) {
                ehps = BlockMiner_getEffectiveHashRate(ctx->bm);
                int i = 0;
                for (; ehps > 10000; i++) { ehps = floor(ehps / 1000); }
                const char* xx[] = { "h", "Kh", "Mh", "Gh", "Th", "Ph", "Zh", "??" };
                if (i > 7) { i = 7; }
                unit = xx[i];
            }
            DEBUGF("%luh real hashrate - %.f%s effective hashrate - "
                "loaded [%d] announcements from [%d] files\n",
                (unsigned long)hps, ehps, unit, reportAnns, reportFiles);
            reportAnns = 0;
            reportFiles = 0;
            lastReport = now;
        }

        if (loadWork(ctx)) {
            // new work
        } else if (!ctx->isMining) {
            // not mining yet
        } else if (ctx->nextAnn < 0) {
            // re-lock because there are a ton of new announcements
        } else if (now - ctx->timeOfLastLock > 45000) {
            // re-lock because 45 seconds went by without a block
        } else {
            continue;
        }

        // Only applicable before we receive our first work, we can't really load
        // any anns because we don't know which ones might be useful.
        if (!ctx->currentWork) { continue; }

        ctx->isMining = restartMiner(ctx);
        if (ctx->isMining) {
            ctx->timeOfLastLock = now;
        }
    }
}
