#include "packetcrypt/PacketCrypt.h"
#include "packetcrypt/BlockMiner.h"
#include "FilePath.h"
#include "Buf.h"
#include "PoolProto.h"
#include "FileUtil.h"
#include "Conf.h"
#include "Difficulty.h"

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
#include <signal.h>

#define DEBUGF(...) fprintf(stderr, "pcblk: " __VA_ARGS__)

static int usage() {
    fprintf(stderr, "Usage: ./pcblk OPTIONS <wrkdir>\n"
        "    OPTIONS:\n"
        "        --maxanns <n> # Maximum number of announcements to use when mining\n"
        "        --threads <n> # number of threads to use, default is 1\n"
        "        --minerId <n> # Numeric ID of the miner, if you have multiple miners with the\n"
        "                      # exact same set of announcements, this ID will prevent them\n"
        "                      # from mining duplicate shares, default is 0\n"
        "    <wrkdir>          # a dir containing announcements grouped by parent block\n"
        "\n"
        "    See: https://github.com/cjdelisle/PacketCrypt/blob/master/docs/pcblk.md\n"
        "    for more information\n");
    return 100;
}

typedef struct Context_s {
    // Only read 1/2 the total possible anns in one cycle, this way we avoid
    // using too much memory.
    int64_t availableAnns;
    int64_t maxAnns;

    FilePath_t filepath;
    BlockMiner_t* bm;

    PoolProto_Work_t* currentWork;
    PacketCrypt_Coinbase_t* coinbaseCommit;
    bool mining;
    int currentWorkProofSz;
} Context_t;


static void loadFile(Context_t* ctx, const char* fileName) {
    if (ctx->availableAnns < 0) { return; }
    strncpy(ctx->filepath.name, fileName, FilePath_NAME_SZ);

    int fileno = open(ctx->filepath.path, O_RDONLY);
    if (fileno < 0) {
        DEBUGF("Failed to open [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
        return;
    }
    struct stat st;
    if (fstat(fileno, &st)) {
        DEBUGF("Failed to fstat [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
        close(fileno);
        return;
    }
    uint64_t numAnns = st.st_size / sizeof(PacketCrypt_Announce_t);
    if ((off_t)(numAnns * sizeof(PacketCrypt_Announce_t)) != st.st_size) {
        DEBUGF("Size of ann file [%s] is [%lld], not a multiple of ann size. "
            "I don't trust this file\n", ctx->filepath.path, (long long)st.st_size);
        close(fileno);
        if (unlink(ctx->filepath.path)) {
            // Delete the file so that we don't continuously cycle around trying to access it.
            DEBUGF("Failed to delete [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
            return;
        }
        return;
    }
    PacketCrypt_Announce_t* anns = malloc(st.st_size);
    if (!anns) {
        DEBUGF("Unable to allocate memory for [%s], will be skipped\n", ctx->filepath.path);
        close(fileno);
        return;
    }
    if (st.st_size != read(fileno, anns, st.st_size)) {
        DEBUGF("Failed to read [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
        close(fileno);
        free(anns);
        return;
    }

    close(fileno);

    if (unlink(ctx->filepath.path)) {
        // make sure we can delete it before we add the announcements,
        // better to lose the announcements than to fill the miner to the moon with garbage.
        DEBUGF("Failed to delete [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
        free(anns);
        return;
    }

    DEBUGF("Loading [%llu] announcements from [%s]\n",
        (unsigned long long)numAnns, ctx->filepath.path);
    int ret = BlockMiner_addAnns(ctx->bm, anns, numAnns, true);
    if (ret) {
        if (ret == BlockMiner_addAnns_LOCKED) {
            DEBUGF("Could not add announcements, miner is locked\n");
        } else {
            DEBUGF("Could not add announcements, unknown error [%d]\n", ret);
        }
    } else {
        ctx->availableAnns -= numAnns;
    }
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

static void loadWork(Context_t* ctx) {
    snprintf(ctx->filepath.name, FilePath_NAME_SZ, "work.bin");

    int workfileno = open(ctx->filepath.path, O_RDONLY);
    if (workfileno < 0) {
        if (errno == ENOENT) { return; }
        DEBUGF("Could not open [%s] for reading errno=[%s]\n",
            ctx->filepath.path, strerror(errno));
        // we won't crash but it's just going to loop and try again...
        return;
    }

    struct stat st;
    if (fstat(workfileno, &st)) {
        DEBUGF("Could not stat [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
        close(workfileno);
        return;
    }

    PoolProto_Work_t* work = malloc(st.st_size);
    assert(work);
    if (st.st_size != read(workfileno, work, st.st_size)) {
        DEBUGF("Invalid read of [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
        close(workfileno);
        free(work);
        return;
    }
    close(workfileno);

    int proofSz = st.st_size - sizeof(PoolProto_Work_t) - work->coinbaseLen;
    if (proofSz < 0 || proofSz % 32) {
        DEBUGF("coinbaseLen [%d] of work.bin size [%d] is insane\n", proofSz, (int)st.st_size);
        free(work);
        return;
    }

    // make sure we can delete work.bin because otherwise we might get in a busy loop
    if (unlink(ctx->filepath.path)) {
        DEBUGF("Failed to unlink [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
        free(work);
        return;
    }

    uint8_t* ptr = FileUtil_memmem(work->coinbaseAndMerkles, work->coinbaseLen,
        COMMIT_PATTERN, COMMIT_PATTERN_SZ);
    if (!ptr) {
        DEBUGF("Coinbase doesn't contain commit pattern\n");
        free(work);
        return;
    }

    free(ctx->currentWork);
    ctx->currentWork = work;
    ctx->currentWorkProofSz = proofSz;
    ctx->coinbaseCommit = (PacketCrypt_Coinbase_t*) (&ptr[COMMIT_PATTERN_OS]);
    ctx->mining = false;
}

static void beginMining(Context_t* ctx)
{
    assert(ctx->currentWork);
    BlockMiner_Stats_t stats;
    ctx->coinbaseCommit->annLeastWorkTarget = 0xffffffff;
    int res = BlockMiner_lockForMining(ctx->bm, &stats, ctx->coinbaseCommit,
        ctx->currentWork->height, ctx->currentWork->shareTarget);
    uint64_t hrm = Difficulty_getHashRateMultiplier(
        ctx->coinbaseCommit->annLeastWorkTarget, stats.finalCount);
    DEBUGF("BlockMiner_lockForMining(): ng: %ld ne: %ld nne: %ld "
        "og: %ld oe: %ld or: %ld finalCount: %ld minTarget: %08x hashrateMultiplier: %ld\n",
        (long)stats.newGood, (long)stats.newExpired, (long)stats.newNotEnough,
        (long)stats.oldGood, (long)stats.oldExpired, (long)stats.oldReplaced,
        (long)stats.finalCount, ctx->coinbaseCommit->annLeastWorkTarget,
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
    DEBUGF("BlockMiner_start()\n");
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

static bool g_openNewFile = false;
static void sighup(int signal) {
    DEBUGF("sighup\n");
    g_openNewFile = true;
}

int main(int argc, char** argv) {
    assert(!sodium_init());
    long long maxAnns = 1024*1024;
    int threads = 1;
    int64_t minerId = 0;
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
        } else if (!wrkdirName) {
            wrkdirName = argv[i];
        } else {
            DEBUGF("I do not understand the argument %s\n", argv[i]);
            return usage();
        }
    }

    if (!wrkdirName || maxAnns < 1 || threads < 1) { return usage(); }

    // Setup before making any blocking calls to try to win races with the parent process.
    signal(SIGHUP, sighup);

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

    snprintf(ctx->filepath.name, FilePath_NAME_SZ, "shares_0.bin");
    int outfile = open(ctx->filepath.path, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (outfile < 0) {
        DEBUGF("Could not open [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
        return 100;
    }

    ctx->bm = BlockMiner_create(maxAnns, minerId, threads, outfile, false);

    int32_t outFileNo = 1;
    for (uint32_t i = 0;; i++) {
        uint8_t discard[8];
        if (1 > read(STDIN_FILENO, discard, 8) && (EAGAIN != errno)) {
            DEBUGF("Stdin is nolonger connected, exiting\n");
            return 0;
        }
        // if we get sighup'd, open a new file and dup2 it so we will begin writing there.
        if (g_openNewFile) {
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
            g_openNewFile = false;
            if (chmod(ctx->filepath.path, 0666)) {
                DEBUGF("Failed to chmod [%s] errno=[%s]\n", ctx->filepath.path, strerror(errno));
                return 100;
            }
            DEBUGF("Created new file [%s]\n", ctx->filepath.path);
        }

        // Check if there's a work.bin file for us
        loadWork(ctx);

        // Only applicable before we receive our first work, we can't really load
        // any anns because we don't know which ones might be useful.
        if (!ctx->currentWork) {
            sleep(1);
            continue;
        }

        // Stop mining ASAP, it will take some time before the miner threads realize they
        // need to stop so while they're doing that, we can be loading anns in.
        BlockMiner_stop(ctx->bm);

        // Load whatever anns we can use in the next mining cycle
        // If mining == false then we're not yet locked, quickly grab up
        // all of the announcements which are usable in the block and then lock and mine.
        // If mining == true then we're currently mining but we can prepare for the next
        // block by scooping up any announcements which will be usable by that block.
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
            loadFile(ctx, file->d_name);
        }

        if (!ctx->mining) { beginMining(ctx); }

        // wait for announcements and don't spam the logs too hard...
        if (!ctx->mining) { sleep(5); }

        // sleep 1 second before re-scanning the work dir in order to reduce load
        sleep(1);

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
