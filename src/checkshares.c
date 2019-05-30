#include "packetcrypt/PacketCrypt.h"
#include "packetcrypt/BlockMiner.h"
#include "packetcrypt/Validate.h"
#include "Buf.h"
#include "FilePath.h"
#include "PoolProto.h"
#include "Hash.h"
#include "WorkQueue.h"
#include "FileUtil.h"

#include <stdio.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/types.h>
#include <dirent.h>
#include <pthread.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define STATE_FILE_VERSION (0)
#define DEDUPE_INITIAL_CAP (1024)

// There's no real guarantee that a share can't get bigger, because the work coinbase could be
// arbitararily large, but 20k is a likely size, so 512k should be enough for anyone.
#define FILE_MAX_SZ (1024*512)

#define DEBUGF(...) fprintf(stderr, "checkshares: " __VA_ARGS__)

static int usage() {
    fprintf(stderr, "Usage: ./checkshares OPTIONS <indir> <outdir> <blkdir> <statedir>\n"
        "    OPTIONS:\n"
        "        --threads     # specify number of threads to use (default: 1)\n"
        "    <indir>           # a dir which will be scanned for incoming ann files\n"
        "    <outdir>          # a dir where result files will be placed\n"
        "    <blkdir>          # a dir where share content will be copied if it's a block\n"
        "    <statedir>        # a dir which will be used for keeping track of duplicates\n"
        "\n"
        "    See https://github.com/cjdelisle/PacketCrypt/blob/master/docs/checkshares.md\n"
        "    for more information\n");
    return 100;
}

typedef struct DedupTable_s {
    uint32_t version;
    int32_t currentlyMiningBlock;
    Buf32_t entries[];
} DedupTable_t;
#define DedupTable_SIZE(numEntries) (8 + (32 * (numEntries)))
#define DedupTable_COUNT_FOR_SIZE(size) (((size) - 8) / 32)
_Static_assert(sizeof(DedupTable_t) == DedupTable_SIZE(0), "");
_Static_assert(DedupTable_COUNT_FOR_SIZE(sizeof(DedupTable_t)) == 0, "");

typedef struct Dedup_s {
    pthread_mutex_t lock;

    // Number of entries in dedupTable
    int len;

    // Number of entries which dedupTable can hold before it needs to be realloc()'d
    int cap;

    DedupTable_t* table;
} Dedup_t;

typedef struct Worker_s Worker_t;

typedef struct MainThread_s {
    Dedup_t dedup;
    WorkQueue_t* q;

    FilePath_t stateFile;

    int workerCount;
    Worker_t* workers;
} MainThread_t;

struct Worker_s {
    int shareLen;
    Dedup_t* dedup;
    WorkQueue_t* q;
    FilePath_t* inFile;
    FilePath_t outFile;
    FilePath_t blkFile;
    FilePath_t stateFile;
    PacketCrypt_ValidateCtx_t vctx;

    // we're going to break some aliasing rules...
    uint8_t fileBuf[FILE_MAX_SZ] __attribute__ ((aligned (__BIGGEST_ALIGNMENT__)));
};

static int writeFile(const char* name, void* content, ssize_t length) {
    int fileNo = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fileNo < 0) {
        DEBUGF("Could not open file [%s] because [%s]\n", name, strerror(errno));
        return errno;
    }
    ssize_t res = write(fileNo, content, length);
    if (res != length) {
        if (res > 0) {
            DEBUGF("Partial write of file [%s]\n", name);
        } else {
            DEBUGF("Failed to write file [%s] because [%s]\n", name, strerror(errno));
        }
        int e = errno;
        close(fileNo);
        return e;
    }
    close(fileNo);
    return 0;
}

// no workers active
static void loadState(MainThread_t* ctx, DIR* d) {
    int highestNum = -1;
    for (;;) {
        errno = 0;
        struct dirent* file = readdir(d);
        if (file == NULL) {
            if (errno != 0) {
                DEBUGF("Error reading state dir because [%s]\n", strerror(errno));
                assert(0 && "Failed to read state dir");
                return;
            }
            break;
        }
        if (strncmp(file->d_name, "state_", 6)) { continue; }
        int num = strtol(&file->d_name[6], NULL, 10);
        if (num > highestNum) { highestNum = num; }
    }
    rewinddir(d);
    if (highestNum < 0) { return; }
    snprintf(ctx->stateFile.name, FilePath_NAME_SZ, "state_%d.bin", highestNum);
    int fileNo = open(ctx->stateFile.path, O_RDONLY);
    if (fileNo < 0) {
        DEBUGF("Failed to open state file [%s] because [%s]\n",
            ctx->stateFile.path, strerror(errno));
        assert(0 && "Failed to open state file");
        return;
    }
    struct stat st;
    if (fstat(fileNo, &st)) {
        DEBUGF("Failed to get length of state file [%s] because [%s]\n",
            ctx->stateFile.path, strerror(errno));
        assert(0 && "Failed to get length of state file");
        return;
    }
    int cap = ctx->dedup.cap;
    while (st.st_size > DedupTable_SIZE(cap)) { cap *= 2; }
    if (cap > ctx->dedup.cap) {
        ctx->dedup.table = realloc(ctx->dedup.table, cap);
        assert(ctx->dedup.table);
        ctx->dedup.cap = cap;
    }
    ssize_t len = read(fileNo, ctx->dedup.table, st.st_size);
    if (len != st.st_size) {
        DEBUGF("%s state file [%s] because [%s]",
            len ? "Partial read of" : "Failed to read",
            ctx->stateFile.path,
            strerror(errno));
        assert(0 && "Failed to read state file");
        return;
    }
    if (ctx->dedup.table->version != STATE_FILE_VERSION) {
        DEBUGF("Unexpected version [%d] of state file [%s]",
            ctx->dedup.table->version, ctx->stateFile.path);
        assert(0 && "Failed to read state file");
        return;
    }
    ctx->dedup.len = DedupTable_COUNT_FOR_SIZE(st.st_size);
}

// no workers active
static void writeStateFile(MainThread_t* ctx) {
    snprintf(ctx->stateFile.name, FilePath_NAME_SZ, "state_%d.bin",
        ctx->dedup.table->currentlyMiningBlock);
    // Discard result because a warning will be printed and we're quitting anyway
    writeFile(ctx->stateFile.path, ctx->dedup.table, ctx->dedup.len);
}

// checkshare
// startup:
// - 1. scan state directory, find highest numbered file and open it, load state
// - 2. launch workers
//
// checkshare master cycle:
// - 1. scan directory
// - 2. for each entry, if the name doesn't share_*, skip
// - 3. build a list of all files
// - 4. snapshot the list of files currently being read and non-busy workers
// - 5. issue files to non-busy workers
// - 6. broadcast a wakeup
// - 7. goto 6 until list is empty
// - 8. goto 1
//
// checkshare worker cycle:
// - 1. remove work entry if any
// - 2. take out the controlLock and check if we should stop, if we should then stop, otherwise go to sleep
// - 3. check the file to be read
// - on error, log it, remove work entry and goto 1 {
//   - 4. open file
//   - 5. fstat file to get length
//   - 6. read file content into buffer
//   - 7. if version is not zero, return
//   - 8. delete file
// }
// on error, write an output file explaining the error and goto 1 {
//   - 9. blake2b and compare hashNum/hashMod to make sure it wasn't sent to wrong handler
//   - 10. compare the work block header and the block header to verify that they are the same except for: nonce, roothash
//   - 11. place the coinbase commit into the coinbase from the work and hash up the chain, verify it matches merkle root
//   - 12. call Validate_checkBlock(hap from share, height from work, coinbaseCommit from share, blockhashes from share)
//   - 13. take out the dedupLock
//   - 14. if entry height exceeds context height, clear dedup table and update currentlyMiningBlock
//   - 15. scan dedup table for duplicate entry
//   - 16. if no duplicate, append entry to dedup table
//   - 17. release dedupLock
//   - 18. if entry height exceeds context height, delete all files in state dir
// }
// on error, crash {
//   - 19. if the hash from Validate_checkBlock is good enough to be a block, write the share buffer to blockdir
// }
// - 20. write a output file to outdir saying it succeeded
// - 21. goto 1
//
// on interrupt:
// - 1. stop adding work
// - 2. flag workers to stop
// - 3. pthread_join every worker
// on error, log and exit {
// - 4. open a new file in the statedir named state_<currentHeight>.bin
// - 5. write the dedup table out to the file
// - 6. close file
// }
// - 7. exit
//


typedef struct ShareHeader_s {
    uint32_t version;
    uint8_t hashNum;
    uint8_t hashMod;
    uint16_t workLen;
    Buf32_t parentHashes[4];
    Buf64_t payTo;
} ShareHeader_t;
_Static_assert(sizeof(ShareHeader_t) == 4+1+1+2+(32*4)+64, "");

typedef struct Share_s {
    ShareHeader_t* hdr;
    PoolProto_Work_t* work;
    BlockMiner_Share_t* share;
} Share_t;

static Share_t parseShare(uint8_t* fileBuf) {
    ShareHeader_t* header = (ShareHeader_t*) fileBuf;
    PoolProto_Work_t* work = (PoolProto_Work_t*) (&header[1]);
    BlockMiner_Share_t* share = (BlockMiner_Share_t*) (&((uint8_t*) work)[header->workLen]);
    return (Share_t) { .hdr = header, .work = work, .share = share };
}

enum Output {
    Output_CHECK_FAIL = 0,
    Output_INVALID_LEN = 1,
    Output_WRONG_HANDLER = 2,
    Output_HEADER_MISMATCH = 3,
    Output_BAD_WORK = 4,
    Output_MERKLE_ROOT_MISMATCH = 5,
    Output_DUPLICATE = 6,
    Output_ACCEPT = 7
};

static char* strOutput(enum Output out) {
    #define XX(x) case x: return #x;
    switch (out) {
        XX(Output_INVALID_LEN)
        XX(Output_WRONG_HANDLER)
        XX(Output_HEADER_MISMATCH)
        XX(Output_BAD_WORK)
        XX(Output_MERKLE_ROOT_MISMATCH)
        XX(Output_DUPLICATE)
        XX(Output_ACCEPT)
        default:;
    }
    if ((out & 0xff) == 0) {
        switch ((out >> 8) & 0xff00) {
            XX(Validate_checkBlock_RUNT)
            XX(Validate_checkBlock_ANN_INVALID_)
            case Validate_checkBlock_ANN_INSUF_POW_: {
                switch ((out >> 8) & 0xff) {
                    case 0: return "Validate_checkBlock_ANN_INSUF_POW(0)";
                    case 1: return "Validate_checkBlock_ANN_INSUF_POW(1)";
                    case 2: return "Validate_checkBlock_ANN_INSUF_POW(2)";
                    case 3: return "Validate_checkBlock_ANN_INSUF_POW(3)";
                    default: return "Validate_checkBlock_ANN_INSUF_POW(unknown)";
                }
            }
            XX(Validate_checkBlock_PCP_INVAL)
            XX(Validate_checkBlock_PCP_MISMATCH)
            XX(Validate_checkBlock_INSUF_POW)
            XX(Validate_checkBlock_BAD_COINBASE)
            XX(Validate_checkBlock_SHARE_OK)
            default:;
        }
    }
    return "unknown error";
    #undef XX
}

static void writeOutput(Worker_t* w, enum Output out, Share_t* s) {
    uint8_t buf[256];
    snprintf(buf, 256, "{\"result\":\"%s\",\"payTo\":\"%s\"}",
        strOutput(out), s->hdr->payTo.bytes);
    DEBUGF("Writing result [%s]\n", buf);
    strncpy(w->outFile.name, w->inFile->name, FilePath_NAME_SZ);
    if (writeFile(w->outFile.path, &buf, strlen(buf))) {
        assert(0 && "Failed to write output file");
    }
}

static void writeBlock(Worker_t* w) {
    DEBUGF("BLOCK!\n");
    strncpy(w->blkFile.name, w->inFile->name, FilePath_NAME_SZ);
    if (writeFile(w->blkFile.path, w->fileBuf, w->shareLen)) {
        assert(0 && "Failed to write block file");
    }
}

static void clearStateDir(Worker_t* w) {
    w->stateFile.name[0] = '\0';
    DIR* statedir = opendir(w->stateFile.path);
    if (!statedir) {
        DEBUGF("Unable to open statedir [%s] because [%s]\n", w->stateFile.path, strerror(errno));
        return;
    }
    for (;;) {
        errno = 0;
        struct dirent* file = readdir(statedir);
        if (file == NULL) {
            if (errno != 0) { DEBUGF("Error reading statedir because [%s]\n", strerror(errno)); }
            closedir(statedir);
            return;
        }
        if (strncmp(file->d_name, "state_", 6)) { continue; }
        strncpy(w->stateFile.name, file->d_name, FilePath_NAME_SZ);
        if (unlink(w->stateFile.path)) {
            DEBUGF("Error deleting [%s] because [%s]\n", w->stateFile.path, strerror(errno));
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

static void processWork(Worker_t* w) {
    Share_t share = parseShare(w->fileBuf);

    int shareLen = BlockMiner_Share_SIZEOF(share.share->hap.proofLen);
    int workLen = share.hdr->workLen;
    if ((int)sizeof(ShareHeader_t) + shareLen + workLen != w->shareLen) {
        writeOutput(w, Output_INVALID_LEN, &share);
        return;
    }
    if (!PoolProto_Work_isValid(workLen, share.work)) {
        writeOutput(w, Output_INVALID_LEN, &share);
        return;
    }

    Buf32_t workHash;
    Hash_compress32(workHash.bytes, (uint8_t*)share.share, shareLen);
    if (workHash.longs[0] % share.hdr->hashMod != share.hdr->hashNum) {
        writeOutput(w, Output_WRONG_HANDLER, &share);
        return;
    }

    PacketCrypt_BlockHeader_t* refHdr = &share.work->blkHdr;
    PacketCrypt_BlockHeader_t* chkHdr = &share.share->hap.blockHeader;
    // Copy over the nonce and hashMerkleRoot before comparing
    refHdr->nonce = chkHdr->nonce;
    Buf_OBJCPY(refHdr->hashMerkleRoot, chkHdr->hashMerkleRoot);
    if (Buf_OBJCMP(refHdr, chkHdr)) {
        writeOutput(w, Output_HEADER_MISMATCH, &share);
        return;
    }

    //place the coinbase commit into the coinbase from the work
    //and hash up the chain, verify it matches merkle root
    uint8_t* ptr = FileUtil_memmem(share.work->coinbaseAndMerkles, share.work->coinbaseLen,
        COMMIT_PATTERN, COMMIT_PATTERN_SZ);
    if (!ptr) {
        DEBUGF("Coinbase doesn't contain commit pattern\n");
        writeOutput(w, Output_BAD_WORK, &share);
        return;
    }
    PacketCrypt_Coinbase_t* coinbaseCommit = (PacketCrypt_Coinbase_t*) (&ptr[COMMIT_PATTERN_OS]);
    Buf_OBJCPY(coinbaseCommit, &share.share->coinbase);

    Buf64_t hashBuf;
    Hash_compressDoubleSha256(hashBuf.thirtytwos[0].bytes,
        share.work->coinbaseAndMerkles, share.work->coinbaseLen);
    int merkleCount = PoolProto_Work_merkleCount(workLen, share.work);
    uint8_t* merkle = &share.work->coinbaseAndMerkles[share.work->coinbaseLen];
    for (int i = 0; i < merkleCount; i++) {
        memcpy(hashBuf.thirtytwos[1].bytes, &merkle[i*32], 32);
        Hash_COMPRESS32_DSHA256(&hashBuf.thirtytwos[0], &hashBuf);
    }

    if (memcmp(hashBuf.thirtytwos[0].bytes, chkHdr->hashMerkleRoot, 32)) {
        writeOutput(w, Output_MERKLE_ROOT_MISMATCH, &share);
        return;
    }

    Buf32_t pcHash;
    int validateRet = Validate_checkBlock(&share.share->hap, share.work->height,
        share.work->shareTarget, &share.share->coinbase,
        (uint8_t*)share.hdr->parentHashes[0].bytes, pcHash.bytes, &w->vctx);

    if (validateRet != Validate_checkBlock_OK && validateRet != Validate_checkBlock_SHARE_OK) {
        writeOutput(w, Output_CHECK_FAIL | (validateRet << 8), &share);
        return;
    }

    bool isNewHeight = false;
    bool isDuplicate = false;

    /// --- ///
    pthread_mutex_lock(&w->dedup->lock);
    if (w->dedup->table->currentlyMiningBlock < share.work->height) {
        isNewHeight = true;
        w->dedup->len = 0;
        w->dedup->table->currentlyMiningBlock = share.work->height;
    }
    for (int i = 0; i < w->dedup->len; i++) {
        if (Buf_OBJCMP(&workHash, &w->dedup->table->entries[i])) { continue; }
        isDuplicate = true;
        break;
    }
    if (!isDuplicate) {
        if (w->dedup->len >= w->dedup->cap) {
            w->dedup->cap *= 2;
            w->dedup->table = realloc(w->dedup->table, DedupTable_SIZE(w->dedup->cap));
            assert(w->dedup->table && "realloc failed");
        }
        Buf_OBJCPY(&w->dedup->table->entries[w->dedup->len], &workHash);
        w->dedup->len++;
    }
    pthread_mutex_unlock(&w->dedup->lock);
    /// --- ///

    if (isDuplicate) {
        writeOutput(w, Output_DUPLICATE, &share);
        return;
    }

    // New block, write out the block before doing anything else...
    if (validateRet == Validate_checkBlock_OK) { writeBlock(w); }

    if (isNewHeight) { clearStateDir(w); }

    if (validateRet == Validate_checkBlock_OK || validateRet == Validate_checkBlock_SHARE_OK) {
        DEBUGF("Accepted share: ");
        Hash_eprintHex(pcHash.bytes, 32);
        writeOutput(w, Output_ACCEPT, &share);
    }
}

static void* workerLoop(void* vWorker) {
    Worker_t* w = vWorker;
    w->inFile = NULL;
    int fileNo = -1;
    for (;;) {
        if (fileNo > -1) {
            close(fileNo);
            fileNo = -1;
        }

        w->inFile = WorkQueue_workerGetWork(w->q, w->inFile);
        if (!w->inFile) { return NULL; }

        DEBUGF("Checking share [%s]\n", w->inFile->path);

        int fileNo = open(w->inFile->path, O_RDONLY);
        if (fileNo < 0) {
            DEBUGF("Could not open file [%s] because [%s]\n", w->inFile->path, strerror(errno));
            continue;
        }

        struct stat st;
        if (fstat(fileNo, &st)) {
            DEBUGF("Could not stat file [%s] because [%s]\n", w->inFile->path, strerror(errno));
            continue;
        }

        if (st.st_size > FILE_MAX_SZ) {
            DEBUGF("File [%s] is too big to parse\n", w->inFile->path);
            snprintf(w->outFile.name, FilePath_NAME_SZ, "toobig_%s", w->inFile->name);
            if (rename(w->inFile->path, w->outFile.path)) {
                // oh boy, this is a bad day
                DEBUGF("Failed to rename [%s] because [%s]\n", w->inFile->path, strerror(errno));
            }
            continue;
        }

        ssize_t byteCount = read(fileNo, w->fileBuf, st.st_size);
        if (byteCount != st.st_size) {
            if (byteCount > 0) {
                DEBUGF("Partial read of [%s]\n", w->inFile->path);
            } else {
                DEBUGF("Failed to read [%s] because [%s]\n", w->inFile->path, strerror(errno));
            }
            continue;
        }
        w->shareLen = byteCount;

        uint32_t version = 0;
        memcpy(&version, w->fileBuf, 4);
        if (version) {
            DEBUGF("File [%s] has an unexpected version [%u], leaving it alone\n",
                w->inFile->path, version);
            continue;
        }

        if (unlink(w->inFile->path)) {
            DEBUGF("Failed to delete [%s] because [%s]\n", w->inFile->path, strerror(errno));
            continue;
        }

        processWork(w);
    }
}

static volatile bool g_pleaseStop = false;
void sigHandler(int sig) {
    g_pleaseStop = true;
    signal(sig, SIG_IGN);
}

void mainLoop(MainThread_t* mt) {
    while (!g_pleaseStop) {
        uint8_t discard[8];
        if (1 > read(STDIN_FILENO, discard, 8) && (EAGAIN != errno)) {
            DEBUGF("Stdin is nolonger connected, exiting\n");
            break;
        }
        if (WorkQueue_masterScan(mt->q)) { sleep(1); }
    }
}

// ---+++---+++---+++---+++---
// init/shutdown
// ---+++---+++---+++---+++---

static MainThread_t* createMain(
    int threads,
    const char* inDir,
    const char* outDir,
    const char* blkDir,
    const char* stateDir
) {
    MainThread_t* ctx = calloc(sizeof(MainThread_t), 1);
    assert(ctx);
    ctx->dedup.table = malloc(DedupTable_SIZE(DEDUPE_INITIAL_CAP));
    assert(ctx->dedup.table);
    ctx->dedup.table->currentlyMiningBlock = 0;
    ctx->dedup.table->version = STATE_FILE_VERSION;
    ctx->dedup.cap = DEDUPE_INITIAL_CAP;

    ctx->workers = calloc(sizeof(Worker_t), threads);
    assert(ctx->workers);

    ctx->q = WorkQueue_create(inDir, "share_", threads);

    for (int i = 0; i < threads; i++) {
        Worker_t* w = &ctx->workers[i];
        w->q = ctx->q;
        w->dedup = &ctx->dedup;
        FilePath_create(&w->outFile, outDir);
        FilePath_create(&w->blkFile, blkDir);
        FilePath_create(&w->stateFile, stateDir);
    }

    FilePath_create(&ctx->stateFile, stateDir);

    assert(!pthread_mutex_init(&ctx->dedup.lock, NULL));

    return ctx;
}

void destroyMain(MainThread_t* ctx) {
    assert(!pthread_mutex_destroy(&ctx->dedup.lock));

    FilePath_destroy(&ctx->stateFile);

    WorkQueue_destroy(ctx->q);

    for (int i = 0; i < ctx->workerCount; i++) {
        Worker_t* w = &ctx->workers[i];
        FilePath_destroy(&w->outFile);
        FilePath_destroy(&w->blkFile);
        FilePath_destroy(&w->stateFile);
    }

    free(ctx->workers);
    free(ctx->dedup.table);
    free(ctx);
}

int main(int argc, const char** argv) {
    if (argc < 5) { return usage(); }

    int threads = 1;
    int arg = 1;

    if (!strcmp(argv[arg], "--threads")) {
        arg++;
        threads = strtol(argv[arg], NULL, 10);
        if (threads < 1) {
            DEBUGF("I don't understand thread count [%s]", argv[arg]);
            return 100;
        }
        arg++;
    }
    if ((argc - arg) < 4) { return usage(); }

    const char* inDir = argv[arg++];
    const char* outDir = argv[arg++];
    const char* blkDir = argv[arg++];
    const char* stateDir = argv[arg++];

    FileUtil_checkDir("input", inDir);
    FileUtil_checkDir("output", outDir);
    FileUtil_checkDir("block", blkDir);
    FileUtil_checkDir("state", stateDir);

    // reasonably cross-platform way to check if the parent is dead
    // read from stdin and if it's an eof then exit.
    FileUtil_mkNonblock(STDIN_FILENO);

    MainThread_t* ctx = createMain(threads, inDir, outDir, blkDir, stateDir);

    {
        DIR* d = opendir(stateDir);
        if (!d) {
            destroyMain(ctx);
            DEBUGF("Could not access state directory because [%s] errno=[%s]",
                stateDir, strerror(errno));
            assert(0);
        }
        DEBUGF("Loading state\n");
        loadState(ctx, d);
        DEBUGF("Loaded [%d] dedup entries successfully, current parentBlockHeight [%u]\n",
            ctx->dedup.len, ctx->dedup.table->currentlyMiningBlock);
        closedir(d);
    }

    // register as late as possible but before we start touching things
    signal(SIGINT, sigHandler);
    signal(SIGHUP, sigHandler);
    signal(SIGPIPE, sigHandler);

    WorkQueue_start(ctx->q, workerLoop, ctx->workers, sizeof(ctx->workers[0]));

    mainLoop(ctx);

    // Wake up any threads which are already asleep so they will quit
    WorkQueue_stop(ctx->q);

    writeStateFile(ctx);
    destroyMain(ctx);
}
