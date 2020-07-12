/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
#include "packetcrypt/Validate.h"
#include "packetcrypt/PacketCrypt.h"
#include "Buf.h"
#include "Hash.h"
#include "Time.h"
#include "FilePath.h"
#include "WorkQueue.h"
#include "FileUtil.h"
#include "ContentMerkle.h"
#include "Util.h"
#include "config.h"

#include "sodium/core.h"
#include "sodium/randombytes.h"

#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <assert.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <stdlib.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>

// The initial capacity of the deduplication table, 8 times this number
// times 2 to the power of STATE_OUTPUT_BITS will be allocated at the start
// but if more is needed, it will be realloc'd
#define DEDUPE_INITIAL_CAP (1024*16)

// Maximum number of incoming announcements to process in one shot.
// This is only a performance affecting number as a single file can
// have as many announcements as you want, they will just be read
// one block at a time.
#define IN_ANN_CAP 256

// Number of announcements to group before outputting a file, 1024 anns will make
// the files coming from checkanns be 1MB each.
#define OUT_ANN_CAP 1024

// Every WRITE_EVERY_SECONDS seconds, we will output a (potentially very small)
// file, even if the chain is not moving and announcements are coming in slowly.
#define WRITE_EVERY_SECONDS 60

// Number of previous blocks that we will accept announcements for
// is 2 to the power of STATE_OUTPUT_BITS
// Make sure this aligns with AnnHandler.js
#define STATE_OUTPUT_BITS 2


#define DEBUGF0(format) \
    fprintf(stderr, "checkanns: " format)

#define DEBUGF(format, ...) \
    fprintf(stderr, "checkanns: " format, __VA_ARGS__)

static int usage() {
    fprintf(stderr, "Usage: ./checkanns <indir> <outdir> <anndir> <tmpdir> <paylogdir>\n"
        "    <indir>           # a dir which will be scanned for incoming ann files\n"
        "    <outdir>          # a dir where result files will be placed\n"
        "    <anndir>          # a dir where verified announcements will be placed\n"
        "    <tempdir>         # a dir which will be used for creating result files\n"
        "    <paylogdir>       # a dir to put logs of who should be paid for announcements\n"
        "\n"
        "    See https://github.com/cjdelisle/PacketCrypt/blob/master/docs/checkanns.md\n"
        "    for more information\n");
    return 100;
}

typedef struct AnnPost_s {
    uint32_t version;
    uint8_t hashNum;
    uint8_t hashMod;
    uint16_t _pad;
    Buf32_t signingKey;
    Buf32_t parentBlockHash;
    uint32_t minWork;
    uint32_t parentBlockHeight;
    uint8_t payTo[64];
    PacketCrypt_Announce_t anns[IN_ANN_CAP];
} AnnPost_t;
#define AnnPost_HEADER_SZ (sizeof(AnnPost_t) - (sizeof(PacketCrypt_Announce_t) * IN_ANN_CAP))
_Static_assert(AnnPost_HEADER_SZ == 144, "");

typedef struct StateFile_Header_s {
    uint32_t version;

    // After we validate some announcements, whenever we update this, we first flush out
    // all announcements to a file, such that all anns in a file will have the same parent
    // block hash to simplify things for the block miner. If announcements are provied with
    // a *lower* height, they will all be rejected as invalid.
    uint32_t parentBlockHeight;
} StateFile_Header_t;
#define StateFile_Header_SZ 8
_Static_assert(sizeof(StateFile_Header_t) == StateFile_Header_SZ, "");

static void checkedWrite(const char* filename, int fileno, void* ptr, int len) {
    ssize_t written = write(fileno, ptr, len);
    if (written < 0) {
        DEBUGF("Unable to write to file [%s] [%s]\n", filename, strerror(errno));
    } else if (written < len) {
        DEBUGF("Short write to file [%s] [%d] bytes of [%d]\n",
            filename, (int)written, len);
    } else {
        return;
    }
    assert(0);
}

typedef struct Result_s {
    uint32_t accepted;
    uint32_t duplicates;
    uint32_t invalid;
    uint32_t badContentHash;
    uint32_t runt;
    uint32_t internalError;
    uint32_t unsignedCount;
    uint32_t totalContentLength;
    uint8_t payTo[64];
} Result_t;

typedef struct Dedup_s {
    // Number of entries in dedupTable
    int dedupTableLen;

    // Number of entries which dedupTable can hold before it needs to be realloc()'d
    int dedupTableCap;

    // The dedup table
    uint64_t entries[];
} Dedup_t;
#define Dedup_SIZE(entries) (sizeof(Dedup_t) + ((entries) * sizeof(uint64_t)))
_Static_assert(Dedup_SIZE(0) == 8, "");
_Static_assert(Dedup_SIZE(1) == 8 + sizeof(uint64_t), "");

typedef struct StateAndOutput_s {
    uint32_t parentBlockHeight;

    // Number of elements in dedupsOut and out (they are appended in lockstep)
    int outCount;

    // Time when the last anns file was written (or when the daemon was started)
    uint64_t timeOfLastWrite;

    PacketCrypt_Announce_t out[OUT_ANN_CAP];
} StateAndOutput_t;

typedef struct LocalWorker_s {
    // Read from the incoming announcement file, if the file is more than IN_ANN_CAP
    // then it is processed in chunks but the first AnnPost_HEADER_SZ bytes of the AnnPost
    // is always from the first chunk of the file.
    AnnPost_t inBuf;

    // Dedup entries created from inBuf
    uint64_t dedupsIn[IN_ANN_CAP];

    FilePath_t* inFile;

    // The report back to the submitter of the announcement(s)
    FilePath_t outFile;

    // This is a file in the temp dir, it's used to write a file then copy it after.
    // its name can change at any time so it must be set just before opening it.
    FilePath_t tmpFile;

    // This is a file which stores a batch of announcement headers for downloading by block miners.
    FilePath_t annFile;

    // This is the SAO which we are currently writing to disk, we do a switcheroo between
    // this and the active SAO so that we will not make a filesystem write call while holding
    // the global lock.
    StateAndOutput_t* backupSao;

    // Used for validation
    PacketCrypt_ValidateCtx_t vctx;
} LocalWorker_t;

static void mkDedupes(uint64_t* dedupsOut, const PacketCrypt_Announce_t* annsIn, int annCount) {
    for (int i = 0; i < annCount; i++) {
        Buf32_t b;
        Hash_COMPRESS32_OBJ(&b, &annsIn[i]);
        dedupsOut[i] = b.longs[0];
    }
}

// This marks entries in dedupsIn to be start = 0 in order to make them invalid
static int validateAnns(LocalWorker_t* lw, int annCount, Result_t* res) {
    int goodCount = 0;
    int modulo = (lw->inBuf.hashMod > 0) ? lw->inBuf.hashMod : 1;
    for (int i = 0; i < annCount; i++) {
        bool isUnsigned = Buf_IS_ZERO(lw->inBuf.anns[i].hdr.signingKey);
        if (!isUnsigned && Buf_OBJCMP(&lw->inBuf.signingKey, &lw->inBuf.anns[i].hdr.signingKey)) {
            // wrong signing key (probably a race condition in the miner mixing different anns)
        } else if (lw->inBuf.parentBlockHeight != lw->inBuf.anns[i].hdr.parentBlockHeight) {
            // wrong parent block height
        } else if (lw->inBuf.minWork < lw->inBuf.anns[i].hdr.workBits) {
            // not enough work
        } else if (lw->dedupsIn[i] == 0 || lw->dedupsIn[i] == UINT64_MAX) {
            // duplicate of the 0 hash or the pad
        } else if ((lw->dedupsIn[i] % modulo) != lw->inBuf.hashNum) {
            // intended for a different validator node
        } else if (lw->inBuf.anns[i].hdr.version != lw->inBuf.version) {
            // wrong version
        } else if (Validate_checkAnn(NULL, &lw->inBuf.anns[i], lw->inBuf.parentBlockHash.bytes, &lw->vctx)) {
            // doesn't check out
        } else {
            goodCount++;
            res->unsignedCount += isUnsigned;
            if (lw->inBuf.version == 0) {
                // We will not consider content length for ann versions
                // above 0 because content proofs are not required.
                res->totalContentLength += lw->inBuf.anns[i].hdr.contentLength;
            }
            continue;
        }
        // Flag it as no-good, 0 is invalid by definition anyway
        lw->dedupsIn[i] = 0;
    }
    return goodCount;
}

static void writeAnns(LocalWorker_t* lw, int annFileNo, int hashNum, StateAndOutput_t* anns) {

    if (anns->outCount == 0) { return; }

    snprintf(lw->annFile.name, FilePath_NAME_SZ, "anns_%u_%d_%d.bin",
        anns->parentBlockHeight, hashNum, annFileNo);
    strcpy(lw->tmpFile.name, lw->annFile.name);
    int annFileno = open(lw->tmpFile.path, O_EXCL | O_CREAT | O_WRONLY, 0666);
    if (annFileno < 0) {
        DEBUGF("Unable to open ann output temp file [%s] [%s]\n",
            lw->tmpFile.path, strerror(errno));
        assert(0);
    }
    DEBUGF("Writing ann file [%s]\n", lw->tmpFile.name);

    checkedWrite(lw->tmpFile.path, annFileno, anns->out,
        anns->outCount * sizeof(anns->out[0]));
    close(annFileno);
    if (rename(lw->tmpFile.path, lw->annFile.path)) {
        DEBUGF("error renaming temp file [%s] to ann file [%s] [%s]\n",
            lw->tmpFile.path, lw->annFile.path, strerror(errno));
        assert(0);
    }
}


/// locks and such happen below here

typedef struct Output_s {
    StateAndOutput_t* stateAndOutput;
    Dedup_t* dedup;
    pthread_mutex_t lock;
} Output_t;

typedef struct Global_s {
    pthread_mutex_t deduplock;

    // Read by workers, updated by master only
    int paylogFileNo;

    WorkQueue_t* q;

    // Number which will be used in the name of the next ann file that is output
    // Incremented by everyone.
    _Atomic int nextAnnFileNo;

    Output_t output[1<<STATE_OUTPUT_BITS];
} Global_t;

typedef struct Worker_s {
    Global_t* g;
    LocalWorker_t lw;
} Worker_t;

#define OUTPUT(g, parentBlockHeight) \
    (&(g)->output[(parentBlockHeight) & ((1<<STATE_OUTPUT_BITS)-1)])

// must be called with the output lock held
static void tryWriteAnnsCritical(
  Worker_t* w,
  Output_t* output,
  uint32_t parentBlockHeight,
  int hashNum,
  bool newBlock
) {
    // If we don't manage a write, it's because there was nothing to write.
    // in any case, we will update the time so as to avoid busy-looping on
    // attempts to write nothing.
    StateAndOutput_t* current = output->stateAndOutput;
    if (!current->outCount && !newBlock) {
        current->timeOfLastWrite = Time_nowMilliseconds() / 1000;
        return;
    }

    int afn = w->g->nextAnnFileNo++;

    StateAndOutput_t* next = w->lw.backupSao;
    w->lw.backupSao = current;
    output->stateAndOutput = next;

    next->parentBlockHeight = parentBlockHeight;
    if (newBlock) {
        output->dedup->dedupTableLen = 0;
        // TODO(cjd): Perhaps we want to reduce the capacity somewhat in order
        // that the dedup table will not fix itself at the largest size it has
        // ever needed to be.
    }
    next->outCount = 0;
    next->timeOfLastWrite = Time_nowMilliseconds() / 1000;

    assert(!pthread_mutex_unlock(&output->lock));
    writeAnns(&w->lw, afn, hashNum, current);
    assert(!pthread_mutex_lock(&output->lock));
}

// must be called with the dedup lock
static int dedupeCritical(Worker_t* w, Output_t* output, int inCount) {
    LocalWorker_t* lw = &w->lw;
    Dedup_t* dedup = output->dedup;
    for (int x = 0; x < dedup->dedupTableLen; x++) {
        uint64_t tblEntry = dedup->entries[x];
        for (int i = 0; i < inCount; i++) {
            if (lw->dedupsIn[i] != tblEntry) { continue; }
            lw->dedupsIn[i] = 0;
        }
    }
    while (dedup->dedupTableLen + inCount > dedup->dedupTableCap) {
        dedup->dedupTableCap *= 2;
        dedup = output->dedup = realloc(dedup, Dedup_SIZE(dedup->dedupTableCap));
    }
    int x = dedup->dedupTableLen;
    int goodCount = 0;
    for (int i = 0; i < inCount; i++) {
        uint64_t td = lw->dedupsIn[i];
        if (td == 0) { continue; }
        goodCount++;
        dedup->entries[x] = td;
        x++;
    }
    dedup->dedupTableLen = x;

    StateAndOutput_t* sao = output->stateAndOutput;
    for (int i = 0; i < inCount; i++) {
        if (lw->dedupsIn[i] == 0) { continue; }
        Buf_OBJCPY(&sao->out[sao->outCount], &lw->inBuf.anns[i]);
        sao->outCount++;
        assert(sao->outCount < OUT_ANN_CAP);
    }

    return goodCount;
}

static bool processAnns1(Worker_t* w, Result_t* res, int fileNo, int annCount) {

    mkDedupes(w->lw.dedupsIn, w->lw.inBuf.anns, annCount);
    int validCount = validateAnns(&w->lw, annCount, res);
    res->invalid += (annCount - validCount);
    if (!validCount) {
      return false;
    }

    uint64_t now = Time_nowMilliseconds() / 1000;
    int goodCount = 0;

    Output_t* output = OUTPUT(w->g, w->lw.inBuf.parentBlockHeight);
    assert(!pthread_mutex_lock(&output->lock));
    do {
        StateAndOutput_t* sao = output->stateAndOutput;
        uint32_t cph = sao->parentBlockHeight;
        int outCount = sao->outCount;
        uint64_t timeOfLastWrite = sao->timeOfLastWrite;
        if (w->lw.inBuf.parentBlockHeight != cph) {
            if (w->lw.inBuf.parentBlockHeight < cph) {
                DEBUGF("File [%s] has parent block height [%d] which is too old expecting [%d]\n",
                    w->lw.inFile->name, w->lw.inBuf.parentBlockHeight, cph);
                validCount = 0;
                break;
            }
            tryWriteAnnsCritical(w, output, w->lw.inBuf.parentBlockHeight, w->lw.inBuf.hashNum, true);
            DEBUGF("New parentBlockHeight [%u]\n", w->lw.inBuf.parentBlockHeight);
        } else if (outCount + validCount >= OUT_ANN_CAP ||
            (timeOfLastWrite + WRITE_EVERY_SECONDS < now))
        {
            // file is full (or WRITE_EVERY_SECONDS seconds have elapsed), write it out
            tryWriteAnnsCritical(w, output, w->lw.inBuf.parentBlockHeight, w->lw.inBuf.hashNum, false);
        }
        goodCount = dedupeCritical(w, output, annCount);
    } while (0);
    assert(!pthread_mutex_unlock(&output->lock));

    res->accepted += goodCount;
    res->duplicates += (validCount - goodCount);

    return goodCount > 0;
}

static void processAnns(Worker_t* w, int fileNo, int annCount) {
    Result_t res;
    Buf_OBJSET(&res, 0);
    Buf_OBJCPY(res.payTo, w->lw.inBuf.payTo);

    Time t;
    Time_BEGIN(t);
    //DEBUGF("Processing ann file %s\n", w->lw.inFile->name);
    for (;;) {
        processAnns1(w, &res, fileNo, annCount);
        ssize_t bytes = read(fileNo, w->lw.inBuf.anns,
            sizeof(PacketCrypt_Announce_t) * IN_ANN_CAP);
        if (bytes < 0) {
            DEBUGF("Error reading file errno=[%s]\n", strerror(errno));
            res.internalError++;
            break;
        } else if (bytes == 0) {
            break;
        } else if (bytes < 1024) {
            DEBUGF("File [%s] contains a runt ann\n", w->lw.inFile->name);
            res.runt++;
            break;
        }
        annCount = bytes / 1024;
        if (annCount * 1024 != bytes) {
            DEBUGF("File [%s] size is not an even multiple of 1024\n", w->lw.inFile->name);
            res.runt++;
            break;
        }
    }
    strncpy(w->lw.tmpFile.name, w->lw.inFile->name, FilePath_NAME_SZ);
    int outFileNo = open(w->lw.tmpFile.path, O_EXCL | O_CREAT | O_WRONLY, 0666);
    if (outFileNo < 0) {
        DEBUGF("Unable to open output file [%s] [%s]\n",
            w->lw.tmpFile.path, strerror(errno));
        assert(0);
    }

    for (int i = 0; i < 64; i++) {
        if (!res.payTo[i]) { continue; }
        if (res.payTo[i] < 32 || res.payTo[i] > 126 ||
            res.payTo[i] == '\\' || res.payTo[i] == '"')
        {
            res.payTo[i] = '_';
        }
    }

    // make an eventId
    uint8_t eventBuf[16];
    randombytes_buf(eventBuf, 16);
    char eventId[33];
    for (int i = 0; i < 16; i++) {
        snprintf(&eventId[i*2], 3, "%02x", eventBuf[i]);
    }

    // Get the time
    struct timeval tv;
    assert(!gettimeofday(&tv, NULL));
    unsigned long long timeMs = tv.tv_sec;
    timeMs *= 1000;
    timeMs += tv.tv_usec / 1000;

    // Align with Protocol.js Protocol_AnnResult_t
    char buf[2048];
    snprintf(buf, 2048, "{\"type\":\"anns\",\"accepted\":%u,\"dup\":%u,"
        "\"inval\":%u,\"badHash\":%u,\"runt\":%u,\"internalErr\":%u,"
        "\"payTo\":\"%s\",\"unsigned\":%u,\"totalLen\":%u,"
        "\"time\":%llu,\"eventId\":\"%s\",\"target\":%u}\n",
        res.accepted, res.duplicates, res.invalid, res.badContentHash, res.runt,
        res.internalError, res.payTo, res.unsignedCount, res.totalContentLength,
        timeMs, eventId, w->lw.inBuf.minWork);
    checkedWrite(w->lw.tmpFile.path, outFileNo, buf, strlen(buf)-1);
    checkedWrite("paylog file", w->g->paylogFileNo, buf, strlen(buf));
    close(outFileNo);
    strncpy(w->lw.outFile.name, w->lw.inFile->name, FilePath_NAME_SZ);
    if (rename(w->lw.tmpFile.path, w->lw.outFile.path)) {
        DEBUGF("error renaming temp file [%s] to out file [%s] [%s]\n",
            w->lw.tmpFile.path, w->lw.outFile.path, strerror(errno));
        assert(0);
    }
    Time_END(t);
    printf("%s", buf);
}

void* workerLoop(void* vWorker) {
    Worker_t* w = vWorker;
    int inFileNo = -1;
    for (;;) {
        if (inFileNo > -1) {
            close(inFileNo);
            if (unlink(w->lw.inFile->path)) {
                DEBUGF("Unable to delete input file [%s] [%s]\n",
                    w->lw.inFile->path, strerror(errno));
                assert(0);
            }
            inFileNo = -1;
        }
        w->lw.inFile = WorkQueue_workerGetWork(w->g->q, w->lw.inFile);
        if (!w->lw.inFile) {
            return NULL;
        }
        inFileNo = open(w->lw.inFile->path, O_RDONLY);
        if (inFileNo < 0) {
            DEBUGF("Error opening file [%s] errno=[%s]\n", w->lw.inFile->path, strerror(errno));
            continue;
        }
        ssize_t bytes = read(inFileNo, &w->lw.inBuf, sizeof(AnnPost_t));
        if (bytes < 0) {
            if (errno == EISDIR) { continue; }
            DEBUGF("Error reading file [%s] errno=[%s]\n", w->lw.inFile->path, strerror(errno));
            continue;
        } else if ((size_t)bytes < AnnPost_HEADER_SZ + sizeof(PacketCrypt_Announce_t)) {
            DEBUGF("File [%s] is a runt\n", w->lw.inFile->path);
            continue;
        } else if (w->lw.inBuf.version > 1) {
            DEBUGF("File [%s] has incompatible version [%d]\n",
                w->lw.inFile->path, w->lw.inBuf.version);
            continue;
        }
        if (w->lw.inBuf.version < 1) {
            DEBUGF("File [%s] has incompatible version [%d]\n",
                w->lw.inFile->path, w->lw.inBuf.version);
            continue;
        }
        bytes -= AnnPost_HEADER_SZ;
        int annCount = bytes / 1024;
        if (annCount * 1024 != bytes) {
            DEBUGF("File [%s] first read is not an even multiple of 1024\n", w->lw.inFile->name);
            continue;
        }
        processAnns(w, inFileNo, annCount);
    }
}

///
/// Master thread stuff
///


typedef struct MasterThread_s {
    Global_t g;
    FilePath_t paylogFile;
    Time paylogCycleTime;
    int threadCount;
    Worker_t* workers;
} MasterThread_t;

static void* checkmem(void* mem) {
    assert(mem && "Not enough memory");
    return mem;
}

static void initOutput(Output_t* out) {
    out->dedup = checkmem(malloc(Dedup_SIZE(DEDUPE_INITIAL_CAP)));
    out->dedup->dedupTableCap = DEDUPE_INITIAL_CAP;
    out->dedup->dedupTableLen = 0;

    out->stateAndOutput = checkmem(calloc(sizeof(StateAndOutput_t), 1));
    out->stateAndOutput->timeOfLastWrite = Time_nowMilliseconds() / 1000;

    assert(!pthread_mutex_init(&out->lock, NULL));
}

static void destroyOutput(Output_t* out) {
    pthread_mutex_destroy(&out->lock);
    free(out->dedup);
    free(out->stateAndOutput);
}

static void initWorker(
    Worker_t* w,
    Global_t* g,
    const char* outDir,
    const char* annDir,
    const char* tmpDir
) {
    w->g = g;
    w->lw.backupSao = checkmem(calloc(sizeof(StateAndOutput_t), 1));
    FilePath_create(&w->lw.outFile, outDir);
    FilePath_create(&w->lw.annFile, annDir);
    FilePath_create(&w->lw.tmpFile, tmpDir);
}

static void destroyWorker(Worker_t* w) {
    free(w->lw.backupSao);
    FilePath_destroy(&w->lw.outFile);
    FilePath_destroy(&w->lw.annFile);
    FilePath_destroy(&w->lw.tmpFile);
}

static MasterThread_t* createMaster(
    int threadCount,
    const char* inDir,
    const char* outDir,
    const char* annDir,
    const char* tmpDir,
    const char* paylogDir
) {
    MasterThread_t* mt = checkmem(calloc(sizeof(MasterThread_t), 1));
    for (int i = 0; i < (1<<STATE_OUTPUT_BITS); i++) {
        initOutput(&mt->g.output[i]);
    }

    mt->g.q = WorkQueue_create(inDir, "annshare_", threadCount);

    FilePath_create(&mt->paylogFile, paylogDir);
    mt->g.paylogFileNo = -1;

    mt->threadCount = threadCount;
    mt->workers = checkmem(calloc(sizeof(Worker_t), threadCount));

    for (int i = 0; i < threadCount; i++) {
        initWorker(&mt->workers[i], &mt->g, outDir, annDir, tmpDir);
    }
    return mt;
}

static void destroyMaster(MasterThread_t* mt) {
    for (int i = 0; i < mt->threadCount; i++) {
        destroyWorker(&mt->workers[i]);
    }
    free(mt->workers);
    FilePath_destroy(&mt->paylogFile);
    WorkQueue_destroy(mt->g.q);
    for (int i = 0; i < (1<<STATE_OUTPUT_BITS); i++) {
        destroyOutput(&mt->g.output[i]);
    }
    free(mt);
}

// Open the highest numbered file in the logdir
// if mt->g.paylogFileNo > -1 then dup2 the file descriptor over this
// otherwise mt->g.paylogFileNo is configured to the fileno
// returns 0 on success, -1 on error
static int openPayLog(MasterThread_t* mt, DIR* logDir, const char* paylogDir) {
    long biggestFile = 0;
    errno = 0;
    for (;;) {
        struct dirent* file = readdir(logDir);
        if (file == NULL) {
            if (errno != 0) {
                DEBUGF("Error reading paylog dir [%s] errno=[%s]\n",
                    paylogDir, strerror(errno));
                return -1;
            }
            rewinddir(logDir);
            break;
        }
        if (strncmp(file->d_name, "paylog_", 7)) { continue; }
        long fileNum = strtol(&file->d_name[7], NULL, 10);
        if (fileNum > biggestFile) { biggestFile = fileNum; }
    }
    biggestFile++;
    snprintf(mt->paylogFile.name, FilePath_NAME_SZ, "paylog_%ld.ndjson", biggestFile);
    DEBUGF("Opening paylog file [%s]\n", mt->paylogFile.path);
    int f = open(mt->paylogFile.path, O_CREAT | O_WRONLY | O_APPEND, 0666);
    if (f < 0) {
        DEBUGF("Error opening paylog dir [%s] errno=[%s]\n", mt->paylogFile.path, strerror(errno));
        return -1;
    }
    if (mt->g.paylogFileNo > -1) {
        if (dup2(f, mt->g.paylogFileNo) < 0) {
            DEBUGF("Error: unable to dup2() outfile [%s]\n", strerror(errno));
            return -1;
        }
        close(f);
    } else {
        mt->g.paylogFileNo = f;
    }
    Time_BEGIN(mt->paylogCycleTime);
    return 0;
}

static int getNextAnn(MasterThread_t* mt, DIR* anndir, const char* annDir) {
    long biggestFile = 0;
    errno = 0;
    for (;;) {
        struct dirent* file = readdir(anndir);
        if (file == NULL) {
            if (errno != 0) {
                DEBUGF("Error reading anndir [%s] errno=[%s]\n",
                    annDir, strerror(errno));
                return -1;
            }
            rewinddir(anndir);
            break;
        }
        if (strncmp(file->d_name, "anns_", 5)) { continue; }
        long fileNum = strtol(&file->d_name[5], NULL, 10);
        if (fileNum > biggestFile) { biggestFile = fileNum; }
    }
    mt->g.nextAnnFileNo = biggestFile + 1;
    return 0;
}

static volatile bool g_pleaseStop = false;
void sigHandler(int sig) {
    g_pleaseStop = true;
    signal(sig, SIG_IGN);
}

int main(int argc, const char** argv) {
    assert(!sodium_init());
    int threads = 1;
    int arg = 1;

    if ((argc - arg) < 5) { return usage(); }

    if (!strcmp(argv[arg], "--threads")) {
        arg++;
        threads = strtol(argv[arg], NULL, 10);
        if (threads < 1) {
            DEBUGF("I don't understand thread count [%s]", argv[arg]);
            return 100;
        }
        arg++;
    }
    if ((argc - arg) < 5) { return usage(); }

    const char* inDir = argv[arg++];
    const char* outDir = argv[arg++];
    const char* annDir = argv[arg++];
    const char* tmpDir = argv[arg++];
    const char* paylogDir = argv[arg++];

    FileUtil_checkDir("input", inDir);
    FileUtil_checkDir("output", outDir);
    FileUtil_checkDir("announcement", annDir);
    FileUtil_checkDir("temp", tmpDir);
    FileUtil_checkDir("paylog", paylogDir);

    MasterThread_t* mt = createMaster(threads, inDir, outDir, annDir, tmpDir, paylogDir);

    DIR* logdir = opendir(paylogDir);
    if (!logdir) {
        DEBUGF("Could not access paylog directory [%s] errno=[%s]", paylogDir, strerror(errno));
        assert(0);
    }
    if (openPayLog(mt, logdir, paylogDir)) {
        assert(0 && "Unable to open payLog");
    }

    DIR* anndir = opendir(annDir);
    if (!anndir) {
        DEBUGF("Could not access announcement output directory [%s] errno=[%s]", annDir, strerror(errno));
        assert(0);
    }
    if (getNextAnn(mt, anndir, annDir)) {
        assert(0 && "Unable to open annDir");
    }

    // Attach sig handler as late as possible before we start touching things that can
    // lead to the need to flush data to disk in order to maintain consistancy.
    signal(SIGINT, sigHandler);
    signal(SIGHUP, sigHandler);
    signal(SIGPIPE, sigHandler);

    FileUtil_mkNonblock(STDIN_FILENO);

    WorkQueue_start(mt->g.q, workerLoop, mt->workers, sizeof(mt->workers[0]));

    while (!g_pleaseStop) {
        uint8_t discard[8];
        if (1 > read(STDIN_FILENO, discard, 8) && (EAGAIN != errno)) {
            DEBUGF0("Stdin is nolonger connected, exiting\n");
            break;
        }
        if (WorkQueue_masterScan(mt->g.q)) { sleep(1); }
        Time_END(mt->paylogCycleTime);
        if (Time_MICROS(mt->paylogCycleTime) > 60000000) {
            openPayLog(mt, logdir, paylogDir);
        }
    }

    DEBUGF0("Got request to stop, stopping threads...\n");

    WorkQueue_stop(mt->g.q);

    destroyMaster(mt);
    DEBUGF0("Graceful shutdown complete\n");
}
