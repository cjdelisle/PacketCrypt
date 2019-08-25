#include "packetcrypt/Validate.h"
#include "packetcrypt/PacketCrypt.h"
#include "Buf.h"
#include "Hash.h"
#include "Time.h"
#include "FilePath.h"
#include "WorkQueue.h"
#include "FileUtil.h"
#include "ContentMerkle.h"

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

#define OUT_ANN_CAP (1024*16)
#define DEDUPE_INITIAL_CAP (1024*1024)
#define IN_ANN_CAP 1
#define STATE_FILE_VERSION (0)

#define WRITE_EVERY_SECONDS 60

typedef struct AnnEntry_s {
    // beginning of the hash (for deduplication)
    uint64_t start;

    // difficulty when mined
    uint32_t diff;

    // height of parent block
    uint32_t height;
} AnnEntry_t;
_Static_assert(sizeof(AnnEntry_t) == 16, "");

#define DEBUGF0(format) \
    fprintf(stderr, "checkanns: " format)

#define DEBUGF(format, ...) \
    fprintf(stderr, "checkanns: " format, __VA_ARGS__)

static int usage() {
    fprintf(stderr, "Usage: ./checkanns <indir> <outdir> <anndir> <statedir> <tmpdir> "
            "<contentdir>\n"
        "    <indir>           # a dir which will be scanned for incoming ann files\n"
        "    <outdir>          # a dir where result files will be placed\n"
        "    <anndir>          # a dir where verified announcements will be placed\n"
        "    <statedir>        # a dir which will be used for keeping track of duplicates\n"
        "    <tempdir>         # a dir which will be used for creating result files\n"
        "    <contentdir>      # a dir where announcement headers+content will be placed\n"
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

typedef struct StateFile_s {
    StateFile_Header_t hdr;
    AnnEntry_t dedups[OUT_ANN_CAP];
} StateFile_t;
_Static_assert(sizeof(StateFile_t) == StateFile_Header_SZ + sizeof(AnnEntry_t) * OUT_ANN_CAP, "");

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

static uint64_t nowSeconds() {
    struct timeval tv;
    if (gettimeofday(&tv, NULL)) {
        DEBUGF("gettimeofday failed [%s]\n", strerror(errno));
        assert(0);
    }
    return tv.tv_sec;
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

typedef struct StateAndOutput_s {
    // Number of elements in dedupsOut and out (they are appended in lockstep)
    int outCount;

    // Number which will be used in the name of the next ann/state file that is output
    int nextStateFileNo;

    // Time when the last anns file was written (or when the daemon was started)
    uint64_t timeOfLastWrite;

    // Outputs (will be written to the out directories)
    StateFile_t state;
    PacketCrypt_Announce_t out[OUT_ANN_CAP];
} StateAndOutput_t;

typedef struct LocalWorker_s {
    // Read from the incoming announcement file, if the file is more than IN_ANN_CAP
    // then it is processed in chunks but the first AnnPost_HEADER_SZ bytes of the AnnPost
    // is always from the first chunk of the file.
    AnnPost_t inBuf;

    // Dedup entries created from inBuf
    AnnEntry_t dedupsIn[IN_ANN_CAP];

    FilePath_t* inFile;

    // The report back to the submitter of the announcement(s)
    FilePath_t outFile;

    // This is a file in the temp dir, it's used to write a file then copy it after.
    // its name can change at any time so it must be set just before opening it.
    FilePath_t tmpFile;

    // This is a file which stores the deduplication table
    FilePath_t stateFile;

    // This is a file which stores a batch of announcement headers for downloading by block miners.
    FilePath_t annFile;

    // This file stores the header and content of a single announcement.
    FilePath_t annContentFile;

    // Used for validation
    PacketCrypt_ValidateCtx_t vctx;
} LocalWorker_t;

static void mkDedupes(AnnEntry_t* dedupsOut, const PacketCrypt_Announce_t* annsIn, int annCount) {
    for (int i = 0; i < annCount; i++) {
        Buf32_t b;
        Hash_COMPRESS32_OBJ(&b, &annsIn[i]);
        dedupsOut[i].start = b.longs[0];
        dedupsOut[i].diff = annsIn[i].hdr.workBits;
        dedupsOut[i].height = annsIn[i].hdr.parentBlockHeight;
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
        } else if (lw->dedupsIn[i].start == 0 || lw->dedupsIn[i].start == UINT64_MAX) {
            // duplicate of the 0 hash or the pad
        } else if ((lw->dedupsIn[i].start % modulo) != lw->inBuf.hashNum) {
            // intended for a different validator node
        } else if (Validate_checkAnn(NULL, &lw->inBuf.anns[i], lw->inBuf.parentBlockHash.bytes, &lw->vctx)) {
            // doesn't check out
        } else {
            goodCount++;
            res->unsignedCount += isUnsigned;
            res->totalContentLength += lw->inBuf.anns[i].hdr.contentLength;
            continue;
        }
        // Flag it as no-good, 0 is invalid by definition anyway
        lw->dedupsIn[i].start = 0;
    }
    return goodCount;
}

static void writeAnns(LocalWorker_t* lw, StateAndOutput_t* anns) {

    if (anns->outCount == 0) { return; }
    // Try to create the new state file, if we're unsuccessful (exists) then we
    // bump the number. If anything else goes wrong then we crash so that we won't
    // be collecting announcements, crediting people, then deleting them.
    int stateFileno = -1;
    for (;;) {
        snprintf(lw->stateFile.name, FilePath_NAME_SZ, "state_%d.bin", anns->nextStateFileNo);
        snprintf(lw->annFile.name, FilePath_NAME_SZ, "anns_%d.bin", anns->nextStateFileNo);
        stateFileno = open(lw->stateFile.path, O_EXCL | O_CREAT | O_WRONLY, 0666);
        if (stateFileno < 0) {
            DEBUGF("Unable to open state file [%s] [%s]\n",
                lw->stateFile.path, strerror(errno));
            assert(0);
        }
        break;
    }
    strcpy(lw->tmpFile.name, lw->annFile.name);
    int annFileno = open(lw->tmpFile.path, O_EXCL | O_CREAT | O_WRONLY, 0666);
    if (annFileno < 0) {
        DEBUGF("Unable to open ann output file [%s] [%s]\n",
            lw->tmpFile.path, strerror(errno));
        assert(0);
    }
    DEBUGF("Writing ann file [%s]\n", lw->tmpFile.name);

    checkedWrite(lw->stateFile.path, stateFileno, &anns->state,
        StateFile_Header_SZ + anns->outCount * sizeof(anns->state.dedups[0]));
    checkedWrite(lw->tmpFile.path, annFileno, anns->out,
        anns->outCount * sizeof(anns->out[0]));
    close(stateFileno);
    close(annFileno);
    if (rename(lw->tmpFile.path, lw->annFile.path)) {
        DEBUGF("error renaming temp file [%s] to ann file [%s] [%s]\n",
            lw->tmpFile.path, lw->annFile.path, strerror(errno));
        assert(0);
    }
}


/// locks and such happen below here

typedef struct Dedup_s {
    // Number of entries in dedupTable
    int dedupTableLen;

    // Number of entries which dedupTable can hold before it needs to be realloc()'d
    int dedupTableCap;

    // The dedup table
    AnnEntry_t entries[];
} Dedup_t;
#define Dedup_SIZE(entries) (sizeof(Dedup_t) + ((entries) * sizeof(AnnEntry_t)))
_Static_assert(Dedup_SIZE(0) == 8, "");
_Static_assert(Dedup_SIZE(1) == 8 + sizeof(AnnEntry_t), "");

typedef struct Global_s {
    pthread_mutex_t deduplock;

    WorkQueue_t* q;
    StateAndOutput_t* sao;
    Dedup_t* dedup;
} Global_t;

typedef struct Worker_s {
    Global_t* g;
    LocalWorker_t lw;
} Worker_t;

// must be called with the dedup lock
static void tryWriteAnnsCritical(Worker_t* w, uint32_t nextParentHeight) {
    StateAndOutput_t* current = w->g->sao;

    // If we don't manage a write, it's because there was nothing to write.
    // in any case, we will update the time so as to avoid busy-looping on
    // attempts to write nothing.
    current->timeOfLastWrite = nowSeconds();

    if (current->outCount == 0) {
        assert(current->state.hdr.parentBlockHeight <= nextParentHeight);
        current->state.hdr.parentBlockHeight = nextParentHeight;
        return;
    }

    StateAndOutput_t* next = malloc(sizeof(StateAndOutput_t));
    assert(next);
    next->state.hdr.version = 0;
    next->state.hdr.parentBlockHeight = nextParentHeight;
    next->outCount = 0;
    next->nextStateFileNo = current->nextStateFileNo + 1;
    next->timeOfLastWrite = nowSeconds();

    w->g->sao = next;

    assert(!pthread_mutex_unlock(&w->g->deduplock));
    writeAnns(&w->lw, current);
    free(current);
    assert(!pthread_mutex_lock(&w->g->deduplock));
}

// must be called with the dedup lock
static int dedupeCritical(Worker_t* w, int inCount) {
    Dedup_t* dedup = w->g->dedup;
    LocalWorker_t* lw = &w->lw;
    for (int x = 0; x < dedup->dedupTableLen; x++) {
        AnnEntry_t* tblEntry = &dedup->entries[x];
        for (int i = 0; i < inCount; i++) {
            AnnEntry_t* td = &lw->dedupsIn[i];
            if (td->start != tblEntry->start) { continue; }
            // toDedup is a dupe but has less work done on it
            td->start = 0;
        }
    }
    while (dedup->dedupTableLen + inCount > dedup->dedupTableCap) {
        dedup->dedupTableCap *= 2;
        dedup = w->g->dedup = realloc(dedup, Dedup_SIZE(dedup->dedupTableCap));
    }
    int x = dedup->dedupTableLen;
    int goodCount = 0;
    for (int i = 0; i < inCount; i++) {
        AnnEntry_t* td = &lw->dedupsIn[i];
        if (td->start == 0) { continue; }
        goodCount++;
        if (td->diff == 0) {
            // It was flagged, we're not going to add it, but we need to un-flag it
            td->diff = lw->inBuf.anns[i].hdr.workBits;
            continue;
        }
        Buf_OBJCPY(&dedup->entries[x], td);
        x++;
    }
    dedup->dedupTableLen = x;

    StateAndOutput_t* sao = w->g->sao;
    for (int i = 0; i < inCount; i++) {
        if (lw->dedupsIn[i].start == 0) { continue; }
        Buf_OBJCPY(&sao->out[sao->outCount], &lw->inBuf.anns[i]);
        Buf_OBJCPY(&sao->state.dedups[sao->outCount], &lw->dedupsIn[i]);
        sao->outCount++;
        assert(sao->outCount < OUT_ANN_CAP);
    }

    return goodCount;
}

static bool processAnns1(Worker_t* w, Result_t* res, int fileNo) {
    // We're setup for doing batches of announcements, but currently
    // we're doing just one at a time.
    int annCount = 1;

    mkDedupes(w->lw.dedupsIn, w->lw.inBuf.anns, annCount);
    int validCount = validateAnns(&w->lw, annCount, res);

    uint64_t now = nowSeconds();
    int goodCount = 0;

    assert(!pthread_mutex_lock(&w->g->deduplock));
    do {
        StateAndOutput_t* sao = w->g->sao;
        uint32_t cph = sao->state.hdr.parentBlockHeight;
        int outCount = sao->outCount;
        uint64_t timeOfLastWrite = sao->timeOfLastWrite;
        if (w->lw.inBuf.parentBlockHeight != cph) {
            if (w->lw.inBuf.parentBlockHeight < cph) {
                DEBUGF("File [%s] has parent block height [%d] which is too old expecting [%d]\n",
                    w->lw.inFile->name, w->lw.inBuf.parentBlockHeight, cph);
                validCount = 0;
                break;
            }
            tryWriteAnnsCritical(w, w->lw.inBuf.parentBlockHeight);
            DEBUGF("New parentBlockHeight [%u]\n", w->lw.inBuf.parentBlockHeight);
        } else if (outCount + validCount >= OUT_ANN_CAP ||
            (timeOfLastWrite + WRITE_EVERY_SECONDS < now))
        {
            // file is full (or WRITE_EVERY_SECONDS seconds have elapsed), write it out
            tryWriteAnnsCritical(w, w->lw.inBuf.parentBlockHeight);
        }
        goodCount = dedupeCritical(w, annCount);
    } while (0);
    assert(!pthread_mutex_unlock(&w->g->deduplock));

    res->accepted += goodCount;
    res->duplicates += (validCount - goodCount);
    res->invalid += (annCount - validCount);

    return goodCount > 0;
}

static void processAnns(Worker_t* w, int fileNo) {
    Result_t res;
    Buf_OBJSET(&res, 0);
    Buf_OBJCPY(res.payTo, w->lw.inBuf.payTo);

    Time t;
    Time_BEGIN(t);
    //DEBUGF("Processing ann file %s\n", w->lw.inFile->name);
    for (;;) {
        uint8_t* contentBuf = NULL;
        uint32_t len = w->lw.inBuf.anns[0].hdr.contentLength;
        if (len > 32) {
            // contentLength > 32 = Out-of-band content
            // therefore the content should follow the announcement header
            contentBuf = malloc(len);
            assert(contentBuf);
            ssize_t len2 = read(fileNo, contentBuf, len);
            if (len2 < 0) {
                DEBUGF("Error reading file content, errno=[%s]\n", strerror(errno));
                res.internalError++;
                break;
            } else if (((size_t)len2) < len) {
                DEBUGF("Runt announcement file [%s], content partially read\n",
                    w->lw.inFile->name);
                res.runt++;
                break;
            }
            Buf32_t b;
            ContentMerkle_compute(&b, contentBuf, len);
            if (Buf_OBJCMP(&b, w->lw.inBuf.anns[0].hdr.contentHash)) {
                DEBUGF("Announcement in file [%s] content doesn't match hash\n",
                    w->lw.inFile->name);
                res.badContentHash++;
                break;
            }

            uint8_t hash[65];
            for (int i = 0; i < 32; i++) {
                sprintf(&hash[i*2], "%02x", b.bytes[i]);
            }
            hash[64] = '\0';
            snprintf(w->lw.annContentFile.name, FilePath_NAME_SZ, "ann_%s.bin", hash);
            strncpy(w->lw.tmpFile.name, w->lw.annContentFile.name, FilePath_NAME_SZ);
            // DEBUGF("writing content to temp file [%s] for content file [%s]\n",
            //             w->lw.tmpFile.path, w->lw.annContentFile.path);
            int outFileNo = open(w->lw.tmpFile.path, O_CREAT | O_WRONLY, 0666);
            if (outFileNo < 0) {
                DEBUGF("Unable to open output file [%s] [%s]\n",
                    w->lw.tmpFile.path, strerror(errno));
                assert(0);
            }
            checkedWrite(w->lw.tmpFile.path, outFileNo, contentBuf, len);
            close(outFileNo);
            if (processAnns1(w, &res, fileNo)) {
                // We need to re-copy the filename over again because tmpFile might
                // be used inside of processAnns1
                strncpy(w->lw.tmpFile.name, w->lw.annContentFile.name, FilePath_NAME_SZ);
                if (rename(w->lw.tmpFile.path, w->lw.annContentFile.path)) {
                    DEBUGF("error renaming temp file [%s] to content file [%s] [%s]\n",
                        w->lw.tmpFile.path, w->lw.annContentFile.path, strerror(errno));
                    assert(0);
                }
            } else {
                strncpy(w->lw.tmpFile.name, w->lw.annContentFile.name, FilePath_NAME_SZ);
                if (unlink(w->lw.tmpFile.path)) {
                    DEBUGF("error deleting temp file [%s] [%s]\n",
                        w->lw.tmpFile.path, strerror(errno));
                    assert(0);
                }
            }
        } else {
            processAnns1(w, &res, fileNo);
        }

        free(contentBuf);

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
        "\"time\":%llu,\"eventId\":\"%s\"}",
        res.accepted, res.duplicates, res.invalid, res.badContentHash, res.runt,
        res.internalError, res.payTo, res.unsignedCount, res.totalContentLength,
        timeMs, eventId);
    checkedWrite(w->lw.tmpFile.path, outFileNo, buf, strlen(buf));
    close(outFileNo);
    strncpy(w->lw.outFile.name, w->lw.inFile->name, FilePath_NAME_SZ);
    if (rename(w->lw.tmpFile.path, w->lw.outFile.path)) {
        DEBUGF("error renaming temp file [%s] to out file [%s] [%s]\n",
            w->lw.tmpFile.path, w->lw.outFile.path, strerror(errno));
        assert(0);
    }
    Time_END(t);
    printf("%s\n", buf);
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
        } else if (w->lw.inBuf.version != 0) {
            DEBUGF("File [%s] has incompatible version [%d]\n",
                w->lw.inFile->path, w->lw.inBuf.version);
            continue;
        }
        processAnns(w, inFileNo);
    }
}

///
/// Master thread stuff
///


typedef struct MasterThread_s {
    Global_t g;
    int threadCount;
    Worker_t* workers;
} MasterThread_t;

static MasterThread_t* createMaster(
    int threadCount,
    const char* inDir,
    const char* outDir,
    const char* annDir,
    const char* stateDir,
    const char* tmpDir,
    const char* contentDir
) {
    MasterThread_t* mt = calloc(sizeof(MasterThread_t), 1);
    assert(mt);
    mt->g.dedup = malloc(Dedup_SIZE(DEDUPE_INITIAL_CAP));
    assert(mt->g.dedup);
    mt->g.dedup->dedupTableCap = DEDUPE_INITIAL_CAP;
    mt->g.dedup->dedupTableLen = 0;
    pthread_mutex_init(&mt->g.deduplock, NULL);

    mt->g.q = WorkQueue_create(inDir, "annshare_", threadCount);

    mt->g.sao = calloc(sizeof(StateAndOutput_t), 1);
    mt->g.sao->timeOfLastWrite = nowSeconds();

    mt->threadCount = threadCount;
    mt->workers = calloc(sizeof(Worker_t), threadCount);
    assert(mt->workers);

    for (int i = 0; i < threadCount; i++) {
        Worker_t* w = &mt->workers[i];
        w->g = &mt->g;
        FilePath_create(&w->lw.outFile, outDir);
        FilePath_create(&w->lw.annFile, annDir);
        FilePath_create(&w->lw.stateFile, stateDir);
        FilePath_create(&w->lw.tmpFile, tmpDir);
        FilePath_create(&w->lw.annContentFile, contentDir);
    }
    return mt;
}

static void destroyMaster(MasterThread_t* mt) {
    for (int i = 0; i < mt->threadCount; i++) {
        Worker_t* w = &mt->workers[i];
        FilePath_destroy(&w->lw.outFile);
        FilePath_destroy(&w->lw.annFile);
        FilePath_destroy(&w->lw.stateFile);
        FilePath_destroy(&w->lw.tmpFile);
        FilePath_destroy(&w->lw.annContentFile);
    }
    free(mt->workers);
    free(mt->g.sao);
    WorkQueue_destroy(mt->g.q);
    pthread_mutex_destroy(&mt->g.deduplock);
    free(mt->g.dedup);
    free(mt);
}

static void loadState(MasterThread_t* mt, DIR* stateDir) {
    int highestFileNo = -1;
    int stateFileDesc = -1;
    for (;;) {
        if (stateFileDesc > -1) {
            close(stateFileDesc);
            stateFileDesc = -1;
        }
        errno = 0;
        struct dirent* file = readdir(stateDir);
        if (file == NULL) {
            if (errno != 0) {
                DEBUGF("Error reading state. errno=[%s]\n", strerror(errno));
            }
            break;
        }
        if (file->d_name[0] == '.') { continue; }
        if (strncmp(file->d_name, "state_", 6) != 0) {
            DEBUGF("Unexpected file in state dir [%s]\n", file->d_name);
            continue;
        }
        int num = strtol(&file->d_name[6], NULL, 10);
        if (num > highestFileNo) { highestFileNo = num; }

        // Workers are not yet started so we can just use the context from one of them.
        FilePath_t* stateFile = &mt->workers[0].lw.stateFile;

        strncpy(stateFile->name, file->d_name, FilePath_NAME_SZ);
        stateFileDesc = open(stateFile->path, O_RDONLY);
        if (stateFileDesc < 0) {
            DEBUGF("Error opening state file [%s]. errno=[%s]\n",
                stateFile->path, strerror(errno));
            continue;
        }
        struct stat st;
        if (fstat(stateFileDesc, &st)) {
            DEBUGF("Failed to stat file [%s]. errno=[%s]\n",
                stateFile->path, strerror(errno));
            continue;
        }
        if (st.st_size < StateFile_Header_SZ) {
            DEBUGF("Error runt state file [%s]. length=[%ld]\n",
                stateFile->path, (long)st.st_size);
            continue;
        }
        size_t numAnns = (st.st_size - StateFile_Header_SZ) / sizeof(AnnEntry_t);
        if (numAnns * sizeof(AnnEntry_t) != (unsigned long)(st.st_size - StateFile_Header_SZ)) {
            DEBUGF("Error oddly sized state file [%s]. length=[%ld]\n",
                stateFile->path, (long)st.st_size);
            continue;
        }
        StateFile_Header_t hdr;
        if (StateFile_Header_SZ != read(stateFileDesc, &hdr, StateFile_Header_SZ)) {
            DEBUGF("Error reading state file [%s]. errno=[%s]\n",
                stateFile->path, strerror(errno));
            continue;
        } else if (hdr.version != STATE_FILE_VERSION) {
            DEBUGF("Got state file [%s] with unexpected version [%u]\n",
                stateFile->path, hdr.version);
            continue;
        }
        if (mt->g.sao->state.hdr.parentBlockHeight < hdr.parentBlockHeight) {
            mt->g.sao->state.hdr.parentBlockHeight = hdr.parentBlockHeight;
        }

        ssize_t remainingAnns = mt->g.dedup->dedupTableCap - mt->g.dedup->dedupTableLen;
        while ((ssize_t)numAnns > remainingAnns) {
            mt->g.dedup->dedupTableCap *= 2;
            mt->g.dedup = realloc(mt->g.dedup, Dedup_SIZE(mt->g.dedup->dedupTableCap));
            remainingAnns = mt->g.dedup->dedupTableCap - mt->g.dedup->dedupTableLen;
        }
        ssize_t bytes = read(stateFileDesc, &mt->g.dedup->entries[mt->g.dedup->dedupTableLen],
            remainingAnns * sizeof(AnnEntry_t));
        if (bytes < 0) {
            DEBUGF("Error reading state file [%s]. errno=[%s]\n",
                stateFile->path, strerror(errno));
            continue;
        }
        if (numAnns * sizeof(AnnEntry_t) != (size_t)bytes) {
            DEBUGF("Error partial read of state file [%s]\n", stateFile->path);
            continue;
        }
        mt->g.dedup->dedupTableLen += numAnns;
    }
    mt->g.sao->nextStateFileNo = highestFileNo + 1;
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

    if ((argc - arg) < 6) { return usage(); }

    if (!strcmp(argv[arg], "--threads")) {
        arg++;
        threads = strtol(argv[arg], NULL, 10);
        if (threads < 1) {
            DEBUGF("I don't understand thread count [%s]", argv[arg]);
            return 100;
        }
        arg++;
    }
    if ((argc - arg) < 6) { return usage(); }

    const char* inDir = argv[arg++];
    const char* outDir = argv[arg++];
    const char* annDir = argv[arg++];
    const char* stateDir = argv[arg++];
    const char* tmpDir = argv[arg++];
    const char* contentDir = argv[arg++];

    FileUtil_checkDir("input", inDir);
    FileUtil_checkDir("output", outDir);
    FileUtil_checkDir("announcement", annDir);
    FileUtil_checkDir("state", stateDir);
    FileUtil_checkDir("temp", tmpDir);
    FileUtil_checkDir("content", contentDir);

    MasterThread_t* mt =
        createMaster(threads, inDir, outDir, annDir, stateDir, tmpDir, contentDir);

    {
        DIR* d = opendir(stateDir);
        if (!d) {
            DEBUGF("Could not access state directory [%s] errno=[%s]", stateDir, strerror(errno));
            assert(0);
        }
        DEBUGF0("Loading state...\n");
        loadState(mt, d);
        DEBUGF("Loaded [%d] dedup entries successfully, current parentBlockHeight [%u]\n",
            mt->g.dedup->dedupTableLen, mt->g.sao->state.hdr.parentBlockHeight);
        closedir(d);
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
    }

    DEBUGF0("Got request to stop, stopping threads...\n");

    WorkQueue_stop(mt->g.q);

    // we're using a worker context to write the anns, it doesn't matter which hardware
    // thread we're in, all of the workers are dead. Even though we don't need the lock
    // for mutual exclusion, it's going to get unlocked inside of tryWriteAnnsCritical
    // so we should have it locked first in order to avoid putting it in a bad state.
    assert(!pthread_mutex_lock(&mt->g.deduplock));
    DEBUGF("Writing [%d] anns to disk\n", mt->g.sao->outCount);
    tryWriteAnnsCritical(&mt->workers[0], 0);
    assert(!pthread_mutex_unlock(&mt->g.deduplock));

    destroyMaster(mt);
    DEBUGF0("Graceful shutdown complete\n");
}
