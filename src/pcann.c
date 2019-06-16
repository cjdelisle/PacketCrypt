#include "RandHash.h"
#include "Hash.h"
#include "Buf.h"
#include "CryptoCycle.h"
#include "Work.h"
#include "Time.h"
#include "Announce.h"
#include "packetcrypt/PacketCrypt.h"
#include "packetcrypt/AnnMiner.h"

#include "sodium/core.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>

static int usage() {
    fprintf(stderr, "Usage: ./pcann OPTIONS\n"
        "    OPTIONS:\n"
        "        --test        # testing, no input is needed, bogus anns will be made\n"
        "        --out <f>     # output file, will be reopened when there's new work\n"
        "                      # NOTE: If --out is passed more than once,\n"
        "                      # announcements will be sent to each file split up by the\n"
        "                      # numeric value of the first byte of the announcement hash\n"
        "        --threads <n> # specify number of threads to use (default: 1)\n"
        "\n"
        "    See: https://github.com/cjdelisle/PacketCrypt/blob/master/docs/pcann.md\n"
        "    for more information\n");
    return 100;
}

#define DEBUGF(...) fprintf(stderr, "pcann: " __VA_ARGS__)

typedef struct {
    PacketCrypt_AnnounceHdr_t hdr;
    Buf32_t parentBlockHash;
} Request_t;

_Static_assert(sizeof(Request_t) == 56+32, "");

static void setTestVal(Request_t* req) {
    memset(req, 0, sizeof *req);
    req->hdr.parentBlockHeight = 122;
    req->hdr.workBits = 0x20000fff;
    Buf_OBJCPY(&req->parentBlockHash, "abcdefghijklmnopqrstuvwxyz01234");
}

struct Files {
    int count;
    const char** names;
    int* fileNos;
};
static void addFile(struct Files* files, const char* filename) {
    files->count++;
    int count = files->count;
    files->names = realloc(files->names, count * sizeof(const char*));
    files->fileNos = realloc(files->fileNos, count * sizeof(int));
    files->fileNos[count-1] = -1;
    files->names[count-1] = filename;
}

int main(int argc, const char** argv) {
    assert(!sodium_init());
    if (argc < 2) { return usage(); }

    struct Files files = { .count = 0 };
    bool test = false;
    long threads = 1;
    {
        bool out = false;
        bool t = false;
        for (int i = 1; i < argc; i++) {
            const char* arg = argv[i];
            if (out) {
                addFile(&files, arg);
                out = false;
            } else if (t) {
                threads = strtol(arg, NULL, 10);
                if (threads < 1 || threads > 0xffff) {
                    DEBUGF("--threads parameter [%s] could not be parsed\n", arg);
                    DEBUGF("or was not an integer between 1 and 65535\n");
                    return usage();
                }
                t = false;
            } else if (!strcmp(arg, "--test")) {
                test = true;
            } else if (!strcmp(arg, "--out")) {
                out = true;
            } else if (!strcmp(arg, "--threads")) {
                t = true;
            } else {
                DEBUGF("Invalid argument [%s]\n", arg);
                return usage();
            }
        }
    }

    for (int i = 0; i < files.count; i++) {
        int outFileNo = open(files.names[i], O_WRONLY | O_CREAT | O_APPEND, 0666);
        if (outFileNo < 0) {
            DEBUGF("Error opening output file [%s] [%s]\n",
                files.names[i], strerror(errno));
            return 100;
        }
        files.fileNos[i] = outFileNo;
    }
    AnnMiner_t* annMiner = AnnMiner_create(threads, files.fileNos, files.count, 0);

    Request_t req;
    if (test) { setTestVal(&req); }
    bool newData = true;
    for (;;) {
        if (!test) {
            for (;;) {
                ssize_t ret = fread(&req, sizeof req, 1, stdin);
                if (!ret) {
                    if (errno == 0) {
                        // EOF, parent died
                        DEBUGF("Parent dead, shutting down\n");
                        return 0;
                    }
                    DEBUGF("Failed read of stdin [%d] [%s]\n", errno, strerror(errno));
                    sleep(1);
                    continue;
                }
                assert(ret == 1);
                break;
            }
            newData = true;
        }
        if (newData) {
            if (files.count) {
                AnnMiner_stop(annMiner);
                for (int i = 0; i < files.count; i++) {
                    int newOutFileNo = open(files.names[i], O_WRONLY | O_CREAT | O_APPEND, 0666);
                    if (newOutFileNo < 0) {
                        DEBUGF("Error: unable to re-open outfile [%s] [%s]\n",
                            files.names[i], strerror(errno));
                        return 100;
                    }
                    if (dup2(newOutFileNo, files.fileNos[i]) < 0) {
                        DEBUGF("Error: unable to dup2() outfile [%s]\n",
                            strerror(errno));
                        return 100;
                    }
                    close(newOutFileNo);
                }
            }
            DEBUGF("Starting job with work target %08x\n", req.hdr.workBits);
            AnnMiner_start(annMiner, &req.hdr, req.parentBlockHash.bytes);
            newData = false;
        }

        int64_t hps = AnnMiner_getHashesPerSecond(annMiner);
        if (hps) { DEBUGF("%lu hashes per second\n", (unsigned long)hps); }

        if (test) { sleep(1); }
    }

    AnnMiner_free(annMiner);
}
