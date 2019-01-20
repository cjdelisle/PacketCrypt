#include "RandHash.h"
#include "Hash.h"
#include "Buf.h"
#include "CryptoCycle.h"
#include "Work.h"
#include "Time.h"
#include "Announce.h"
#include "packetcrypt/PacketCrypt.h"
#include "packetcrypt/AnnMiner.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

static int usage() {
    fprintf(stderr, "Usage: ./pcann [-t] <threads>\n");
    fprintf(stderr, "    -t           # testing, no input\n");
    fprintf(stderr, "    <threads>    # number of threads to use for hashing\n");
    return 100;
}

typedef struct {
    PacketCrypt_AnnounceHdr_t hdr;
    Buf32_t parentBlockHash;
} Request_t;

static void setTestVal(Request_t* req) {
    memset(req, 0, sizeof *req);
    req->hdr.parentBlockHeight = 122;
    req->hdr.workBits = 0x200fffff;
    Buf_OBJCPY(&req->parentBlockHash, "abcdefghijklmnopqrstuvwxyz01234");
}

int main(int argc, char** argv) {

    if (argc < 2) { return usage(); }

    char* arg = argv[1];

    bool test = false;
    if (!strcmp(arg, "-t")) {
        if (argc < 3) { return usage(); }
        arg = argv[2];
        test = true;
    }

    long n = strtol(arg, NULL, 10);
    if (n < 1 || n > 0xffff) { return usage(); }

    AnnMiner_t* annMiner = AnnMiner_create(n, STDOUT_FILENO);

    Request_t req;
    if (test) { setTestVal(&req); }
    bool newData = true;
    for (;;) {
        if (!test) {
            assert(1 == fread(&req, sizeof req, 1, STDIN_FILENO));
            newData = true;
        }
        if (newData) {
            fprintf(stderr, "Starting job with work target %08x\n", req.hdr.workBits);
            AnnMiner_start(annMiner,
                req.hdr.contentHash,
                req.hdr.contentType,
                req.hdr.workBits,
                req.hdr.parentBlockHeight,
                req.parentBlockHash.bytes);
            newData = false;
        }

        fprintf(stderr, "%lu hashes per second\n",
            (unsigned long)AnnMiner_getHashesPerSecond(annMiner));

        if (test) { sleep(1); }
    }

    AnnMiner_free(annMiner);
}
