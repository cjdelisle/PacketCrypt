/**
 * (C) Copyright 2019
 * Caleb James DeLisle
 *
 * SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)
 */
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
#include <math.h>

static int usage() {
    fprintf(stderr, "Usage: ./pcann OPTIONS\n"
        "    OPTIONS:\n"
        "        --out <f>     # output file, will be reopened when there's new work\n"
        "                      # NOTE: If --out is passed more than once,\n"
        "                      # announcements will be sent to each file split up by the\n"
        "                      # numeric value of the first byte of the announcement hash\n"
        "        --threads <n> # specify number of threads to use (default: 1)\n"
        "        --minerId <n> # set the number of the miner to dupe announcements\n"
        "        --version <n> # specify the version of announcements to mine\n"
        "        --paranoia    # if specified, every announcement will be checked after\n"
        "                      # it is created\n"
        "\n"
        "    See: https://github.com/cjdelisle/PacketCrypt/blob/master/docs/pcann.md\n"
        "    for more information\n");
    return 100;
}

#define DEBUGF(...) fprintf(stderr, "pcann: " __VA_ARGS__)

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
    long threads = 1;
    uint32_t minerId = 0;
    int version = 0;
    enum AnnMiner_Flags flags = 0;
    {
        bool out = false;
        bool t = false;
        bool mid = false;
        bool ver = false;
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
            } else if (mid) {
                errno = 0;
                long long lminerId = strtoll(arg, NULL, 10);
                if (lminerId == 0 && errno != 0) {
                    DEBUGF("--minerId parameter [%s] could not be parsed as a number\n", arg);
                    return usage();
                }
                if (lminerId < 0 || lminerId > 0xffffffffll) {
                    DEBUGF("--minerId parameter [%s] is out of range\n", arg);
                    DEBUGF("must be an integer between 0 and 4294967295\n");
                    return usage();
                }
                minerId = lminerId;
                mid = false;
            } else if (ver) {
                version = strtol(arg, NULL, 10);
                if (version < 0 || version > 1) {
                    DEBUGF("--version parameter [%s] could not be parsed\n", arg);
                    DEBUGF("or was not either 0 or 1\n");
                    return usage();
                }
                ver = false;
            } else if (!strcmp(arg, "--out")) {
                out = true;
            } else if (!strcmp(arg, "--threads")) {
                t = true;
            } else if (!strcmp(arg, "--minerId")) {
                mid = true;
            } else if (!strcmp(arg, "--version")) {
                ver = true;
            } else if (!strcmp(arg, "--paranoia")) {
                flags |= AnnMiner_Flags_PARANOIA;
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
    AnnMiner_t* annMiner = AnnMiner_create(minerId, threads, files.fileNos, files.count, flags);

    AnnMiner_Request_t req;
    char* content = NULL;
    char* pleaseFree = NULL;
    for (;;) {
        for (;;) {
            //DEBUGF("Read input\n");
            ssize_t ret = fread(&req, sizeof req, 1, stdin);
            //DEBUGF("Read input complete\n");
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
            if (req.contentLen) {
                assert(req.contentLen < 0xffff);
                pleaseFree = content;
                content = malloc(req.contentLen);
                assert(content);
                //DEBUGF("Read content [%d]\n", req.contentLen);
                if (fread(content, req.contentLen, 1, stdin) != 1) {
                    DEBUGF("Unable to read ann data [%d] [%s], stopping\n",
                        errno, strerror(errno));
                    return 100;
                }
                //DEBUGF("Read content complete\n");
            }
            break;
        }
        if (files.count) {
            // We don't really need to stop here and if we do so then we lose the kbps counter.
            //AnnMiner_stop(annMiner);
            for (int i = 0; i < files.count; i++) {
                //DEBUGF("Re-opening file [%s]\n", files.names[i]);
                int newOutFileNo = open(files.names[i], O_WRONLY | O_CREAT | O_APPEND, 0666);
                if (newOutFileNo > 100) {
                    DEBUGF("WARN using a lot of filenos, opened file [%s] with fileno [%d]\n",
                        files.names[i], newOutFileNo);
                }
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
        if (req.contentLen > 0) {
            DEBUGF("Starting job with work target [%08x] and content length [%d]\n",
                req.workTarget, req.contentLen);
        }
        AnnMiner_start(annMiner, &req, content, version);
        free(pleaseFree);
        pleaseFree = NULL;

        double bps = AnnMiner_getAnnsPerSecond(annMiner) * 8;
        if (bps > 0.0) {
            const char* letter = "KMGPYZ?";
            while (bps > 1000 && *letter != '?') {
                bps /= 1000;
                letter = &letter[1];
            }
            DEBUGF("%.02f%cb/s\n", bps, *letter);
        }
    }

    AnnMiner_free(annMiner);
}
