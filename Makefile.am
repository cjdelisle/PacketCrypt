# (C) Copyright 2019
# Caleb James DeLisle
#
# SPDX-License-Identifier: (LGPL-2.1-only OR LGPL-3.0-only)

WARNFLAGS = -Wall -Wextra --pedantic

# clang should not panic when GCC options are passed
WARNFLAGS += -Wno-unknown-warning-option

# gcc thinks every snprintf is potentially 4096 bytes
WARNFLAGS += -Wno-stringop-truncation

# warning about unused arguments to a function is annoying
WARNFLAGS += -Wno-unused-parameter

# likewise, complaining about uint8_t* vs char* is annoying
WARNFLAGS += -Wno-pointer-sign

OPTFLAGS = -O3

DEBUGFLAGS = -g

# Use address sanitizer
#DEBUGFLAGS += -fsanitize=address -lasan

CFLAGS = -std=c11 $(OPTFLAGS) $(WARNFLAGS) $(DEBUGFLAGS)
CXXFLAGS = -std=c++11 $(OPTFLAGS) $(WARNFLAGS) $(DEBUGFLAGS)

bin_PROGRAMS =
lib_LIBRARIES =

lib_LIBRARIES += libpacketcrypt.a
libpacketcrypt_a_SOURCES = Makefile\
                                include/PacketCrypt.h \
    src/Validate.c              include/Validate.h \
    src/AnnMiner.c              include/AnnMiner.h \
    src/BlockMiner.c            include/BlockMiner.h \
    src/AnnMerkle.c             src/AnnMerkle.h \
    src/Announce.c              src/Announce.h \
                                src/Buf.h \
                                src/Conf.h \
    src/ContentMerkle.c         src/ContentMerkle.h \
    src/CryptoCycle.c           src/CryptoCycle.h \
                                src/DecodeInsn.h \
    src/Difficulty.c            src/Difficulty.h \
    src/Hash.c                  src/Hash.h \
                                src/OpCodes.h \
                                src/OpTemplate.h \
    src/PacketCryptProof.c      src/PacketCryptProof.h \
    src/PcCompress.c            src/PcCompress.h \
    src/RandGen.c               src/RandGen.h \
    src/RandHash_interpreted.c \
    src/RandHashOps.c           src/RandHashOps.h \
                                src/RandHash.h \
    src/Time.c                  src/Time.h \
                                src/Util.h \
                                src/Vec.h \
    src/Work.c                  src/Work.h

libpacketcrypt_a_CFLAGS = ${CRYPTO_CFLAGS} ${sodium_CFLAGS} ${PTHREAD_CFLAGS} -Iinclude

bin_PROGRAMS += bin/pcblk
bin_pcblk_SOURCES = src/pcblk.c \
                                include/BlockMiner.h \
                                include/PacketCrypt.h \
    src/FileUtil.c src/FileUtil.h
bin_pcblk_CFLAGS = -Iinclude ${sodium_CFLAGS}
bin_pcblk_LDADD = libpacketcrypt.a ${sodium_LIBS} ${PTHREAD_CFLAGS} ${CRYPTO_LIBS} -lm

bin_PROGRAMS += bin/pcann
bin_pcann_SOURCES = src/pcann.c \
                                include/AnnMiner.h \
                                include/PacketCrypt.h
bin_pcann_CFLAGS = -Iinclude ${sodium_CFLAGS}
bin_pcann_LDADD = libpacketcrypt.a ${sodium_LIBS} ${PTHREAD_CFLAGS} ${CRYPTO_LIBS}

if ENABLE_DIFFTEST
bin_PROGRAMS +=  bin/difftest
bin_difftest_SOURCES = src/difftest/main.cpp \
    src/difftest/bignum.h \
    src/Difficulty.c \
    src/Difficulty.h
bin_difftest_CFLAGS = ${CRYPTO_CFLAGS}
bin_difftest_LDADD = ${CRYPTO_LIBS}
endif

bin_PROGRAMS += bin/optest
bin_optest_SOURCES = Makefile \
    src/optest.c \
    src/Hash.c                  src/Hash.h \
    src/RandGen.c               src/RandGen.h \
    src/RandHash_interpreted.c
bin_optest_CFLAGS = -Iinclude ${sodium_CFLAGS} -DOPTEST=1
bin_optest_LDADD = ${sodium_LIBS}

bin_PROGRAMS += bin/checkanns
bin_checkanns_SOURCES = Makefile \
    src/checkanns.c \
    include/packetcrypt/PacketCrypt.h \
    include/packetcrypt/Validate.h \
    src/Buf.h \
    src/Hash.h \
    src/Time.h \
    src/FilePath.h \
    src/WorkQueue.c src/WorkQueue.h \
    src/FileUtil.c src/FileUtil.h \
    src/ContentMerkle.c src/ContentMerkle.h
bin_checkanns_CFLAGS = -Iinclude ${sodium_CFLAGS}
bin_checkanns_LDADD = libpacketcrypt.a ${sodium_LIBS} ${PTHREAD_CFLAGS} ${CRYPTO_LIBS}
