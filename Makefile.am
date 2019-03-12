# what flags you want to pass to the C compiler & linker
CFLAGS = \
    --pedantic \
    -Wall \
    -Wextra \
    -Wno-pointer-sign \
    -Wno-unused-parameter \
    -std=c11 \
    -g \
    -O3 -march=native -Werror

#-fsanitize=address -lasan

CXXFLAGS = \
    --pedantic \
    -Wall \
    -Wextra \
    -Wno-unused-parameter \
    -std=c++11 \
    -g \
    -O0 -march=native -Werror

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
    src/optest.c \
                                src/RandHash.h \
    src/Time.c                  src/Time.h \
                                src/Util.h \
                                src/Vec.h \
    src/Work.c                  src/Work.h

libpacketcrypt_a_CFLAGS = ${CRYPTO_CFLAGS} ${sodium_CFLAGS} ${PTHREAD_CFLAGS} -Iinclude

bin_PROGRAMS += pcblk
pcblk_SOURCES = src/pcblk.c \
                                include/BlockMiner.h \
                                include/PacketCrypt.h
pcblk_CFLAGS = -Iinclude
pcblk_LDADD = libpacketcrypt.a ${sodium_LIBS} ${PTHREAD_CFLAGS} ${CRYPTO_LIBS}

bin_PROGRAMS += pcann
pcann_SOURCES = src/pcann.c \
                                include/AnnMiner.h \
                                include/PacketCrypt.h
pcann_CFLAGS = -Iinclude
pcann_LDADD = libpacketcrypt.a ${sodium_LIBS} ${PTHREAD_CFLAGS} ${CRYPTO_LIBS}

if ENABLE_DIFFTEST
bin_PROGRAMS +=  difftest
difftest_SOURCES = src/difftest/main.cpp \
    src/difftest/bignum.h \
    src/Difficulty.c \
    src/Difficulty.h
difftest_CFLAGS = ${CRYPTO_CFLAGS}
difftest_LDADD = ${CRYPTO_LIBS}
endif

bin_PROGRAMS += optest
optest_SOURCES = Makefile \
    src/optest.c \
    src/Hash.c                  src/Hash.h \
    src/RandGen.c               src/RandGen.h \
    src/RandHash_interpreted.c
optest_CFLAGS = -Iinclude -DOPTEST=1
optest_LDADD = ${sodium_LIBS}
