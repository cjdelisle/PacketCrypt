# what flags you want to pass to the C compiler & linker
CFLAGS = \
    --pedantic \
    -Wall \
    -Wextra \
    -Wno-pointer-sign \
    -Wno-unused-parameter \
    -std=c11 \
    -g \
    -O0 -march=native -Werror

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

bin_PROGRAMS += pcblk
pcblk_SOURCES = src/pcblk.c \
    src/Hash.c \
    src/PacketCrypt.c \
    src/CryptoCycle.c \
    src/Work.c \
    src/Difficulty.c \
    src/Difficulty.h \
    src/PacketCryptProof.c \
    src/PacketCryptProof.h \
    src/PcCompress.h \
    src/PcCompress.c \
    src/Bits.h
pcblk_CFLAGS = ${sodium_CFLAGS} ${PTHREAD_CFLAGS} ${CRYPTO_CFLAGS} -DNO_RANDHASH
pcblk_LDADD = ${sodium_LIBS} ${PTHREAD_LDFLAGS} ${CRYPTO_LIBS}

bin_PROGRAMS += pcann
pcann_SOURCES = src/pcann.c \
    src/RandGen.c   \
    src/RandHash.c  \
    src/RandHash_interpreted.c \
    src/PrintProg.c \
    src/Work.c  \
    src/CryptoCycle.c \
    src/Hash.c \
    src/AnnMerkle.c \
    src/PacketCrypt.c
pcann_CFLAGS = ${sodium_CFLAGS} ${PTHREAD_CFLAGS} ${CRYPTO_CFLAGS}
pcann_LDADD = ${sodium_LIBS} ${PTHREAD_LDFLAGS} ${CRYPTO_LIBS}

bin_PROGRAMS += simplehash
simplehash_SOURCES = src/simplehash.c \
    src/RandGen.c   \
    src/PrintProg.c \
    src/RandHash.c  \
    src/RandHash_interpreted.c \
    src/Hash.c
simplehash_CFLAGS = ${sodium_CFLAGS}
simplehash_LDADD = ${sodium_LIBS}

if ENABLE_DIFFTEST
bin_PROGRAMS +=  difftest
difftest_SOURCES = src/difftest/main.cpp \
    src/difftest/bignum.h \
    src/Difficulty.c \
    src/Difficulty.h
difftest_CFLAGS = ${CRYPTO_CFLAGS}
difftest_LDADD = ${CRYPTO_LIBS}
endif

lib_LIBRARIES += libprogsupport.a
libprogsupport_a_SOURCES = src/ProgSupport.c src/Hash.c
