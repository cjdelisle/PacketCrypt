# what flags you want to pass to the C compiler & linker
CFLAGS = --pedantic -Wall -Wextra -Wno-pointer-sign -Wno-unused-parameter -std=c11 -O3 -march=native

bin_PROGRAMS = pcann simplehash
pcann_SOURCES = \
    src/pcann.c \
    src/RandGen.c   \
    src/RandHash.c  \
    src/RandHash_interpreted.c \
    src/PrintProg.c \
    src/Work.c  \
    src/CryptoCycle.c \
    src/Hash.c \
    src/Merkle.c

simplehash_SOURCES = src/simplehash.c \
    src/RandGen.c   \
    src/PrintProg.c \
    src/RandHash.c  \
    src/RandHash_interpreted.c \
    src/Hash.c

pcann_CFLAGS = ${sodium_CFLAGS}
pcann_LDADD = ${sodium_LIBS}

simplehash_CFLAGS = ${sodium_CFLAGS}
simplehash_LDADD = ${sodium_LIBS}

lib_LIBRARIES = libprogsupport.a
libprogsupport_a_SOURCES = src/ProgSupport.c src/Hash.c