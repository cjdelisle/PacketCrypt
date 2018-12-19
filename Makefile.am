# what flags you want to pass to the C compiler & linker
CFLAGS = --pedantic -Wall -Wextra -Wno-pointer-sign -std=c11 -O3

bin_PROGRAMS = randhash
randhash_SOURCES = src/randhash.c src/RandGen.c src/PrintProg.c src/Interpreter.c

randhash_CFLAGS = ${sodium_CFLAGS}
randhash_LDADD = ${sodium_LIBS}

lib_LIBRARIES = libprogsupport.a
libprogsupport_a_SOURCES = src/ProgSupport.c