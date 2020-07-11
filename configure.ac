#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([randomhash], [0.0.1], [cjd@cjdns.fr])
AC_CONFIG_SRCDIR([src/Conf.h])
AM_INIT_AUTOMAKE([1.11 dist-bzip2 tar-ustar foreign subdir-objects])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_RANLIB

AX_CXX_COMPILE_STDCXX_11([ext],[mandatory])

# Checks for libraries.
PKG_CHECK_MODULES([sodium], [libsodium], [], [
    AC_MSG_ERROR([
        libsodium not found
        1. make sure it's installed
        2. try to locate the file: libsodium.pc and you can inform pkg-config where to find it as
           follows ( pretending it's in usr/local/libpkgconfig/ )
           $ PKG_CONFIG_PATH=/usr/local/lib/pkgconfig/ ./configure
        3. If you have no libsodium.pc file but you're sure it's installed (homebrew on OSX) then
           you can pass the pass the header and lib arguments for libsodium as follows:
           $ sodium_CFLAGS=-I/usr/local/include sodium_LIBS=-lsodium ./configure
    ])
])

# Difficulty_getEffectiveTarget() uses libcrypto
PKG_CHECK_MODULES([CRYPTO], [libcrypto],, [AC_MSG_ERROR(libcrypto not found.)])

AX_PTHREAD([], [
    AC_MSG_ERROR([
        pthread missing
    ])
])

AC_SEARCH_LIBS([floor], [m])

AC_CHECK_HEADERS([ \
    assert.h \
    dirent.h \
    errno.h \
    fcntl.h \
    math.h \
    pthread.h \
    openssl/bn.h \
    pthread.h \
    signal.h \
    stdarg.h \
    stdbool.h \
    stdint.h \
    stdio.h \
    stdlib.h \
    string.h \
    sys/stat.h \
    sys/types.h \
    time.h \
    unistd.h \
])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([gettimeofday memset])

# conditionals
AC_ARG_ENABLE([difftest],
    AS_HELP_STRING([--enable-difftest], [Build difftest which requires an old version of openssl,
 only needed for testing]),
    [ enable_difftest=yes ]
)
AM_CONDITIONAL([ENABLE_DIFFTEST], [test x$enable_difftest = xyes])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
