#!/bin/bash
die() { exit 1; }
eval "${MATRIX_EVAL}";
if test "x$LINT" = "x1"; then
    npm install || die
    npm install -g 'jshint@^2.10.2' || die
    npm run lint || die
    npm run flow || die
else
    if test "`uname`" = "Darwin"; then
        brew install libsodium pkg-config autoconf-archive openssl || die
        ./autogen.sh || die
        export PKG_CONFIG_PATH="$PKG_CONFIG_PATH:`echo /usr/local/Cellar/libsodium/*/lib/pkgconfig`"
        export PKG_CONFIG_PATH="$PKG_CONFIG_PATH:`echo /usr/local/Cellar/openssl/*/lib/pkgconfig/`"
        ./configure || die
        make || die
    else
        ./autogen.sh || die
        ./configure CC=$CC CXX=$CXX || die
        make || die
    fi
fi
