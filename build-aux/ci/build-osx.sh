#!/usr/bin/env bash
set -e

# Avoid weird interleaving due to buffering.
exec 1>&2

# Link to the same OpenSSL version as libfido2.
OPENSSL="$(brew deps libfido2 | grep openssl)"
LIBFIDO2_PKGCONF="$(brew --prefix libfido2)/lib/pkgconfig"
OPENSSL_PKGCONF="$(brew --prefix "${OPENSSL}")/lib/pkgconfig"
export PKG_CONFIG_PATH="${LIBFIDO2_PKGCONF}:${OPENSSL_PKGCONF}"

./autogen.sh
./configure --disable-silent-rules --disable-man
make -j "$(sysctl -n hw.logicalcpu)"
make check

d_PREFIX="$PWD/my_p"
d_PREFIX_ALT="$PWD/my_p_ALT"
d_DEST="$PWD/my_d"

reset() {
  mkdir -p "$d_PREFIX" && rm -rf "${d_PREFIX:?}/"*
  mkdir -p "$d_PREFIX_ALT" && rm -rf "${d_PREFIX_ALT:?}/"*
  mkdir -p "$d_DEST" && rm -rf "${d_DEST:?}/"*
}

view() {
  : VIEW PREFIX
  ls -lR "$d_PREFIX"

  : VIEW PREFIX_ALT
  ls -lR "$d_PREFIX_ALT"

  : VIEW DESTDIR
  ls -lR "$d_DEST"
}

reset

set -x

: XXX 000
./configure --disable-silent-rules --disable-man
make install || :
view
reset

: XXX 001
make install DESTDIR="$d_DEST" || :
view
reset

: XXX 010
make install prefix="$d_PREFIX" || :
view
reset

: XXX 011
make install prefix="$d_PREFIX" DESTDIR="$d_DEST" || :
view
reset

: XXX 100
./configure --disable-silent-rules --disable-man --prefix="$d_PREFIX"
make install || :
view
reset

: XXX 101
make install DESTDIR="$d_DEST" || :
view
reset

: XXX 110
make install prefix="$d_PREFIX" || :
view
reset

: XXX 111
make install prefix="$d_PREFIX" DESTDIR="$d_DEST" || :
view
reset
