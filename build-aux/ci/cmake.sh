#!/usr/bin/env sh
# Copyright (C) 2025 Yubico AB - See COPYING

set -exu

GIT_TOPLEVEL="$(git rev-parse --show-toplevel)"

scan_build() {
  ${SCAN_BUILD:+scan-build${CC#clang} --use-cc="${CC}"} "$@"
}

case "$RUNNER_OS" in

  Linux)
    case "${CC}" in
    clang*) SCAN_BUILD=1
    esac

    NPROC="$(nproc)"
    ;;

  macOS)
    # Link to the same OpenSSL version as libfido2.
    OPENSSL="$(brew deps libfido2 | grep openssl)"
    LIBFIDO2_PKGCONF="$(brew --prefix libfido2)/lib/pkgconfig"
    OPENSSL_PKGCONF="$(brew --prefix "${OPENSSL}")/lib/pkgconfig"
    export PKG_CONFIG_PATH="${LIBFIDO2_PKGCONF}:${OPENSSL_PKGCONF}"

    NPROC="$(sysctl -n hw.logicalcpu)"
    ;;

  *)
    echo >&2 "Not yet supported: $RUNNER_OS"
    exit 1

esac

cmake \
  -B ./build \
  -S "$GIT_TOPLEVEL" \
  -G Ninja \
  -DCMAKE_C_FLAGS='-Werror' \
  -DBUILD_MANPAGES=OFF \
;
scan_build cmake --build ./build -j "$NPROC" -v

CTEST_OUTPUT_ON_FAILURE=1 \
  cmake --build ./build -j "$NPROC" -v -t test
