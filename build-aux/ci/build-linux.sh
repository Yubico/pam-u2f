#!/usr/bin/env bash
set -ex

BUILDROOT="$(git rev-parse --show-toplevel)"

pushd "$BUILDROOT" &>/dev/null
  ./build-aux/ci/format-code.sh
  ./autogen.sh && ./configure --disable-silent-rules --disable-man && make check
popd &>/dev/null
