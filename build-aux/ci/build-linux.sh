#!/usr/bin/env bash
set -ex

BUILDROOT="$(git rev-parse --show-toplevel)"

pushd "$BUILDROOT" &>/dev/null
  sudo chown root:root tests/credentials/*
  ./autogen.sh
  ./configure --disable-silent-rules --disable-man
  make check
popd &>/dev/null
