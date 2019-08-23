#!/usr/bin/env bash
set -ex

BUILDROOT="$(git rev-parse --show-toplevel)"

source $BUILDROOT/build-aux/ci/format-code.sh "$(git rev-parse HEAD~)"
source $BUILDROOT/build-aux/ci/build-linux.sh
