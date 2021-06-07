#!/bin/sh -eux

${CC} --version

./autogen.sh
./configure --enable-fuzzing --disable-silent-rules --disable-man CFLAGS="-fsanitize=address,signed-integer-overflow"
make -j $(nproc)
make -j $(nproc) -C fuzz

curl --retry 4 -s -o corpus.tgz https://storage.googleapis.com/kroppkaka/corpus/pam-u2f.corpus.tgz
tar xzf corpus.tgz
fuzz/fuzz_format_parsers -reload=30 -print_pcs=1  -print_funcs=30 -timeout=10 -runs=1 corpus


