# Copyright (C) 2020 Yubico AB - See COPYING

AM_CFLAG = ${(WARN_FLAGS)
AM_CPPFLAGS = $(LIBFIDO2_CFLAGS) $(LIBCRYPTO_CFLAGS) -I$(srcdir)/..
AM_CPPFLAGS+=-fsanitize=fuzzer,address,signed-integer-overflow 
AM_CPPFLAGS+=-fno-sanitize-recover=all

fuzz_format_parsers_SOURCES = fuzz_format_parsers.c

fuzz_format_parsers_LDADD = -lpam $(LIBFIDO2_LIBS) $(LIBCRYPTO_LIBS)
fuzz_format_parsers_LDFLAGS = -Wl,--wrap=strdup -Wl,--wrap=calloc
fuzz_format_parsers_LDFLAGS+= -fsanitize=fuzzer,address,signed-integer-overflow

bin_PROGRAMS = fuzz_format_parsers
