# Copyright (C) 2020 Yubico AB - See COPYING
AM_CFLAGS    = $(CWFLAGS) $(CSFLAGS) -fsanitize=fuzzer
AM_CPPFLAGS  = $(LIBFIDO2_CFLAGS) $(LIBCRYPTO_CFLAGS) -I$(srcdir)/..
AM_LDFLAGS   = -no-install -fsanitize=fuzzer

fuzz_format_parsers_SOURCES = fuzz_format_parsers.c
fuzz_format_parsers_LDADD = -lpam $(LIBFIDO2_LIBS) $(LIBCRYPTO_LIBS) ../pam_u2f.la

noinst_PROGRAMS = fuzz_format_parsers

EXTRA_DIST = coverage.sh make_seed.py
