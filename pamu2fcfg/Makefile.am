#  Copyright (C) 2014-2022 Yubico AB - See COPYING

AM_CFLAGS = $(CWFLAGS) $(CSFLAGS)
AM_CPPFLAGS = -I$(srcdir)/.. $(LIBFIDO2_CFLAGS)

bin_PROGRAMS = pamu2fcfg

pamu2fcfg_SOURCES = pamu2fcfg.c
pamu2fcfg_SOURCES += cmdline.ggo cmdline.c cmdline.h
pamu2fcfg_SOURCES += readpassphrase.c _readpassphrase.h
pamu2fcfg_SOURCES += strlcpy.c openbsd-compat.h
pamu2fcfg_SOURCES += ../util.c ../b64.c ../explicit_bzero.c
pamu2fcfg_LDADD = $(LIBFIDO2_LIBS) $(LIBCRYPTO_LIBS)

%.c %.h: %.ggo
	$(AM_V_GEN)gengetopt --no-handle-help --input $<

BUILT_SOURCES = cmdline.c cmdline.h
MAINTAINERCLEANFILES = $(BUILT_SOURCES)
