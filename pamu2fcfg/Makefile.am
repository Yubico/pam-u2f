#  Copyright (C) 2014-2018 Yubico AB - See COPYING

AM_CFLAGS = $(WARN_CFLAGS)
AM_CPPFLAGS=-I$(srcdir)/.. -I$(builddir)/.. $(LIBU2FHOST_CFLAGS) $(LIBU2FSERVER_CFLAGS)

bin_PROGRAMS = pamu2fcfg

pamu2fcfg_SOURCES = pamu2fcfg.c
pamu2fcfg_SOURCES += cmdline.ggo cmdline.c cmdline.h
pamu2fcfg_LDADD = $(LIBU2FHOST_LIBS) $(LIBU2FSERVER_LIBS)

cmdline.c cmdline.h: cmdline.ggo Makefile.am
	gengetopt --no-handle-help --input $^

BUILT_SOURCES = cmdline.c cmdline.h
MAINTAINERCLEANFILES = $(BUILT_SOURCES)

if ENABLE_MAN
dist_man1_MANS = $(top_builddir)/man/pamu2fcfg.1
DISTCLEANFILES = $(dist_man1_MANS)

MANSOURCES = $(top_builddir)/man/pamu2fcfg.1.txt
EXTRA_DIST = $(MANSOURCES)

SUFFIXES = .1.txt .1

.1.txt.1:
	$(A2X) --format=manpage -L -a revdate="Version $(VERSION)" $<
endif
