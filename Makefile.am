#  Copyright (C) 2014 Yubico AB - See COPYING

SUBDIRS = . pamu2fcfg tests

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = $(WARN_CFLAGS)

libdir = $(PAMDIR)

lib_LTLIBRARIES = pam_u2f.la

pam_u2f_la_SOURCES = pam-u2f.c
pam_u2f_la_SOURCES += util.c util.h
# XXX add -Wl,-x too?  PAM documentation suggests it.
pam_u2f_la_LIBADD = -lpam
pam_u2f_la_LIBADD += $(LIBU2FHOST_LIBS) $(LIBU2FSERVER_LIBS)
pam_u2f_la_LDFLAGS = -module -avoid-version

DEFS = -DDEBUG_PAM -DPAM_DEBUG @DEFS@

dist_man8_MANS = pam_u2f.8
DISTCLEANFILES = $(dist_man8_MANS)

MANSOURCES = pam_u2f.8.txt
EXTRA_DIST = $(MANSOURCES)

SUFFIXES = .8.txt .8

.8.txt.8:
	$(A2X) --format=manpage -a revdate="Version $(VERSION)" $<

# Release

indent:
	indent -kr -nut -i2 *.c *.h pamu2fcfg/*.c pamu2fcfg/*.h
	indent -kr -nut -i2 *.c *.h pamu2fcfg/*.c pamu2fcfg/*.h

ChangeLog:
	cd $(srcdir) && git2cl > ChangeLog

PROJECT = pam-u2f

release:
	@if test -z "$(KEYID)"; then \
		echo "Try this instead:"; \
		echo "  make release KEYID=[PGPKEYID]"; \
		echo "For example:"; \
		echo "  make release KEYID=2117364A"; \
		exit 1; \
	fi
	@head -3 $(srcdir)/NEWS | grep -q "Version $(VERSION) .released `date -I`" || \
		(echo 'error: Update date/version in $(srcdir)/NEWS.'; exit 1)
	@if test ! -d "$(YUBICO_WWW_REPO)"; then \
		echo "WWW repo not found!"; \
		echo "Make sure that YUBICO_WWW_REPO is set"; \
		exit 1; \
		fi
	rm -f ChangeLog
	make check-doc-dist ChangeLog distcheck
	gpg --detach-sign --default-key $(KEYID) $(PACKAGE)-$(VERSION).tar.gz
	gpg --verify $(PACKAGE)-$(VERSION).tar.gz.sig
	cd $(srcdir) && git push
	cd $(srcdir) && git tag -u $(KEYID) -m $(VERSION) $(VERSION)
	cd $(srcdir) && git push --tags
	$(YUBICO_GITHUB_REPO)/save-mans $(PROJECT) $(MANSOURCES)
	$(YUBICO_GITHUB_REPO)/publish $(PROJECT) $(VERSION) $(PACKAGE)-$(VERSION).tar.gz*

