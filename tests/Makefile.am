#  Copyright (C) 2014-2022 Yubico AB - See COPYING

AM_TESTS_ENVIRONMENT = PAM_U2F_MODULE='$(top_builddir)/.libs/pam_u2f.so'

AM_CFLAGS = $(CWFLAGS)
AM_CPPFLAGS = -I$(srcdir)/..

AM_LDFLAGS = -no-install

check_PROGRAMS = dlsym_check
dlsym_check_LDFLAGS = -ldl $(AM_LDFLAGS)

# XXX move openbsd-compat
check_PROGRAMS += get_devices
get_devices_SOURCES = get_devices.c mock_syslog.c
get_devices_LDADD = $(top_builddir)/libmodule.la

check_PROGRAMS += expand
expand_SOURCES = expand.c mock_syslog.c
expand_LDADD = $(top_builddir)/libmodule.la

check_PROGRAMS += cfg
cfg_SOURCES = ./cfg.c ../cfg.c ../logging.c
cfg_CFLAGS = -DPAM_U2F_TESTING -DSCONFDIR='"@SCONFDIR@"' $(AM_CFLAGS)

check_PROGRAMS += util
util_SOURCES = util.c
util_CPPFLAGS = $(LIBFIDO2_CFLAGS) $(AM_CPPFLAGS)
util_LDADD = $(top_builddir)/libmodule.la

check_PROGRAMS += logging
logging_SOURCES = logging.c ../logging.c
logging_CFLAGS = -DPAM_U2F_TESTING -DDEBUG_PAM -DPAM_DEBUG $(AM_CFLAGS)

TESTS = $(check_PROGRAMS)

EXTRA_DIST = CMakeLists.txt
