#  Copyright (C) 2014-2022 Yubico AB - See COPYING

AM_TESTS_ENVIRONMENT = PAM_U2F_MODULE='$(top_builddir)/.libs/pam_u2f.so'

AM_CFLAGS = $(CWFLAGS)
AM_CPPFLAGS = -I$(srcdir)/..

AM_LDFLAGS = -no-install

check_PROGRAMS = dlsym_check
dlsym_check_LDFLAGS = -ldl $(AM_LDFLAGS)

# XXX move openbsd-compat
check_PROGRAMS += get_devices
get_devices_SOURCES = get_devices.c
get_devices_LDADD = $(top_builddir)/libmodule.la

check_PROGRAMS += expand
expand_LDADD = $(top_builddir)/libmodule.la

check_PROGRAMS += cfg
cfg_SOURCES = ./cfg.c ../cfg.c ../debug.c
cfg_CFLAGS = -DPAM_U2F_TESTING -DSCONFDIR='"@SCONFDIR@"' $(AM_CFLAGS)

TESTS = $(check_PROGRAMS)
