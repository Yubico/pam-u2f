#  Copyright (C) 2014-2018 Yubico AB - See COPYING
#

AUTOMAKE_OPTIONS = serial-tests

AM_CFLAGS = $(WARN_CFLAGS)
AM_CPPFLAGS=-I$(srcdir)/.. -I$(builddir)/..

AM_LDFLAGS = -no-install

LDADD = $(top_builddir)/pam_u2f.la

.templ.cred:
		@sed "s/__USERNAME__/$(shell whoami)/g" $< > $@

check_PROGRAMS = basic get_devices

get_devices_SOURCES = get_devices.c

get_devices_DEPENDENCIES = credentials/new_double_-N.cred
get_devices_DEPENDENCIES += credentials/new_double_-P-N.cred
get_devices_DEPENDENCIES += credentials/new_double_-P.cred
get_devices_DEPENDENCIES += credentials/new_double_-P-V-N.cred
get_devices_DEPENDENCIES += credentials/new_double_-P-V.cred
get_devices_DEPENDENCIES += credentials/new_double_-r-N.cred
get_devices_DEPENDENCIES += credentials/new_double_-r-P-N.cred
get_devices_DEPENDENCIES += credentials/new_double_-r-P.cred
get_devices_DEPENDENCIES += credentials/new_double_-r-P-V-N.cred
get_devices_DEPENDENCIES += credentials/new_double_-r-P-V.cred
get_devices_DEPENDENCIES += credentials/new_double_-r.cred
get_devices_DEPENDENCIES += credentials/new_double_-r-V-N.cred
get_devices_DEPENDENCIES += credentials/new_double_-r-V.cred
get_devices_DEPENDENCIES += credentials/new_double_.cred
get_devices_DEPENDENCIES += credentials/new_double_-V-N.cred
get_devices_DEPENDENCIES += credentials/new_double_-V.cred
get_devices_DEPENDENCIES += credentials/new_mixed_12.cred
get_devices_DEPENDENCIES += credentials/new_mixed_1-P2.cred
get_devices_DEPENDENCIES += credentials/new_mixed_-P12.cred
get_devices_DEPENDENCIES += credentials/new_mixed_-P1-P2.cred
get_devices_DEPENDENCIES += credentials/new_-N.cred
get_devices_DEPENDENCIES += credentials/new_-P-N.cred
get_devices_DEPENDENCIES += credentials/new_-P.cred
get_devices_DEPENDENCIES += credentials/new_-P-V-N.cred
get_devices_DEPENDENCIES += credentials/new_-P-V.cred
get_devices_DEPENDENCIES += credentials/new_-r-N.cred
get_devices_DEPENDENCIES += credentials/new_-r-P-N.cred
get_devices_DEPENDENCIES += credentials/new_-r-P.cred
get_devices_DEPENDENCIES += credentials/new_-r-P-V-N.cred
get_devices_DEPENDENCIES += credentials/new_-r-P-V.cred
get_devices_DEPENDENCIES += credentials/new_-r.cred
get_devices_DEPENDENCIES += credentials/new_-r-V-N.cred
get_devices_DEPENDENCIES += credentials/new_-r-V.cred
get_devices_DEPENDENCIES += credentials/new_.cred
get_devices_DEPENDENCIES += credentials/new_-V-N.cred
get_devices_DEPENDENCIES += credentials/new_-V.cred
get_devices_DEPENDENCIES += credentials/old_credential.cred
get_devices_DEPENDENCIES += credentials/ssh_credential.cred

TESTS = $(check_PROGRAMS)

clean-local:
	rm -rf credentials/*.cred
