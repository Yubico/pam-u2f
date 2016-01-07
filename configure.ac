#  Copyright (C) 2014-2015 Yubico AB - See COPYING
#

AC_INIT([pam_u2f], [1.0.5], [yubico-devel@googlegroups.com])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 foreign -Wall -Werror])
AM_SILENT_RULES([yes])
AM_PROG_CC_C_O

m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

AC_LIBTOOL_WIN32_DLL
AC_DISABLE_STATIC
AC_PROG_LIBTOOL
AM_MISSING_PROG([A2X], a2x, $missing_dir)

AC_CHECK_HEADERS([security/pam_appl.h], [],
  [AC_MSG_ERROR([[PAM header files not found, install libpam-dev.]])])
AC_CHECK_HEADERS([security/pam_modules.h security/_pam_macros.h security/pam_modutil.h], [], [],
  [#include <sys/types.h>
   #include <security/pam_appl.h>])

AC_CHECK_LIB([pam], [pam_start])

PKG_CHECK_MODULES([LIBU2FHOST], [u2f-host], [], [])
PKG_CHECK_MODULES([LIBU2FSERVER], [u2f-server], [], [])

AC_SUBST(PAMDIR, "/lib/x86_64-linux-gnu/security")
AC_ARG_WITH(pam-dir,
  AC_HELP_STRING([--with-pam-dir=DIR],
                 [Where to install PAM module [[PREFIX/lib/x86_64-linux-gnu/security]]]),
            [case "${withval}" in
            /*) PAMDIR="${withval}";;
            ./*|../*) AC_MSG_ERROR(Bad value for --with-pam-dir);;
            *)  PAMDIR="\$(exec_prefix)/lib/${withval}";;
            esac])
AC_MSG_NOTICE([PAM installation path $PAMDIR])

# Check for secure_getenv
am_save_CFLAGS="$CFLAGS"
am_save_LIBS="$LIBS"
CFLAGS="$CFLAGS"
LIBS="$LIBS"
AC_CHECK_FUNCS([secure_getenv])
CFLAGS=$am_save_CFLAGS
LIBS=$am_save_LIBS

AC_ARG_ENABLE([gcc-warnings],
  [AS_HELP_STRING([--enable-gcc-warnings],
      [turn on lots of GCC warnings (for developers)])],
  [case $enableval in
     yes|no) ;;
     *)      AC_MSG_ERROR([bad value $enableval for gcc-warnings option]) ;;
   esac
   gl_gcc_warnings=$enableval],
  [gl_gcc_warnings=no]
)

if test "$gl_gcc_warnings" = yes; then
  nw="$nw -Wsystem-headers"         # Don't let system headers trigger warnings
  nw="$nw -Wpadded"                 # Struct's arenot padded
  nw="$nw -Wc++-compat"             # We don't care strongly about C++ compilers
  nw="$nw -Wtraditional"            # Warns on #elif which we use often
  nw="$nw -Wtraditional-conversion" # Too many warnings for now
  nw="$nw -Wconversion"             # Too many warnings for now
  nw="$nw -Wsuggest-attribute=pure" # Is it worth using attributes?

  gl_MANYWARN_ALL_GCC([ws])
  gl_MANYWARN_COMPLEMENT(ws, [$ws], [$nw])
  for w in $ws; do
    gl_WARN_ADD([$w])
  done

  gl_WARN_ADD([-fdiagnostics-show-option])
fi

AC_CONFIG_FILES([
  Makefile
  pamu2fcfg/Makefile
  tests/Makefile
])
AC_OUTPUT

AC_MSG_NOTICE([Summary of build options:

  Version:             ${VERSION}
  Host type:           ${host}
  Install prefix:      ${prefix}
  Compiler:            ${CC}
  Library types:       Shared=${enable_shared}, Static=${enable_static}
  LIBU2FHOST CFLAGS:   $LIBU2FHOST_CFLAGS
  LIBU2FHOST LIBS:     $LIBU2FHOST_LIBS
  LIBU2FSERVER CFLAGS: $LIBU2FSERVER_CFLAGS
  LIBU2FSERVER LIBS:   $LIBU2FSERVER_LIBS
  PAMDIR:              $PAMDIR
])
