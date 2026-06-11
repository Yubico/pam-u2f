/*
 *  Copyright (C) 2014-2025 Yubico AB - See COPYING
 */

#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

/* XXX: force all debug output to stderr */
void syslog(int priority, const char *message, ...) {
  va_list ap;

  (void) priority;

  va_start(ap, message);
  vfprintf(stderr, message, ap);
  va_end(ap);
  fputc('\n', stderr);
}
