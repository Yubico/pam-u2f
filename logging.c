/*
 * Copyright (C) 2021-2025 Yubico AB - See COPYING
 */

#include <stdarg.h>
#include <string.h>
#include <syslog.h>

#include "logging.h"

#define DEBUG_FMT "debug(pam_u2f): %s:%d (%s): %s%s"
#define MSGLEN 2048

static void do_log(const char *file, int line, const char *func,
                   const char *msg, const char *suffix) {
#if defined(WITH_FUZZING)
  snprintf(NULL, 0, DEBUG_FMT, file, line, func, msg, suffix);
#elif defined(PAM_U2F_TESTING)
  fprintf(stderr, DEBUG_FMT, file, line, func, msg, suffix);
  fputc('\n', stderr);
#else
  syslog(LOG_AUTHPRIV | LOG_DEBUG, DEBUG_FMT, file, line, func, msg, suffix);
#endif
}

ATTRIBUTE_FORMAT(printf, 4, 0)
static void debug_vfprintf(const char *file, int line, const char *func,
                           const char *fmt, va_list args) {
  const char *bn;
  char msg[MSGLEN];
  int r;

  if ((bn = strrchr(file, '/')) != NULL)
    file = bn + 1;

  if ((r = vsnprintf(msg, sizeof(msg), fmt, args)) < 0)
    do_log(file, line, func, __func__, "");
  else
    do_log(file, line, func, msg,
           (size_t) r < sizeof(msg) ? "" : "[truncated]");
}

void debug_printf(const char *file, int line, const char *func, const char *fmt,
                  ...) {
  va_list ap;

  va_start(ap, fmt);
  debug_vfprintf(file, line, func, fmt, ap);
  va_end(ap);
}
