/*
 * Copyright (C) 2021-2025 Yubico AB - See COPYING
 */

#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <stdio.h>

#include "logging.h"

#define FORMAT "%s(pam_u2f): %s:%d (%s): %s%s"
#define MSGLEN 2048

static _Thread_local int g_debug_enabled = 0;

static const char *level_name(int level) {
  switch (level) {
    case LOG_EMERG:
      return "emerg";
    case LOG_ALERT:
      return "alert";
    case LOG_CRIT:
      return "critical";
    case LOG_ERR:
      return "error";
    case LOG_WARNING:
      return "warning";
    case LOG_NOTICE:
      return "notice";
    case LOG_INFO:
      return "info";
    case LOG_DEBUG:
      return "debug";
  }
  return "-";
}

static void do_log(int level, const char *file, int line, const char *func,
                   const char *msg, const char *suffix) {
#if defined(WITH_FUZZING)
  snprintf(NULL, 0, FORMAT, level_name(level), file, line, func, msg, suffix);
#elif defined(PAM_U2F_TESTING)
  fprintf(stderr, FORMAT, level_name(level), file, line, func, msg, suffix);
  fputc('\n', stderr);
#else
  syslog(LOG_AUTHPRIV | LOG_DEBUG, FORMAT, level_name(level), file, line, func,
         msg, suffix);
#endif
}

ATTRIBUTE_FORMAT(printf, 5, 0)
static void log_vprintf(int level, const char *file, int line, const char *func,
                        const char *fmt, va_list args) {
  const char *bn;
  char msg[MSGLEN];
  int r;

  if ((bn = strrchr(file, '/')) != NULL)
    file = bn + 1;

  if ((r = vsnprintf(msg, sizeof(msg), fmt, args)) < 0)
    do_log(level, file, line, func, __func__, "");
  else
    do_log(level, file, line, func, msg,
           (size_t) r < sizeof(msg) ? "" : "[truncated]");
}

void log_printf(int level, const char *file, int line, const char *func,
                const char *fmt, ...) {
  va_list ap;

  if (level == LOG_DEBUG && !g_debug_enabled)
    return;

  va_start(ap, fmt);
  log_vprintf(level, file, line, func, fmt, ap);
  va_end(ap);
}

void log_debug_enable(void) { g_debug_enabled = 1; }
