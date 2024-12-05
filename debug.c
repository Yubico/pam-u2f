/*
 * Copyright (C) 2021 Yubico AB - See COPYING
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "debug.h"

#define DEBUG_FMT "debug(pam_u2f): %s:%d (%s): %s%s"
#define MSGLEN 2048

static int debug_get_file(const char *name, FILE **out)
{
  struct stat st;
  FILE *file;
  int fd;

  if (strcmp(name, "stdout") == 0) {
    *out = stdout;
    return 0;
  }
  if (strcmp(name, "stderr") == 0) {
    *out = stderr;
    return 0;
  }
  if (strcmp(name, "syslog") == 0) {
    *out = NULL;
    return 0;
  }

  fd = open(name, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY | O_CREAT);
  if (fd == -1 || fstat(fd, &st) != 0) {
    D(DEFAULT_DEBUG_FILE, "Could not open %s: %s", name, strerror(errno));
    goto err;
  }

#ifndef WITH_FUZZING
  if (!S_ISREG(st.st_mode))
    goto err;
#endif

  if ((file = fdopen(fd, "a")) != NULL) {
    *out = file;
    return 0;
  }

err:
  if (fd != -1)
    close(fd);

  return -1;
}

FILE *debug_open(const char *name) {
  FILE *ret;

  if (debug_get_file(name, &ret))
    return DEFAULT_DEBUG_FILE;

  return ret;
}

void debug_close(FILE *f) {
  if (f == NULL || f == stdout || f == stderr)
    return;

  if (fflush(f) == EOF)
    D(DEFAULT_DEBUG_FILE, "Could not close debug file: %s", strerror(errno));

  fclose(f);
}

FILE *debug_replace(FILE *old, const char *new_name) {
  FILE *new;

  if (debug_get_file(new_name, &new))
    return old;

  debug_close(old);
  return new;
}

static void do_log(FILE *debug_file, const char *file, int line,
                   const char *func, const char *msg, const char *suffix) {
#ifndef WITH_FUZZING
  if (debug_file == NULL) {
    syslog(LOG_AUTHPRIV | LOG_DEBUG, DEBUG_FMT, file, line, func, msg, suffix);
  } else {
    fprintf(debug_file, DEBUG_FMT "\n", file, line, func, msg, suffix);
  }
#else
  (void) debug_file;
  snprintf(NULL, 0, DEBUG_FMT, file, line, func, msg, suffix);
#endif
}

ATTRIBUTE_FORMAT(printf, 5, 0)
static void debug_vfprintf(FILE *debug_file, const char *file, int line,
                           const char *func, const char *fmt, va_list args) {
  const char *bn;
  char msg[MSGLEN];
  int r;

  if ((bn = strrchr(file, '/')) != NULL)
    file = bn + 1;

  if ((r = vsnprintf(msg, sizeof(msg), fmt, args)) < 0)
    do_log(debug_file, file, line, func, __func__, "");
  else
    do_log(debug_file, file, line, func, msg,
           (size_t) r < sizeof(msg) ? "" : "[truncated]");
}

void debug_fprintf(FILE *debug_file, const char *file, int line,
                   const char *func, const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  debug_vfprintf(debug_file, file, line, func, fmt, ap);
  va_end(ap);
}
