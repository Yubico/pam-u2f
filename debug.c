/*
 * Copyright (C) 2021 Yubico AB - See COPYING
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "debug.h"

#define DEBUG_STR "debug(pam_u2f): %s:%d (%s): "

FILE *debug_open(const char *filename) {
  struct stat st;
  FILE *file;
  int fd;

  if (strcmp(filename, "stdout") == 0)
    return stdout;
  if (strcmp(filename, "stderr") == 0)
    return stderr;
  if (strcmp(filename, "syslog") == 0)
    return NULL;

  fd = open(filename, O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NOCTTY);
  if (fd == -1 || fstat(fd, &st) != 0)
    goto err;

#ifndef WITH_FUZZING
  if (!S_ISREG(st.st_mode))
    goto err;
#endif

  if ((file = fdopen(fd, "a")) != NULL)
    return file;

err:
  if (fd != -1)
    close(fd);

  return DEFAULT_DEBUG_FILE; /* fallback to default */
}

void debug_close(FILE *f) {
  if (f != NULL && f != stdout && f != stderr)
    fclose(f);
}

void debug_fprintf(FILE *debug_file, const char *file, int line,
                   const char *func, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);

#if defined(WITH_FUZZING)
  (void) debug_file;
  snprintf(NULL, 0, DEBUG_STR, file, line, func);
  vsnprintf(NULL, 0, fmt, ap);
#else
  if (debug_file == NULL) {
    syslog(LOG_AUTHPRIV | LOG_DEBUG, DEBUG_STR, file, line, func);
    vsyslog(LOG_AUTHPRIV | LOG_DEBUG, fmt, ap);
  } else {
    fprintf(debug_file, DEBUG_STR, file, line, func);
    vfprintf(debug_file, fmt, ap);
    fprintf(debug_file, "\n");
  }
#endif
  va_end(ap);
}
