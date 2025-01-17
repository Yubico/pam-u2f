/*
 * Copyright (C) 2021-2025 Yubico AB - See COPYING
 */

#ifndef LOGGING_H
#define LOGGING_H

#include <syslog.h>

#if defined(DEBUG_PAM)
#define LOG(level, ...)                                                        \
  log_printf(level, __FILE__, __LINE__, __func__, __VA_ARGS__);
#else /* DEBUG_PAM */
#define LOG(level, ...) ((void) level)
#endif /* DEBUG_PAM */

#ifdef __GNUC__
#define ATTRIBUTE_FORMAT(f, s, a) __attribute__((format(f, s, a)))
#else
#define ATTRIBUTE_FORMAT(f, s, a)
#endif

void log_printf(int level, const char *, int, const char *, const char *, ...)
  ATTRIBUTE_FORMAT(printf, 5, 6);

void log_debug_enable(void);

#endif /* LOGGING_H */
