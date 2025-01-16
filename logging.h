/*
 * Copyright (C) 2021-2025 Yubico AB - See COPYING
 */

#ifndef LOGGING_H
#define LOGGING_H

#include <stdio.h>

#if defined(DEBUG_PAM)
#define D(...) debug_printf(__FILE__, __LINE__, __func__, __VA_ARGS__)
#else
#define D(...) ((void) 0)
#endif /* DEBUG_PAM */

#define debug_dbg(cfg, ...)                                                    \
  do {                                                                         \
    if (cfg->debug) {                                                          \
      D(__VA_ARGS__);                                                          \
    }                                                                          \
  } while (0)

#ifdef __GNUC__
#define ATTRIBUTE_FORMAT(f, s, a) __attribute__((format(f, s, a)))
#else
#define ATTRIBUTE_FORMAT(f, s, a)
#endif

void debug_printf(const char *, int, const char *, const char *, ...)
  ATTRIBUTE_FORMAT(printf, 4, 5);

#endif /* LOGGING_H */
