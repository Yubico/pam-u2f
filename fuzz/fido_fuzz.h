/* Copyright (C) 2025 Yubico AB - See COPYING */
#ifndef FIDO_FUZZ_H
#define FIDO_FUZZ_H

#include <stdint.h>

/* The following symbols are part of libfido2's fuzzing instrumentation.
 * The linked libfido2 library must be built with -DFUZZ=1
 */

extern int prng_up;
void prng_init(unsigned long);
uint32_t uniform_random(uint32_t);

#endif /* FIDO_FUZZ_H */
