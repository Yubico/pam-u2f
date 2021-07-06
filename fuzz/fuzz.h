/* Copyright (C) 2021 Yubico AB - See COPYING */
#ifndef FUZZ_H
#define FUZZ_H

#include <stdint.h>
#include <stddef.h>
#include <security/pam_modules.h>

#define FUZZ_DEV_HANDLE 0x68696421
#define FUZZ_PAM_HANDLE 0x68696423

void set_wiredata(uint8_t *, size_t);
void set_user(const char *);
void set_conv(struct pam_conv *);
void set_authfile(int);

/* part of libfido2's fuzzing instrumentation, requires build with -DFUZZ=1 */
void prng_init(unsigned long);
uint32_t uniform_random(uint32_t);

#endif
