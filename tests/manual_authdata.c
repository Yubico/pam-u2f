/*
 *  Copyright (C) 2026 Yubico AB - See COPYING
 *
 *  Manual mode hands the user's pasted authenticator data to libfido2.
 *  unwrap_cbor_bytestring() must accept exactly the byte-string encodings
 *  fido2-assert(1) emits and reject everything else, so that the bytes
 *  never reach cbor_load() (PJK/libcbor#418).
 */

#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cbor.h>
#include <fido.h>

#include "../util.h"

static const unsigned char payload[37] = {
  0x49, 0x96, 0x0d, 0xe5, 0x88, 0x0e, 0x8c, 0x68, 0x74, 0x34, 0x17, 0x0f,
  0x64, 0x76, 0x60, 0x5b, 0x8f, 0xe4, 0xae, 0xb9, 0xa2, 0x86, 0x32, 0xc7,
  0x99, 0x5c, 0xf3, 0xba, 0x83, 0x1d, 0x97, 0x63, 0x01, 0x00, 0x00, 0x00,
  0x2a,
};

static void accept(const unsigned char *hdr, size_t hdr_len,
                   const unsigned char *data, size_t data_len) {
  unsigned char buf[4096];
  const unsigned char *out = NULL;
  size_t out_len = 0;

  assert(hdr_len + data_len <= sizeof(buf));
  memcpy(buf, hdr, hdr_len);
  memcpy(buf + hdr_len, data, data_len);
  assert(unwrap_cbor_bytestring(buf, hdr_len + data_len, &out, &out_len) == 1);
  assert(out == buf + hdr_len);
  assert(out_len == data_len);
  assert(memcmp(out, data, data_len) == 0);
}

static void reject(const unsigned char *in, size_t in_len) {
  const unsigned char *out = (const unsigned char *) 0x1;
  size_t out_len = 1;

  assert(unwrap_cbor_bytestring(in, in_len, &out, &out_len) == 0);
}

static void test_accepts_fido2_assert_encodings(void) {
  /* one-byte header, length in the initial byte (0..23) */
  const unsigned char h1[] = {0x40 + 23};
  /* two-byte header: what fido2-assert emits for 37-byte authenticator
   * data, the smallest valid size */
  const unsigned char h2[] = {0x58, 37};
  /* three-byte header, 300 bytes: authenticator data with extensions */
  const unsigned char h3[] = {0x59, 0x01, 0x2c};
  /* five- and nine-byte headers are legal encodings of the same length */
  const unsigned char h5[] = {0x5a, 0x00, 0x00, 0x00, 37};
  const unsigned char h9[] = {0x5b, 0, 0, 0, 0, 0, 0, 0, 37};
  const unsigned char empty[] = {0x40};
  unsigned char big[300];

  memset(big, 0xa5, sizeof(big));
  accept(h1, sizeof(h1), payload, 23);
  accept(h2, sizeof(h2), payload, sizeof(payload));
  accept(h3, sizeof(h3), big, sizeof(big));
  accept(h5, sizeof(h5), payload, sizeof(payload));
  accept(h9, sizeof(h9), payload, sizeof(payload));
  accept(empty, sizeof(empty), payload, 0);
}

static void test_rejects_everything_else(void) {
  /* the libcbor#418 input: an array header, not a byte string */
  const unsigned char array[] = {0x9a, 0x11, 0x27, 0x00, 0x00};
  /* a map header */
  const unsigned char map[] = {0xba, 0x10, 0x00, 0x00, 0x00};
  /* a text string of the right length is still the wrong type */
  const unsigned char text[] = {0x61, 'x'};
  /* indefinite-length byte string */
  const unsigned char indef[] = {0x5f, 0x41, 0x00, 0xff};
  /* reserved additional information values */
  const unsigned char res28[] = {0x5c, 0x00};
  const unsigned char res30[] = {0x5e, 0x00};
  /* declared length longer than the input */
  const unsigned char longer[] = {0x58, 38, 0x00};
  const unsigned char huge[] = {0x5b, 0xff, 0xff, 0xff, 0xff,
                                0xff, 0xff, 0xff, 0xff};
  /* declared length shorter than the input: trailing bytes */
  const unsigned char shorter[] = {0x41, 0x00, 0x00};
  /* truncated multi-byte headers */
  const unsigned char trunc2[] = {0x58};
  const unsigned char trunc9[] = {0x5b, 0, 0, 0, 0};
  const unsigned char *out = NULL;
  size_t out_len = 0;

  reject(array, sizeof(array));
  reject(map, sizeof(map));
  reject(text, sizeof(text));
  reject(indef, sizeof(indef));
  reject(res28, sizeof(res28));
  reject(res30, sizeof(res30));
  reject(longer, sizeof(longer));
  reject(huge, sizeof(huge));
  reject(shorter, sizeof(shorter));
  reject(trunc2, sizeof(trunc2));
  reject(trunc9, sizeof(trunc9));
  reject(NULL, 0);
  reject(array, 0);
  (void) out;
  (void) out_len;
}

/* libcbor must not be asked for memory on the manual path. Install a
 * guard allocator and run the unwrapped payload through the libfido2
 * call manual_get_assert() uses; then show the call it replaced would
 * have requested memory for the libcbor#418 input. */
static size_t biggest;
static void *guard_malloc(size_t n) {
  if (n > biggest)
    biggest = n;
  return n > 64 * 1024 ? NULL : malloc(n);
}
static void *guard_realloc(void *p, size_t n) {
  if (n > biggest)
    biggest = n;
  return n > 64 * 1024 ? NULL : realloc(p, n);
}

static void test_raw_setter_allocates_nothing_large(void) {
  const unsigned char array[] = {0x9a, 0x11, 0x27, 0x00, 0x00};
  fido_assert_t *assert_ = NULL;
  const unsigned char *out = NULL;
  size_t out_len = 0;
  unsigned char wrapped[2 + sizeof(payload)] = {0x58, sizeof(payload)};

  memcpy(wrapped + 2, payload, sizeof(payload));
  cbor_set_allocs(guard_malloc, guard_realloc, free);
  fido_init(0);

  assert_ = fido_assert_new();
  assert(assert_ != NULL);
  assert(fido_assert_set_count(assert_, 1) == FIDO_OK);

  /* the new path: valid pasted data, nothing large requested */
  biggest = 0;
  assert(unwrap_cbor_bytestring(wrapped, sizeof(wrapped), &out, &out_len));
  assert(fido_assert_set_authdata_raw(assert_, 0, out, out_len) == FIDO_OK);
  assert(biggest <= 4096);

  /* the old path on the libcbor#418 input: libfido2 asks libcbor for
   * memory proportional to the declared count, which the guard refuses */
  biggest = 0;
  assert(fido_assert_set_authdata(assert_, 0, array, sizeof(array)) !=
         FIDO_OK);
  assert(biggest > 64 * 1024);

  fido_assert_free(&assert_);
  cbor_set_allocs(malloc, realloc, free);
}

int main(void) {
  test_accepts_fido2_assert_encodings();
  test_rejects_everything_else();
  test_raw_setter_allocates_nothing_large();
  return EXIT_SUCCESS;
}
