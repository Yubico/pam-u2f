/* Copyright (C) 2026 Yubico AB - See COPYING */

/* Generate a seed corpus entry for fuzz_auth that drives
 * do_authentication() down the failure path that logs the
 * authenticator's public key via AUDIT_LOG(), i.e.
 * "Failed FIDO authentication with publicKey %s (idx %u): %s".
 *
 * This is achieved by making the (mocked) authenticator return
 * CTAP2_ERR_PIN_INVALID for the final fido_dev_get_assert() call, so
 * that do_authentication() falls through to the AUDIT_LOG() call with
 * a fido_failure_reason()-recognized error.
 *
 * Build and run from the fuzz/ directory:
 *   cc -I.. -o make_seed_auth make_seed_auth.c pack.c
 *   ./make_seed_auth seed/auth_pin_invalid
 *
 * Then merge the new seed into the corpus with:
 *   ./fuzz_auth corpus seed -merge=1
 *
 * The SEED value below was found by brute force: libfido2's fuzzing
 * PRNG (prng_init()/uniform_random()) deterministically derives the
 * per-device HID report size from it, and only a report size of 64
 * bytes (CTAP_MAX_REPORT_LEN) matches the pre-baked, 64-byte-aligned
 * CTAPHID frames below. If libfido2's PRNG, or the sequence of calls
 * pam-u2f makes into it, ever changes, a new seed satisfying that
 * constraint will need to be found.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fuzz/fuzz.h"
#include "fuzz/wiredata.h"
#include "fuzz/authfile.h"

#define SEED 168

static const char dummy_authfile[] = AUTHFILE_NEW;
static const char dummy_conf[] = "pinverification=0;userverification=0;";

/* INIT opens the device; the first CBOR_INFO/ASSERT_DISCOVER pair lets
 * get_authenticators() recognize the device as FIDO2 and pick the
 * matching credential; the second CBOR_INFO is consumed by
 * get_device_opts() (fido_dev_get_cbor_info()) before
 * do_authentication() issues the final getAssertion, whose response
 * (ASSERT_AUTHENTICATE) is patched below to report PIN_INVALID. */
static unsigned char dummy_wiredata[] = {
  WIREDATA_CTAP_INIT,
  WIREDATA_CTAP_CBOR_INFO,
  WIREDATA_CTAP_CBOR_ASSERT_DISCOVER,
  WIREDATA_CTAP_CBOR_INFO,
  WIREDATA_CTAP_CBOR_ASSERT_AUTHENTICATE,
};

struct param {
  uint32_t seed;
  char user[MAXSTR];
  char conf[MAXSTR];
  char conv[MAXSTR];
  struct blob authfile;
  struct blob wiredata;
  struct blob conf_file;
};

static int set_blob(struct blob *blob, const void *data, size_t len) {
  if (len > MAXBLOB)
    return 0;
  memcpy(blob->body, data, len);
  blob->len = len;
  return 1;
}

static int set_string(char *dst, const char *src, size_t size) {
  int n = snprintf(dst, size, "%s", src);
  if (n < 0 || (size_t) n >= size)
    return 0;
  return 1;
}

static size_t pack(uint8_t *data, size_t len, const struct param *p) {
  size_t ilen = len;

  if (pack_u32(&data, &len, p->seed) != 1 ||
      pack_string(&data, &len, p->user) != 1 ||
      pack_string(&data, &len, p->conf) != 1 ||
      pack_string(&data, &len, p->conv) != 1 ||
      pack_blob(&data, &len, &p->authfile) != 1 ||
      pack_blob(&data, &len, &p->wiredata) != 1 ||
      pack_blob(&data, &len, &p->conf_file) != 1) {
    return 0;
  }

  return ilen - len;
}

int main(int argc, char **argv) {
  struct param dummy;
  uint8_t out[64 * 1024];
  size_t r;
  FILE *f;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <outfile>\n", argv[0]);
    return 1;
  }

  /* Patch the CTAP2 status byte of the getAssertion response from
   * CTAP2_OK (0x00) to CTAP2_ERR_PIN_INVALID (0x31). */
  dummy_wiredata[sizeof(dummy_wiredata) - 256 + 7] = 0x31;

  memset(&dummy, 0, sizeof(dummy));
  if (!set_string(dummy.user, "user", MAXSTR) ||
      !set_string(dummy.conf, dummy_conf, MAXSTR) ||
      !set_string(dummy.conv, "", MAXSTR) ||
      !set_blob(&dummy.authfile, dummy_authfile, sizeof(dummy_authfile)) ||
      !set_blob(&dummy.wiredata, dummy_wiredata, sizeof(dummy_wiredata)) ||
      !set_blob(&dummy.conf_file, "", 0)) {
    fprintf(stderr, "failed to prepare seed\n");
    return 1;
  }
  dummy.seed = SEED;

  r = pack(out, sizeof(out), &dummy);
  if (r == 0) {
    fprintf(stderr, "failed to pack seed\n");
    return 1;
  }

  f = fopen(argv[1], "wb");
  if (!f || fwrite(out, 1, r, f) != r) {
    fprintf(stderr, "failed to write %s\n", argv[1]);
    return 1;
  }
  fclose(f);

  fprintf(stderr, "wrote %zu bytes to %s (seed=%u)\n", r, argv[1], SEED);
  return 0;
}
