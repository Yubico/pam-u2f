/*
 * Copyright (C) 2020 Yubico AB - See COPYING
 */
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util.c"
#include "b64.c"

/* wrap some functions so we can let them fail some times to trigger error
 * paths. compile with -Wl,--wrap=strdup -Wl,--wrap=calloc to activate.
 * Note: idea taken from libfido2/fuzz/wrap.c
 */
extern char *__wrap_strdup(const char *);
extern char *__real_strdup(const char *);
char *__wrap_strdup(const char *s) {
  if (random() < (RAND_MAX / 100) / 4) { // fail 0.25% of the time
    errno = ENOMEM;
    return NULL;
  }

  return __real_strdup(s);
}

extern void *__wrap_calloc(size_t, size_t);
extern void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t nmemb, size_t size) {
  if (random() < (RAND_MAX / 100) / 4) { // fail 0.25% of the time
    errno = ENOMEM;
    return NULL;
  }

  return __real_calloc(nmemb, size);
}

static void cleanup(device_t *devs, unsigned int n_devs) {
  for (int i = 0; i < n_devs; i++) {
    free(devs[i].keyHandle);
    free(devs[i].publicKey);
    free(devs[i].coseType);
    free(devs[i].attributes);
    devs[i].keyHandle = NULL;
    devs[i].publicKey = NULL;
    devs[i].coseType = NULL;
    devs[i].attributes = NULL;
  }
}

#define DEV_MAX_SIZE 10

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char buf[DEVSIZE * DEV_MAX_SIZE]; /* DEVSIZE * cfg.max_size */
  device_t devs[12] = {0};
  unsigned int n_devs = 12;
  FILE *fp = NULL;
  size_t fp_len = 0;
  size_t offset = 0;
  char username[256] = {0};
  size_t username_len = 0;
  uint8_t ssh_format = 1;
  cfg_t cfg = {0};
  cfg.max_devs = DEV_MAX_SIZE;

  /* first 6 byte decides which parser we should call, if
   * we want to run with debug and also sets the initial seed
   * for random().
   */
  if (size < 6) {
    return -1;
  }
  /* do not always run with debug, only 8/255 times */
  if (data[offset++] < 9) {
    cfg.debug = 1;
  }

  /* predictable random for this seed */
  srandom(data[offset] << 24 | data[offset + 1] << 16 | data[offset + 2] << 8 |
          data[offset + 3]);
  offset += 4;

  /* choose which format parser to run, even == native, odd == ssh */
  if (data[offset++] % 2) {
    ssh_format = 0;
    /* native format, get a random username first */
    if (size < 7) {
      return -1;
    }
    username_len = data[offset++];
    if (username_len > (size - offset)) {
      username_len = (size - offset);
    }
    memcpy(username, &data[offset], username_len);
    offset += username_len;
  }

  fp_len = size - offset;
  fp = tmpfile();
  if (fp == NULL || (fwrite(&data[offset], 1, fp_len, fp)) != fp_len) {
    fprintf(stderr, "failed to create file for parser: %s\n", strerror(errno));
    if (fp != NULL) {
      fclose(fp);
    }
    return -1;
  }
  (void) fseek(fp, 0L, SEEK_SET);

  if (ssh_format) {
    parse_ssh_format(&cfg, buf, sizeof(buf), fp, size, devs, &n_devs);
  } else {
    parse_native_format(&cfg, username, buf, fp, devs, &n_devs);
  }

  cleanup(devs, n_devs);

  fclose(fp);

  return 0;
}
