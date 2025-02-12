/* Copyright (C) 2021-2022 Yubico AB - See COPYING */
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cfg.h"

#include "fuzz/authfile.h"
#include "fuzz/fido_fuzz.h"
#include "fuzz/fuzz.h"
#include "fuzz/wiredata.h"

#define MUTATE_SEED 0x01
#define MUTATE_PARAM 0x02
#define MUTATE_WIREDATA 0x04
#define MUTATE_ALL (MUTATE_SEED | MUTATE_PARAM | MUTATE_WIREDATA)

size_t LLVMFuzzerMutate(uint8_t *, size_t, size_t);
int LLVMFuzzerInitialize(int *, char ***);
int LLVMFuzzerTestOneInput(const uint8_t *, size_t);
size_t LLVMFuzzerCustomMutator(uint8_t *, size_t, size_t, unsigned int);

struct param {
  uint32_t seed;
  char user[MAXSTR];
  char conf[MAXSTR];
  char conv[MAXSTR];
  struct blob authfile;
  struct blob wiredata;
  struct blob conf_file;
};

struct conv_appdata {
  char *str;
  char *save;
};

/* fuzzer configuration */
static unsigned int flags = MUTATE_ALL;

/* it is far easier for the fuzzer to guess the native format */
static const char dummy_authfile[] = AUTHFILE_SSH;

/* module configuration split by fuzzer on semicolon */
static const char *dummy_conf = "sshformat;pinverification=0;manual;";

/* module configuration file */
static const char dummy_conf_file[] = "max_devices=10\n"
                                      "manual\n"
                                      "debug\n"
                                      "nouserok\n"
                                      "openasuser\n"
                                      "alwaysok\n"
                                      "interactive\n"
                                      "cue\n"
                                      "nodetect\n"
                                      "expand\n"
                                      "userpresence=0\n"
                                      "userverification=0\n"
                                      "pinverification=0\n"
                                      "authfile=/foo/bar\n"
                                      "sshformat\n"
                                      "authpending_file=/baz/quux\n"
                                      "origin=pam://lolcalhost\n"
                                      "appid=pam://lolcalhost\n"
                                      "prompt=hello\n"
                                      "cue_prompt=howdy\n"
                                      "debug_file=stdout\n";

/* conversation dummy for manual authentication */
static const char *dummy_conv =
  "94/ZgCC5htEl9SRmTRfUffKCzU/2ScRJYNFSlC5U+ik=\n"
  "ssh:\n"
  "WCXjBhDooWIRWWD+HsIj5lKcn0tugCANy15cMhyK8eKxvwEAAAAP\n"
  "MEQCIDBrIO3J/B9Y7LJca3A7t0m76WcxoATJe0NG/"
  "ZsjOMq2AiAdBGrjMalfVtzEe0rjWfnRrGhMFyRyaRuPfCHVYdIWdg==\n";

/* wiredata collected from an authenticator during authentication */
static unsigned char dummy_wiredata[] = {
  WIREDATA_CTAP_INIT,
  WIREDATA_CTAP_CBOR_INFO,
  WIREDATA_CTAP_CBOR_ASSERT_DISCOVER,
  WIREDATA_CTAP_CBOR_ASSERT_AUTHENTICATE,
};

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

static int set_blob(struct blob *blob, const void *data, size_t len) {
  if (len > MAXBLOB)
    return 0;
  memcpy(blob->body, data, len);
  blob->len = len;
  return 1;
}

static int set_string(char *dst, const char *src, size_t size) {
  int n;

  /* FIXME: use strlcpy */
  n = snprintf(dst, size, "%s", src);
  if (n < 0 || (size_t) n >= size)
    return 0;
  return 1;
}

static size_t pack_dummy(uint8_t *data, size_t len) {
  struct param dummy;
  size_t r;

  memset(&dummy, 0, sizeof(dummy));
  if (!set_string(dummy.user, "user", MAXSTR) ||
      !set_string(dummy.conf, dummy_conf, MAXSTR) ||
      !set_string(dummy.conv, dummy_conv, MAXSTR) ||
      !set_blob(&dummy.authfile, dummy_authfile, sizeof(dummy_authfile)) ||
      !set_blob(&dummy.wiredata, dummy_wiredata, sizeof(dummy_wiredata)) ||
      !set_blob(&dummy.conf_file, dummy_conf_file, sizeof(dummy_conf_file))) {
    assert(0); /* dummy couldn't be prepared */
    return 0;
  }

  r = pack(data, len, &dummy);
  assert(r != 0); /* dummy couldn't be packed */
  return r;
}

static struct param *unpack(const uint8_t *data, size_t len) {
  struct param *p = NULL;

  if ((p = calloc(1, sizeof(*p))) == NULL ||
      unpack_u32(&data, &len, &p->seed) != 1 ||
      unpack_string(&data, &len, p->user) != 1 ||
      unpack_string(&data, &len, p->conf) != 1 ||
      unpack_string(&data, &len, p->conv) != 1 ||
      unpack_blob(&data, &len, &p->authfile) != 1 ||
      unpack_blob(&data, &len, &p->wiredata) != 1 ||
      unpack_blob(&data, &len, &p->conf_file) != 1) {
    free(p);
    return NULL;
  }

  return p;
}

static void mutate_blob(struct blob *blob) {
  blob->len =
    LLVMFuzzerMutate((uint8_t *) blob->body, blob->len, sizeof(blob->body));
}

static void mutate_string(char *s, size_t maxlen) {
  size_t len;

  len = LLVMFuzzerMutate((uint8_t *) s, strlen(s), maxlen);
  s[len - 1] = '\0';
}

static void mutate(struct param *p, uint32_t seed) {
  if (flags & MUTATE_SEED)
    p->seed = seed;
  if (flags & MUTATE_PARAM) {
    mutate_string(p->user, MAXSTR);
    mutate_string(p->conf, MAXSTR);
    mutate_string(p->conv, MAXSTR);
    mutate_blob(&p->authfile);
    mutate_blob(&p->conf_file);
  }
  if (flags & MUTATE_WIREDATA)
    mutate_blob(&p->wiredata);
}

static void consume(const void *body, size_t len) {
  const volatile uint8_t *ptr = body;
  volatile uint8_t x = 0;

  while (len--)
    x ^= *ptr++;

  (void) x;
}

static int conv_cb(int num_msg, const struct pam_message **msg,
                   struct pam_response **resp_p, void *appdata_ptr) {
  struct conv_appdata *conv = appdata_ptr;
  struct pam_response *resp = NULL;
  const char *str = NULL;

  assert(num_msg == 1);
  assert(resp_p != NULL);

  consume(msg[0]->msg, strlen(msg[0]->msg));

  if ((*resp_p = resp = calloc(1, sizeof(*resp))) == NULL)
    return PAM_CONV_ERR;

  if (msg[0]->msg_style == PAM_PROMPT_ECHO_OFF ||
      msg[0]->msg_style == PAM_PROMPT_ECHO_ON) {
    str = strtok_r(conv->save ? NULL : conv->str, "\n", &conv->save);
    if (str != NULL && (resp->resp = strdup(str)) == NULL) {
      free(resp);
      return PAM_CONV_ERR;
    }
  }

  return PAM_SUCCESS;
}

static void prepare_argv(char *s, const char **argv, int *argc) {
  const char *delim = ";";
  char *token, *save;
  int size = *argc;

  *argc = 0;

  token = strtok_r(s, delim, &save);
  while (token != NULL && *argc < size) {
    argv[(*argc)++] = token;
    token = strtok_r(NULL, delim, &save);
  }
}

static void prepare_conv(struct pam_conv *conv, struct conv_appdata *data,
                         char *str) {
  data->str = str;
  conv->conv = conv_cb;
  conv->appdata_ptr = data;
}

static int prepare_authfile(const unsigned char *data, size_t len) {
  int fd;
  ssize_t r;

  if ((fd = memfd_create("u2f_keys", MFD_CLOEXEC)) == -1)
    return -1;

  if ((r = write(fd, data, len)) == -1 || (size_t) r != len ||
      lseek(fd, 0, SEEK_SET) == -1) {
    close(fd);
    return -1;
  }

  return fd;
}

static int prepare_conf_file(const struct blob *conf_file, int argc,
                             const char **argv, const char **conf_file_path) {
  int i, fd;
  ssize_t w;

  *conf_file_path = CFG_DEFAULT_PATH;
  for (i = 0; i < argc; i++) {
    const char *value;

    if (strncmp(argv[i], "conf=", strlen("conf=")))
      continue;

    value = argv[i] + strlen("conf=");
    *conf_file_path = value;
  }

  if ((fd = memfd_create("pam_u2f.conf", MFD_CLOEXEC)) == -1)
    return -1;

  w = write(fd, conf_file->body, conf_file->len);
  if (w == -1 || (size_t) w != conf_file->len)
    goto fail;

  if (lseek(fd, 0, SEEK_SET) == -1)
    goto fail;

  return fd;

fail:
  close(fd);
  return -1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  struct param *param = NULL;
  struct pam_conv conv;
  struct conv_appdata conv_data;
  const char *argv[32], *conf_file_path;
  int argc = 32;
  int authfile_fd = -1, conf_file_fd = -1;

  memset(&argv, 0, sizeof(*argv));
  memset(&conv, 0, sizeof(conv));
  memset(&conv_data, 0, sizeof(conv_data));

  if ((param = unpack(data, size)) == NULL)
    goto err;

  /* init libfido2's fuzzing prng */
  prng_init(param->seed);

  /* configure wrappers */
  prepare_conv(&conv, &conv_data, param->conv);
  set_conv(&conv);
  set_user(param->user);
  set_wiredata(param->wiredata.body, param->wiredata.len);

  if ((authfile_fd =
         prepare_authfile(param->authfile.body, param->authfile.len)) == -1)
    goto err;
  set_authfile(authfile_fd);

  prepare_argv(param->conf, &argv[0], &argc);

  if ((conf_file_fd = prepare_conf_file(&param->conf_file, argc, argv,
                                        &conf_file_path)) == -1)
    goto err;
  set_conf_file_path(conf_file_path);
  set_conf_file_fd(conf_file_fd);

  pam_sm_authenticate((void *) FUZZ_PAM_HANDLE, 0, argc, argv);

err:
  if (authfile_fd != -1)
    close(authfile_fd);
  if (conf_file_fd != -1)
    close(conf_file_fd);
  free(param);
  return 0;
}

size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t maxsize,
                               unsigned int seed) {
  size_t blob_len;
  struct param *p = NULL;

  if ((p = unpack(data, size)) == NULL)
    return pack_dummy(data, maxsize);

  mutate(p, seed);
  blob_len = pack(data, maxsize, p);
  free(p);

  return blob_len;
}

static void parse_mutate_flags(const char *opt, unsigned int *mutate_flags) {
  const char *f;

  if ((f = strchr(opt, '=')) == NULL || strlen(++f) == 0)
    errx(1, "usage: --pam-u2f-mutate=<flag>");

  if (strcmp(f, "seed") == 0)
    *mutate_flags |= MUTATE_SEED;
  else if (strcmp(f, "param") == 0)
    *mutate_flags |= MUTATE_PARAM;
  else if (strcmp(f, "wiredata") == 0)
    *mutate_flags |= MUTATE_WIREDATA;
  else
    errx(1, "--pam-u2f-mutate: unknown flag '%s'", f);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  unsigned int mutate_flags = 0;

  for (int i = 0; i < *argc; i++) {
    if (strncmp((*argv)[i], "--pam-u2f-mutate=", 17) == 0) {
      parse_mutate_flags((*argv)[i], &mutate_flags);
    }
  }

  if (mutate_flags)
    flags = mutate_flags;

  return 0;
}
