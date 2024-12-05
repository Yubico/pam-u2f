/* Copyright (C) 2021-2024 Yubico AB - See COPYING */
#undef NDEBUG

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <security/pam_appl.h>

#include "cfg.h"

static void write_conf(int fd, const char *text) {
  size_t len;
  int r;

  len = strlen(text);
  while (len) {
    ssize_t w;

    w = write(fd, text, len);
    assert(w >= 0);

    len -= w;
    text += w;
  }

  r = fsync(fd);
  assert(r == 0);
}

static char *generate_conf_file_arg(void) {
  // Generate a conf= argument
  //
  // The function returns a string which is:
  // - suitable as argv item for pam_u2f
  // - suitable as template argument for mkstemp
  // - referring to the absolute path of the temporary file.

  char cwd[4096];
  char *template;
  int err;

  err = !getcwd(cwd, sizeof(cwd));
  assert(!err);

  err = asprintf(&template, "conf=%.*s/test_config_XXXXXX", (int) sizeof(cwd),
                 cwd) == -1;
  assert(!err);

  return template;
}

static void test_regular(void) {
  // Testing regular behaviour:
  // - config file inheritance: the config file provides defaults,
  //   overrides from regular argv
  // - comments
  // - indentation

  char *config_arg;
  int fd, r;
  cfg_t cfg;

  config_arg = generate_conf_file_arg();

  fd = mkstemp(config_arg + strlen("conf="));
  assert(fd != -1);

  write_conf(fd,
             "max_devices=10\n"
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
             "# sshformat\n"                 // Commented -> no effect
             "  # sshformat\n"               // also commented
             " authpending_file=/baz/quux\n" // Indented -> accepted
             "origin=pam://lolcalhost\n"
             "appid=pam://lolcalhost\n"
             "prompt=hello\n"
             "cue_prompt=howdy\n"
             "debug_file=stdout\n");

  const char *argv[] = {
    config_arg, "prompt=hi",
    "debug", // So we have a log file for the test
  };

  r = cfg_init(&cfg, 0, sizeof(argv) / sizeof(*argv), argv);
  assert(r == PAM_SUCCESS);

  unlink(config_arg + strlen("conf="));
  free(config_arg);
  close(fd);

  assert(cfg.alwaysok);
  assert(strcmp(cfg.auth_file, "/foo/bar") == 0);
  assert(!cfg.sshformat); // setting is commented out
  assert(strcmp(cfg.authpending_file, "/baz/quux") == 0);
  assert(strcmp(cfg.origin, "pam://lolcalhost") == 0);
  assert(strcmp(cfg.appid, "pam://lolcalhost") == 0);
  assert(strcmp(cfg.prompt, "hi") == 0);
  assert(strcmp(cfg.cue_prompt, "howdy") == 0);
  assert(cfg.debug_file == stdout);

  cfg_free(&cfg);
}

static void test_config_abspath(void) {
  /* Ensuring that the library rejects the conf= argument
   * unless it points to an absolute path.
   */

  const char *argv[] = {
    NULL,    // replaced with config_arg_{...}
    "debug", // So we have a log file for the test
  };

  char config_arg_relative[] = "conf=test_config_XXXXXX";
  char *config_arg_absolute;
  int fd, r;
  cfg_t cfg;

  // 1. Generate a valid configuration and pass it around
  // as relative path.  Assert failure.
  fd = mkstemp(config_arg_relative + strlen("conf="));
  assert(fd != -1);
  write_conf(fd, "alwaysok\n"
                 "prompt=hello");

  argv[0] = config_arg_relative;
  r = cfg_init(&cfg, 0, sizeof(argv) / sizeof(*argv), argv);
  assert(r != PAM_SUCCESS);

  unlink(config_arg_relative + strlen("conf="));
  close(fd);

  // 2. Generate a same configuration and pass it around
  // as absolute path.  Assert success.

  config_arg_absolute = generate_conf_file_arg();

  fd = mkstemp(config_arg_absolute + strlen("conf="));
  assert(fd != -1);
  write_conf(fd, "alwaysok\n"
                 "prompt=hello");

  argv[0] = config_arg_absolute;
  r = cfg_init(&cfg, 0, sizeof(argv) / sizeof(*argv), argv);
  assert(r == PAM_SUCCESS);

  assert(strcmp(cfg.prompt, "hello") == 0);
  cfg_free(&cfg);

  unlink(config_arg_absolute + strlen("conf="));
  close(fd);
  free(config_arg_absolute);
}

static void test_last_config_wins(void) {
  // If conf= is used multiple times, only
  // the last one is honored.

  const char *argv[3] = {NULL, NULL, "debug"};
  char *config_arg1, *config_arg2;
  int fd1, fd2, r;
  cfg_t cfg;

  config_arg1 = generate_conf_file_arg();
  fd1 = mkstemp(config_arg1 + strlen("conf="));
  assert(fd1 != -1);

  config_arg2 = generate_conf_file_arg();
  fd2 = mkstemp(config_arg2 + strlen("conf="));
  assert(fd2 != -1);

  write_conf(fd1, "max_devices=10\n");
  write_conf(fd2, "max_devices=12\n");

  argv[0] = config_arg1;
  argv[1] = config_arg2;

  r = cfg_init(&cfg, 0, sizeof(argv) / sizeof(*argv), argv);
  assert(r == PAM_SUCCESS);
  assert(cfg.max_devs == 12);
  cfg_free(&cfg);

  argv[0] = config_arg2;
  argv[1] = config_arg1;
  r = cfg_init(&cfg, 0, sizeof(argv) / sizeof(*argv), argv);
  assert(r == PAM_SUCCESS);
  assert(cfg.max_devs == 10);
  cfg_free(&cfg);

  unlink(config_arg1 + strlen("conf="));
  free(config_arg1);
  close(fd1);

  unlink(config_arg2 + strlen("conf="));
  free(config_arg2);
  close(fd2);
}

static void test_corner_cases(void) {
  // Testng config file corner cases.

  const char *argv[] = {NULL, "debug"};
  char *config_arg;
  int fd, r;
  size_t size = 0;
  cfg_t cfg;
  ssize_t w;

  config_arg = generate_conf_file_arg();
  argv[0] = config_arg;

  fd = mkstemp(config_arg + strlen("conf="));
  assert(fd != -1);

  // 1. Empty file -> Success
  r = cfg_init(&cfg, 0, sizeof(argv) / sizeof(*argv), argv);
  assert(r == PAM_SUCCESS);
  cfg_free(&cfg);

  // 2. File size within limit (1KiB) -> Success
  while (size + strlen("manual\n") < CFG_MAX_FILE_SIZE) {
    w = write(fd, "manual\n", sizeof("manual\n"));
    assert(w >= 0);
    size += w;
  }
  r = cfg_init(&cfg, 0, sizeof(argv) / sizeof(*argv), argv);
  assert(r == PAM_SUCCESS);
  cfg_free(&cfg);

  // 3. File size beyond limit -> Failure
  w = write(fd, "manual\n", strlen("manual\n"));
  assert(w == strlen("manual\n"));
  r = cfg_init(&cfg, 0, sizeof(argv) / sizeof(*argv), argv);
  assert(r != PAM_SUCCESS);

  // 4. Missing file -> Failure
  unlink(config_arg + strlen("conf="));
  r = cfg_init(&cfg, 0, sizeof(argv) / sizeof(*argv), argv);
  assert(r != PAM_SUCCESS);

  free(config_arg);
  close(fd);
}

int main(int argc, char **argv) {
  (void) argc, (void) argv;

  test_regular();
  test_config_abspath();
  test_last_config_wins();
  test_corner_cases();
}
