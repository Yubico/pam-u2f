#undef NDEBUG

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "cfg.h"

#define WRITE(fd, text)                                                        \
  do {                                                                         \
    ssize_t w = write(fd, (text), sizeof(text));                               \
    assert(w == sizeof(text));                                                 \
    int e = fsync(fd);                                                         \
    assert(e == 0);                                                            \
  } while (0)

static char *abs_config_path(void) {
  char cwd[1024];
  char *template;
  int err;

  err = !getcwd(cwd, sizeof(cwd));
  assert(!err);

  err = asprintf(&template, "config=%.*s/test_config_XXXXXX", (int) sizeof(cwd),
                 cwd) == -1;
  assert(!err);

  return template;
}

static void test_inherit(void) {
  /* Testing config file inheritance: the config file provides defaults,
   * overrides from regular argv
   */

  char *config_arg;
  int fd;
  cfg_t cfg;

  config_arg = abs_config_path();

  fd = mkstemp(config_arg + strlen("config="));
  assert(fd != -1);

  WRITE(fd, "alwaysok\nprompt=hello");
  const char *argv[] = {
    config_arg, "prompt=hi",
    "debug", // So we have a log file for the test
  };
  cfg_init(&cfg, 0, sizeof(argv) / sizeof(*argv), argv);

  unlink(config_arg + strlen("config="));
  free(config_arg);
  close(fd);

  assert(cfg.alwaysok);
  assert(strcmp(cfg.prompt, "hi") == 0);

  cfg_free(&cfg);
}

static void test_config_abspath(void) {
  /* Ensuring that the configuraton file path, provided via config=
   * is absolute.
   */

  char config_arg[] = "config=test_config_XXXXXX";
  int fd;
  cfg_t cfg;

  fd = mkstemp(config_arg + strlen("config="));
  assert(fd != -1);

  /* Same test as in test_inherit() ... */
  WRITE(fd, "alwaysok\nprompt=hello");
  const char *argv[] = {
    config_arg,
    "debug", // So we have a log file for the test
  };
  cfg_init(&cfg, 0, sizeof(argv) / sizeof(*argv), argv);

  unlink(config_arg + strlen("config="));
  close(fd);

  /* ...but this time defaults are NOT set by the config file */
  assert(!cfg.alwaysok);
  assert(!cfg.prompt);
}

static void test_debug_replace(void) {
  cfg_t cfg;
  const char *argv[] = {
    "debug",
    NULL,
    NULL,
  };
  char *config_arg;
  int fd;

  // Default is stderr
  argv[0] = "debug";
  cfg_init(&cfg, 0, 1, argv);
  assert(cfg.debug_file == stderr);
  cfg_free(&cfg);

  // debug_file is honoured
  argv[1] = "debug_file=syslog";
  cfg_init(&cfg, 0, 2, argv);
  assert(cfg.debug_file == NULL);
  cfg_free(&cfg);

  // fallback to last working debug file
  argv[1] = "debug_file=/hopefully/this/path/does/not/exist/debug.txt";
  cfg_init(&cfg, 0, 2, argv);
  assert(cfg.debug_file == stderr);
  cfg_free(&cfg);

  // A valid config file
  config_arg = abs_config_path();
  fd = mkstemp(config_arg + strlen("config="));
  assert(fd != -1);
  WRITE(fd, "debug_file=stdout");

  // debug_file from config is honoured
  argv[1] = config_arg;
  cfg_init(&cfg, 0, 2, argv);
  assert(cfg.debug_file == stdout);
  cfg_free(&cfg);

  // debug_file from config can be overriden
  argv[2] = "debug_file=syslog";
  cfg_init(&cfg, 0, 3, argv);
  assert(cfg.debug_file != stdout);
  cfg_free(&cfg);

  // Valid debug_file from config is not replaced by bogus path
  argv[2] = "debug_file=/hopefully/this/path/does/not/exist/debug.txt";
  cfg_init(&cfg, 0, 3, argv);
  assert(cfg.debug_file == stdout);
  cfg_free(&cfg);

  unlink(config_arg + strlen("config="));
  free(config_arg);
  close(fd);
}

int main(int argc, char **argv) {
  (void) argc, (void) argv;

  test_inherit();
  test_config_abspath();
  test_debug_replace();
}
