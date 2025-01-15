/* Copyright (C) 2021-2024 Yubico AB - See COPYING */
#undef NDEBUG

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#include <security/pam_appl.h>

#include "cfg.h"

static char *generate_template(void) {
  // Generate a conf= argument
  //
  // The function returns a string which is:
  // - suitable as argv item for pam_u2f
  // - suitable as template argument for mkstemp
  // - optionally referring to the absolute path of the temporary file.

  char *template;
  char cwd[PATH_MAX];
  int err;

  err = !getcwd(cwd, sizeof(cwd));
  assert(!err);

  err = asprintf(&template, "conf=%.*s/test_config_XXXXXX", (int) sizeof(cwd),
                 cwd) == -1;
  assert(!err);

  return template;
}

struct conf_file {
  char *arg;
  const char *path;
  FILE *out;
};

static void conf_file_init(struct conf_file *cf, const char *template) {
  int fd;
  char *path;

  memset(cf, 0, sizeof *cf);

  if (template) {
    cf->arg = strdup(template);
    assert(cf->arg);
  } else
    cf->arg = generate_template();

  path = cf->arg + strlen("conf=");
  fd = mkstemp(path);
  assert(fd != -1);

  cf->path = path;
  cf->out = fdopen(fd, "w");
  assert(cf->out);
}

static void conf_file_clear(struct conf_file *cf) {
  unlink(cf->path);
  fclose(cf->out);
  free(cf->arg);
}

static void config_different_str(FILE *conf_out, const char *key,
                                 const char *default_value) {
  // Adding '!' to make it different.
  fprintf(conf_out, "%s=%s!\n", key, default_value ? default_value : "");
}

static void config_different_bool(FILE *conf_out, const char *key,
                                  int default_value) {
  if (!default_value)
    fprintf(conf_out, "%s\n", key);
}

static void config_different_treestate(FILE *conf_out, const char *key,
                                       int default_value) {
  int new_value;

  assert(default_value >= -1 && default_value <= 1);

  // -1 =>  0
  //  0 =>  1
  //  1 => -1
  new_value = ((default_value + 2) % 3) - 1;

  if (new_value >= 0)
    fprintf(conf_out, "%s=%d\n", key, new_value);
}

static void config_flip_all(const struct conf_file *cf, const cfg_t *cfg) {
  // Loads hard-wired defaults, and dumps
  // into conf_fd a config file that changes all of them.

  FILE *conf_out = cf->out;

  config_different_bool(conf_out, "alwaysok", cfg->alwaysok);
  config_different_bool(conf_out, "cue", cfg->cue);
  config_different_bool(conf_out, "debug", cfg->debug);
  config_different_bool(conf_out, "expand", cfg->expand);
  config_different_bool(conf_out, "interactive", cfg->interactive);
  config_different_bool(conf_out, "manual", cfg->manual);
  config_different_bool(conf_out, "nodetect", cfg->nodetect);
  config_different_bool(conf_out, "nouserok", cfg->nouserok);
  config_different_bool(conf_out, "openasuser", cfg->openasuser);
  config_different_bool(conf_out, "sshformat", cfg->sshformat);

  config_different_str(conf_out, "appid", cfg->appid);
  config_different_str(conf_out, "authfile", cfg->auth_file);
  config_different_str(conf_out, "authpending_file", cfg->authpending_file);
  config_different_str(conf_out, "cue_prompt", cfg->cue_prompt);
  config_different_str(conf_out, "origin", cfg->origin);
  config_different_str(conf_out, "prompt", cfg->prompt);

  config_different_treestate(conf_out, "pinverification", cfg->pinverification);
  config_different_treestate(conf_out, "userpresence", cfg->userpresence);
  config_different_treestate(conf_out, "userverification",
                             cfg->userverification);

  fprintf(conf_out, "max_devices=%d\n", cfg->max_devs + 1);

  fflush(conf_out);
}

static int str_opt_cmp(const char *s1, const char *s2) {
  if ((!s1) != (!s2))
    return s1 ? -1 : 1;

  if (!s1)
    return 0;

  return strcmp(s1, s2);
}

static void test_regular(void) {
  // Ensure that all configuration options are loaded into the configuration:

  const char *argv[] = {NULL,
                        "debug", // So we have a log file for the test
                        "prompt=hi"};

  struct conf_file cf;
  int r;
  cfg_t cfg, cfg_defaults;

  conf_file_init(&cf, NULL);
  argv[0] = cf.arg;

  // 1. Load the default
  r = cfg_init(&cfg_defaults, 0, 1, argv);
  assert(r == PAM_SUCCESS);

  // 2. Write the configuration file, changing every field.
  config_flip_all(&cf, &cfg_defaults);

  // 3. Load from the file
  r = cfg_init(&cfg, 0, sizeof(argv) / sizeof(*argv), argv);
  assert(r == PAM_SUCCESS);
  conf_file_clear(&cf);

  // 4. Assert that every field is different from the default.
  assert(cfg.max_devs != cfg_defaults.max_devs);
  assert(cfg.manual != cfg_defaults.manual);
  assert(cfg.debug != cfg_defaults.debug);
  assert(cfg.nouserok != cfg_defaults.nouserok);
  assert(cfg.openasuser != cfg_defaults.openasuser);
  assert(cfg.alwaysok != cfg_defaults.alwaysok);
  assert(cfg.interactive != cfg_defaults.interactive);
  assert(cfg.cue != cfg_defaults.cue);
  assert(cfg.nodetect != cfg_defaults.nodetect);
  assert(cfg.userpresence != cfg_defaults.userpresence);
  assert(cfg.userverification != cfg_defaults.userverification);
  assert(cfg.pinverification != cfg_defaults.pinverification);
  assert(cfg.sshformat != cfg_defaults.sshformat);
  assert(cfg.expand != cfg_defaults.expand);

  assert(str_opt_cmp(cfg.auth_file, cfg_defaults.auth_file));
  assert(str_opt_cmp(cfg.authpending_file, cfg_defaults.authpending_file));
  assert(str_opt_cmp(cfg.origin, cfg_defaults.origin));
  assert(str_opt_cmp(cfg.appid, cfg_defaults.appid));
  assert(str_opt_cmp(cfg.prompt, cfg_defaults.prompt));
  assert(str_opt_cmp(cfg.cue_prompt, cfg_defaults.cue_prompt));

  cfg_free(&cfg_defaults);
  cfg_free(&cfg);
}

static void test_config_abspath(void) {
  /* Ensuring that the library rejects the conf= argument
   * unless it points to an absolute path.
   */

  struct conf_file cf;
  const char *argv[] = {
    NULL,    // replaced with config_arg_{...}
    "debug", // So we have a log file for the test
  };
  int r;
  cfg_t cfg;

  // 1. Generate a valid configuration and pass it around
  //    as relative path.  Assert failure.
  conf_file_init(&cf, "conf=test_config_XXXXXX");
  fputs("alwaysok\n"
        "prompt=hello",
        cf.out);
  r = fflush(cf.out);
  assert(r == 0);

  argv[0] = cf.arg;
  r = cfg_init(&cfg, 0, sizeof(argv) / sizeof(*argv), argv);
  assert(r == PAM_SERVICE_ERR);
  conf_file_clear(&cf);

  // 2. Generate a same configuration and pass it around
  //    as absolute path.  Assert success.
  conf_file_init(&cf, NULL);
  fputs("alwaysok\n"
        "prompt=hello",
        cf.out);
  r = fflush(cf.out);
  assert(r == 0);

  argv[0] = cf.arg;
  r = cfg_init(&cfg, 0, sizeof(argv) / sizeof(*argv), argv);
  assert(r == PAM_SUCCESS);

  assert(strcmp(cfg.prompt, "hello") == 0);
  conf_file_clear(&cf);

  cfg_free(&cfg);
}

static void test_last_config_wins(void) {
  // If conf= is used multiple times, only
  // the last one is honored.

  const char *argv[3] = {NULL, NULL, "debug"};
  struct conf_file cf_1, cf_2;
  int r;
  cfg_t cfg;

  conf_file_init(&cf_1, NULL);
  conf_file_init(&cf_2, NULL);

  fputs("max_devices=10\n", cf_1.out);
  fflush(cf_1.out);
  fputs("max_devices=12\n", cf_2.out);
  fflush(cf_2.out);

  argv[0] = cf_1.arg;
  argv[1] = cf_2.arg;
  r = cfg_init(&cfg, 0, sizeof(argv) / sizeof(*argv), argv);
  assert(r == PAM_SUCCESS);
  assert(cfg.max_devs == 12);
  cfg_free(&cfg);

  argv[0] = cf_2.arg;
  argv[1] = cf_1.arg;
  r = cfg_init(&cfg, 0, sizeof(argv) / sizeof(*argv), argv);
  assert(r == PAM_SUCCESS);
  assert(cfg.max_devs == 10);
  cfg_free(&cfg);

  conf_file_clear(&cf_1);
  conf_file_clear(&cf_2);
}

static void test_file_corner_cases(void) {
  // Testng config file corner cases.

  const char *argv[] = {NULL, "debug"};
  struct conf_file cf;
  int r;
  cfg_t cfg;
  char buffer[CFG_MAX_FILE_SIZE];

  conf_file_init(&cf, NULL);
  argv[0] = cf.arg;

  // 1. Empty file -> Success
  r = cfg_init(&cfg, 0, sizeof(argv) / sizeof(*argv), argv);
  assert(r == PAM_SUCCESS);
  cfg_free(&cfg);

  // 2. File size within limit -> Success
  memset(buffer, ' ', sizeof(buffer));
  memcpy(buffer, "manual\n", strlen("manual\n"));
  r = fwrite(buffer, sizeof(buffer), 1, cf.out) != 1;
  assert(!r);
  r = fflush(cf.out);
  assert(r == 0);
  r = cfg_init(&cfg, 0, sizeof(argv) / sizeof(*argv), argv);
  assert(r == PAM_SUCCESS);
  cfg_free(&cfg);

  // 3. File size beyond limit -> Failure
  r = fwrite("manual\n", strlen("manual\n"), 1, cf.out) != 1;
  assert(!r);
  r = fflush(cf.out);
  assert(r == 0);
  r = cfg_init(&cfg, 0, sizeof(argv) / sizeof(*argv), argv);
  assert(r == PAM_SERVICE_ERR);

  // 4. Missing file -> Failure
  argv[0] = "conf=/not/the/droids/you/are/looking/for";
  r = cfg_init(&cfg, 0, sizeof(argv) / sizeof(*argv), argv);
  assert(r == PAM_SERVICE_ERR);

  conf_file_clear(&cf);
}

static void test_file_parser(void) {
  cfg_t cfg_defaults, cfg;
  const char *argv[] = {
    NULL, "debug",
    "cu", // not 'cue'
  };
  struct conf_file cf;
  int r;

  conf_file_init(&cf, NULL);
  argv[0] = cf.arg;

  r = cfg_init(&cfg_defaults, 0, 1, argv);
  assert(r == PAM_SUCCESS);

  // Defaults are unlikely to change, but if they do
  // the test might be invalidated.
  assert(!cfg_defaults.alwaysok);
  assert(!cfg_defaults.prompt);
  assert(!cfg_defaults.cue_prompt);
  assert(!cfg_defaults.auth_file);
  assert(!cfg_defaults.interactive);
  assert(!cfg_defaults.cue);
  assert(!cfg_defaults.origin);
  assert(!cfg_defaults.appid);
  assert(!cfg_defaults.appid);
  assert(!cfg_defaults.authpending_file);

  fputs("   \n", cf.out);
  fputs("  # interactive \n", cf.out);
  fputs(" alwaysok # I really mean it.\n", cf.out);
  fputs("prompt =  C:/> # DOS like a boss.\n", cf.out);
  fputs("cue_prompt = =C:/ > # DOS in space.\n", cf.out);
  fputs("authfile = /dev/null \n", cf.out);
  fputs("interactive \n", cf.out);
  fputs("cu # Not 'cue'\n", cf.out);
  fputs("cu\n", cf.out);
  fputs("origin unknown\n", cf.out);
  fputs("appid= something\n", cf.out);
  fputs("authpending_file =else\n", cf.out);
  fflush(cf.out);

  r = cfg_init(&cfg, 0, sizeof(argv) / sizeof(*argv), argv);
  assert(r == PAM_SUCCESS);

  assert(cfg.alwaysok);
  assert(strcmp(cfg.prompt, "C:/>") == 0);
  assert(strcmp(cfg.cue_prompt, "=C:/ >") == 0);
  assert(strcmp(cfg.auth_file, "/dev/null") == 0);
  assert(cfg.interactive);
  assert(!cfg.cue);
  assert(!cfg.origin);
  assert(strcmp(cfg.appid, "something") == 0);
  assert(strcmp(cfg.authpending_file, "else") == 0);

  cfg_free(&cfg_defaults);
  cfg_free(&cfg);
  conf_file_clear(&cf);
}

int main(int argc, char **argv) {
  (void) argc, (void) argv;

  test_regular();
  test_config_abspath();
  test_last_config_wins();
  test_file_corner_cases();
  test_file_parser();
}
