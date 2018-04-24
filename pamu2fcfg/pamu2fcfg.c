/*
 * Copyright (C) 2014-2018 Yubico AB - See COPYING
 */

#include <u2f-server.h>
#include <u2f-host.h>

#define BUFSIZE 1024
#define PAM_PREFIX "pam://"
#define TIMEOUT 15
#define FREQUENCY 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include "cmdline.h"

int main(int argc, char *argv[]) {
  int exit_code = EXIT_FAILURE;
  struct gengetopt_args_info args_info;
  char buf[BUFSIZE];
  char *p;
  char *response;
  u2fs_ctx_t *ctx;
  u2fs_reg_res_t *reg_result;
  u2fs_rc s_rc;
  u2fh_rc h_rc;
  char *origin = NULL;
  char *appid = NULL;
  char *user = NULL;
  struct passwd *passwd;
  const char *kh = NULL;
  const char *pk = NULL;
  u2fh_devs *devs = NULL;
  unsigned i;
  unsigned max_index = 0;

  if (cmdline_parser(argc, argv, &args_info) != 0)
    exit(EXIT_FAILURE);

  if (args_info.help_given) {
    cmdline_parser_print_help();
    printf("\nReport bugs at <https://github.com/Yubico/pam-u2f>.\n");
    exit(EXIT_SUCCESS);
  }

  s_rc = u2fs_global_init(args_info.debug_flag ? U2FS_DEBUG : 0);
  if (s_rc != U2FS_OK) {
    fprintf(stderr, "error: u2fs_global_init (%d): %s\n", s_rc,
            u2fs_strerror(s_rc));
    exit(EXIT_FAILURE);
  }

  s_rc = u2fs_init(&ctx);
  if (s_rc != U2FS_OK) {
    fprintf(stderr, "error: u2fs_init (%d): %s\n", s_rc, u2fs_strerror(s_rc));
    exit(EXIT_FAILURE);
  }

  if (args_info.origin_given)
    origin = args_info.origin_arg;
  else {
    if (!strcpy(buf, PAM_PREFIX)) {
      fprintf(stderr, "strcpy failed\n");
      exit(EXIT_FAILURE);
    }
    if (gethostname(buf + strlen(PAM_PREFIX), BUFSIZE - strlen(PAM_PREFIX)) ==
        -1) {
      perror("gethostname");
      exit(EXIT_FAILURE);
    }
    origin = buf;
  }

  if (args_info.verbose_given)
    fprintf(stderr, "Setting origin to %s\n", origin);

  s_rc = u2fs_set_origin(ctx, origin);
  if (s_rc != U2FS_OK) {
    fprintf(stderr, "error: u2fs_set_origin (%d): %s\n", s_rc,
            u2fs_strerror(s_rc));
    exit(EXIT_FAILURE);
  }

  if (args_info.appid_given)
    appid = args_info.appid_arg;
  else {
    appid = origin;
  }

  if (args_info.verbose_given)
    fprintf(stderr, "Setting appid to %s\n", appid);

  s_rc = u2fs_set_appid(ctx, appid);
  if (s_rc != U2FS_OK) {
    fprintf(stderr, "error: u2fs_set_appid (%d): %s\n", s_rc,
            u2fs_strerror(s_rc));
    exit(EXIT_FAILURE);
  }

  if (args_info.username_given)
    user = args_info.username_arg;
  else {
    passwd = getpwuid(getuid());
    if (passwd == NULL) {
      perror("getpwuid");
      exit(EXIT_FAILURE);
    }
    user = passwd->pw_name;
  }

  if (u2fh_global_init(args_info.debug_flag ? U2FH_DEBUG : 0) != U2FH_OK ||
      u2fh_devs_init(&devs) != U2FH_OK) {
    fprintf(stderr, "Unable to initialize libu2f-host\n");
    exit(EXIT_FAILURE);
  }

  h_rc = u2fh_devs_discover(devs, &max_index);
  if (h_rc != U2FH_OK && h_rc != U2FH_NO_U2F_DEVICE) {
    fprintf(stderr, "Unable to discover device(s), %s (%d)\n",
            u2fh_strerror(h_rc), h_rc);
    exit(EXIT_FAILURE);
  }

  if (h_rc == U2FH_NO_U2F_DEVICE) {
    for (i = 0; i < TIMEOUT; i += FREQUENCY) {
      fprintf(stderr, "\rNo U2F device available, please insert one now, you "
                      "have %2d seconds",
              TIMEOUT - i);
      fflush(stderr);
      sleep(FREQUENCY);

      h_rc = u2fh_devs_discover(devs, &max_index);
      if (h_rc == U2FH_OK) {
        fprintf(stderr, "\nDevice found!\n");
        break;
      }

      if (h_rc != U2FH_NO_U2F_DEVICE) {
        fprintf(stderr, "\nUnable to discover device(s), %s (%d)",
                u2fh_strerror(h_rc), h_rc);
        exit(EXIT_FAILURE);
      }
    }
  }

  if (h_rc != U2FH_OK) {
    fprintf(stderr, "\rNo device found. Aborting.                              "
                    "           \n");
    exit(EXIT_FAILURE);
  }

  s_rc = u2fs_registration_challenge(ctx, &p);
  if (s_rc != U2FS_OK) {
    fprintf(stderr, "Unable to generate registration challenge, %s (%d)\n",
            u2fs_strerror(s_rc), s_rc);
    exit(EXIT_FAILURE);
  }

  h_rc = u2fh_register(devs, p, origin, &response, U2FH_REQUEST_USER_PRESENCE);
  if (h_rc != U2FH_OK) {
    fprintf(stderr, "Unable to generate registration challenge, %s (%d)\n",
            u2fh_strerror(h_rc), h_rc);
    exit(EXIT_FAILURE);
  }

  s_rc = u2fs_registration_verify(ctx, response, &reg_result);
  if (s_rc != U2FS_OK) {
    fprintf(stderr, "error: (%d) %s\n", s_rc, u2fs_strerror(s_rc));
    exit(EXIT_FAILURE);
  }

  kh = u2fs_get_registration_keyHandle(reg_result);
  if (!kh) {
    fprintf(stderr, "Unable to extract keyHandle: (%d) %s\n", s_rc,
            u2fs_strerror(s_rc));
    exit(EXIT_FAILURE);
  }

  pk = u2fs_get_registration_publicKey(reg_result);
  if (!pk) {
    fprintf(stderr, "Unable to extract public key: (%d) %s\n", s_rc,
            u2fs_strerror(s_rc));
    exit(EXIT_FAILURE);
  }

  if (!args_info.nouser_given)
    printf("%s", user);

  printf(":%s,", kh);
  for (i = 0; i < U2FS_PUBLIC_KEY_LEN; i++) {
    printf("%02x", pk[i] & 0xFF);
  }

  exit_code = EXIT_SUCCESS;

  u2fs_done(ctx);
  u2fs_global_done();
  exit(exit_code);
}
