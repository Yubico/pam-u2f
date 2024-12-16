/*
 * Copyright (C) 2014-2019 Yubico AB - See COPYING
 */

#ifndef CFG_H
#define CFG_H

#include <stdio.h>

#define CFG_DEFAULT_PATH (SCONFDIR "/pam_u2f.conf")
#define CFG_MAX_FILE_SIZE 4096

typedef struct {
  unsigned max_devs;
  int manual;
  int debug;
  int nouserok;
  int openasuser;
  int alwaysok;
  int interactive;
  int cue;
  int nodetect;
  int userpresence;
  int userverification;
  int pinverification;
  int sshformat;
  int expand;
  const char *auth_file;
  const char *authpending_file;
  const char *origin;
  const char *appid;
  const char *prompt;
  const char *cue_prompt;
  FILE *debug_file;
  char *defaults_buffer;
} cfg_t;

int cfg_init(cfg_t *cfg, int flags, int argc, const char **argv);

void cfg_free(cfg_t *cfg);

#endif
