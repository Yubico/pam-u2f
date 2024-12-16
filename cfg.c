/* Copyright (C) 2021-2024 Yubico AB - See COPYING */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <security/pam_modules.h>

#include "cfg.h"
#include "debug.h"

static void cfg_load_arg(cfg_t *cfg, const char *arg) {
  if (strncmp(arg, "max_devices=", 12) == 0) {
    sscanf(arg, "max_devices=%u", &cfg->max_devs);
  } else if (strcmp(arg, "manual") == 0) {
    cfg->manual = 1;
  } else if (strcmp(arg, "debug") == 0) {
    cfg->debug = 1;
  } else if (strcmp(arg, "nouserok") == 0) {
    cfg->nouserok = 1;
  } else if (strcmp(arg, "openasuser") == 0) {
    cfg->openasuser = 1;
  } else if (strcmp(arg, "alwaysok") == 0) {
    cfg->alwaysok = 1;
  } else if (strcmp(arg, "interactive") == 0) {
    cfg->interactive = 1;
  } else if (strcmp(arg, "cue") == 0) {
    cfg->cue = 1;
  } else if (strcmp(arg, "nodetect") == 0) {
    cfg->nodetect = 1;
  } else if (strcmp(arg, "expand") == 0) {
    cfg->expand = 1;
  } else if (strncmp(arg, "userpresence=", 13) == 0) {
    sscanf(arg, "userpresence=%d", &cfg->userpresence);
  } else if (strncmp(arg, "userverification=", 17) == 0) {
    sscanf(arg, "userverification=%d", &cfg->userverification);
  } else if (strncmp(arg, "pinverification=", 16) == 0) {
    sscanf(arg, "pinverification=%d", &cfg->pinverification);
  } else if (strncmp(arg, "authfile=", 9) == 0) {
    cfg->auth_file = arg + 9;
  } else if (strcmp(arg, "sshformat") == 0) {
    cfg->sshformat = 1;
  } else if (strncmp(arg, "authpending_file=", 17) == 0) {
    cfg->authpending_file = arg + 17;
  } else if (strncmp(arg, "origin=", 7) == 0) {
    cfg->origin = arg + 7;
  } else if (strncmp(arg, "appid=", 6) == 0) {
    cfg->appid = arg + 6;
  } else if (strncmp(arg, "prompt=", 7) == 0) {
    cfg->prompt = arg + 7;
  } else if (strncmp(arg, "cue_prompt=", 11) == 0) {
    cfg->cue_prompt = arg + 11;
  } else if (strncmp(arg, "debug_file=", 11) == 0) {
    const char *filename = arg + 11;
    debug_close(cfg->debug_file);
    cfg->debug_file = debug_open(filename);
  }
}

static int slurp(int fd, size_t to_read, char **dst) {
  char *buffer, *w;

  if (to_read > CFG_MAX_FILE_SIZE)
    return PAM_SERVICE_ERR;

  buffer = malloc(to_read + 1);
  if (!buffer)
    return PAM_BUF_ERR;

  w = buffer;
  while (to_read) {
    ssize_t r;

    r = read(fd, w, to_read);
    if (r < 0) {
      free(buffer);
      return PAM_SYSTEM_ERR;
    }

    if (r == 0)
      break;

    w += r;
    to_read -= r;
  }

  *w = '\0';
  *dst = buffer;
  return PAM_SUCCESS;
}

static const char *ltrim(const char *s) {
  while (isspace((unsigned char) *s))
    s++;
  return s;
}

static int check_path_safe(const struct stat *st) {
  int r = PAM_SERVICE_ERR;

  if (!S_ISREG(st->st_mode))
    return r;

  if (st->st_mode & (S_IWGRP | S_IWOTH))
    return r;

  return PAM_SUCCESS;
}

static int cfg_load_defaults(cfg_t *cfg, const char *config_path) {
  int fd, r;
  struct stat st;
  char *buffer = NULL, *saveptr = NULL;
  const char *arg;

  // If a config file other than the default is provided,
  // the path must be absolute.
  if (config_path && *config_path != '/')
    return PAM_SERVICE_ERR;

  fd = open(config_path ? config_path : CFG_DEFAULT_PATH,
            O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW, 0);
  if (fd == -1) {

    // Only the default config file is allowed to be missing.
    if (errno == ENOENT && !config_path)
      return PAM_SUCCESS;

    return PAM_SERVICE_ERR;
  }

  if (fstat(fd, &st)) {
    r = PAM_SYSTEM_ERR;
    goto exit;
  }

  r = check_path_safe(&st);
  if (r)
    goto exit;

  if (st.st_size == 0) {
    r = PAM_SUCCESS;
    goto exit;
  }

  r = slurp(fd, st.st_size, &buffer);
  if (r)
    goto exit;

  arg = strtok_r(buffer, "\n", &saveptr);
  while (arg) {
    arg = ltrim(arg);

    if (arg[0] != '\0' && arg[0] != '#')
      cfg_load_arg(cfg, arg);

    arg = strtok_r(NULL, "\n", &saveptr);
  }

  // Transfer buffer ownership
  cfg->defaults_buffer = buffer;
  buffer = NULL;
  r = PAM_SUCCESS;

exit:
  free(buffer);
  close(fd);
  return r;
}

static void cfg_reset(cfg_t *cfg) {
  memset(cfg, 0, sizeof(cfg_t));
  cfg->debug_file = DEFAULT_DEBUG_FILE;
  cfg->userpresence = -1;
  cfg->userverification = -1;
  cfg->pinverification = -1;
}

int cfg_init(cfg_t *cfg, int flags, int argc, const char **argv) {
  int i, r;
  const char *config_path = NULL;

  cfg_reset(cfg);

  for (i = argc - 1; i >= 0; i--) {
    if (strncmp(argv[i], "conf=", strlen("conf=")) == 0) {
      config_path = argv[i] + strlen("conf=");
      break;
    }
  }

  r = cfg_load_defaults(cfg, config_path);
  if (r != PAM_SUCCESS)
    goto fail;

  for (i = 0; i < argc; i++) {
    if (strncmp(argv[i], "conf=", strlen("conf=")) == 0)
      continue;

    cfg_load_arg(cfg, argv[i]);
  }

  if (cfg->debug) {
    debug_dbg(cfg, "called.");
    debug_dbg(cfg, "flags %d argc %d", flags, argc);
    for (i = 0; i < argc; i++) {
      debug_dbg(cfg, "argv[%d]=%s", i, argv[i]);
    }
    debug_dbg(cfg, "max_devices=%d", cfg->max_devs);
    debug_dbg(cfg, "debug=%d", cfg->debug);
    debug_dbg(cfg, "interactive=%d", cfg->interactive);
    debug_dbg(cfg, "cue=%d", cfg->cue);
    debug_dbg(cfg, "nodetect=%d", cfg->nodetect);
    debug_dbg(cfg, "userpresence=%d", cfg->userpresence);
    debug_dbg(cfg, "userverification=%d", cfg->userverification);
    debug_dbg(cfg, "pinverification=%d", cfg->pinverification);
    debug_dbg(cfg, "manual=%d", cfg->manual);
    debug_dbg(cfg, "nouserok=%d", cfg->nouserok);
    debug_dbg(cfg, "openasuser=%d", cfg->openasuser);
    debug_dbg(cfg, "alwaysok=%d", cfg->alwaysok);
    debug_dbg(cfg, "sshformat=%d", cfg->sshformat);
    debug_dbg(cfg, "expand=%d", cfg->expand);
    debug_dbg(cfg, "authfile=%s", cfg->auth_file ? cfg->auth_file : "(null)");
    debug_dbg(cfg, "authpending_file=%s",
              cfg->authpending_file ? cfg->authpending_file : "(null)");
    debug_dbg(cfg, "origin=%s", cfg->origin ? cfg->origin : "(null)");
    debug_dbg(cfg, "appid=%s", cfg->appid ? cfg->appid : "(null)");
    debug_dbg(cfg, "prompt=%s", cfg->prompt ? cfg->prompt : "(null)");
  }
  return PAM_SUCCESS;

fail:
  cfg_free(cfg);
  return r;
}

void cfg_free(cfg_t *cfg) {
  debug_close(cfg->debug_file);
  free(cfg->defaults_buffer);
  cfg_reset(cfg);
}
