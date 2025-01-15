/*
 *  Copyright (C) 2025 Yubico AB - See COPYING
 */

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

static void cfg_load_arg_debug(cfg_t *cfg, const char *arg) {
  if (strcmp(arg, "debug") == 0)
    cfg->debug = 1;
}

static void cfg_load_arg(cfg_t *cfg, const char *arg) {
  if (strncmp(arg, "max_devices=", strlen("max_devices=")) == 0) {
    sscanf(arg, "max_devices=%u", &cfg->max_devs);
  } else if (strcmp(arg, "manual") == 0) {
    cfg->manual = 1;
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
  } else if (strncmp(arg, "userpresence=", strlen("userpresence=")) == 0) {
    sscanf(arg, "userpresence=%d", &cfg->userpresence);
  } else if (strncmp(arg, "userverification=", strlen("userverification=")) ==
             0) {
    sscanf(arg, "userverification=%d", &cfg->userverification);
  } else if (strncmp(arg, "pinverification=", strlen("pinverification=")) ==
             0) {
    sscanf(arg, "pinverification=%d", &cfg->pinverification);
  } else if (strncmp(arg, "authfile=", strlen("authfile=")) == 0) {
    cfg->auth_file = arg + strlen("authfile=");
  } else if (strcmp(arg, "sshformat") == 0) {
    cfg->sshformat = 1;
  } else if (strncmp(arg, "authpending_file=", strlen("authpending_file=")) ==
             0) {
    cfg->authpending_file = arg + strlen("authpending_file=");
  } else if (strncmp(arg, "origin=", strlen("origin=")) == 0) {
    cfg->origin = arg + strlen("origin=");
  } else if (strncmp(arg, "appid=", strlen("appid=")) == 0) {
    cfg->appid = arg + strlen("appid=");
  } else if (strncmp(arg, "prompt=", strlen("prompt=")) == 0) {
    cfg->prompt = arg + strlen("prompt=");
  } else if (strncmp(arg, "cue_prompt=", strlen("cue_prompt=")) == 0) {
    cfg->cue_prompt = arg + strlen("cue_prompt=");
  } else
    cfg_load_arg_debug(cfg, arg);
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
    to_read -= (size_t) r;
  }

  *w = '\0';
  *dst = buffer;
  return PAM_SUCCESS;
}

/* Open the given path while ensuring certain security properties hold.
 *
 * On success returns PAM_SUCCESS
 * On failure returns PAM_SERVICE_ERR and sets errno to indicate the error.
 */
static int open_safely(int *outfd, size_t *outsize, const char *path) {
  int fd, r = -EINVAL;
  struct stat st;

  if (*path != '/')
    return r;

  fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW, 0);
  if (fd == -1)
    return -errno;

  if (fstat(fd, &st) != 0)
    goto fail;

#ifndef PAM_U2F_TESTING
  if (st.st_uid != 0)
    goto fail;
#endif
  if (!S_ISREG(st.st_mode) || st.st_mode & (S_IWGRP | S_IWOTH))
    goto fail;
  if (st.st_size < 0)
    goto fail;

  *outfd = fd;
  *outsize = (size_t) st.st_size;
  return 0;

fail:
  close(fd);
  return r;
}

static char *ltrim(char *s) {
  while (isspace((unsigned char) *s))
    s++;
  return s;
}

static char *rtrim(char *s) {
  size_t l;

  l = strlen(s);

  while (l > 0 && isspace((unsigned char) s[l - 1]))
    s[--l] = '\0';

  return s;
}

/*
 * Transform a line from the configuration file in an equivalent
 * module command line value. Comments are stripped.
 *
 * E.g.
 *  'foo = bar' => 'foo=bar'
 *  'baz'       => 'baz'
 *  'baz # etc' => 'baz'
 */
static const char *pack(char *s) {
  size_t n;
  char *v;

  s[strcspn(s, "#")] = '\0';
  s = ltrim(s);

  v = strchr(s, '=');
  if (!v)
    return rtrim(s);

  *v++ = '\0';
  v = ltrim(rtrim(v));

  s = rtrim(s);
  n = strlen(s);
  s[n++] = '=';

  memmove(s + n, v, strlen(v) + 1);

  return s;
}

static void cfg_load_buffer(cfg_t *cfg, char *buffer) {
  char *saveptr_out = NULL, *line;

  line = strtok_r(buffer, "\n", &saveptr_out);
  while (line) {
    char *buf;
    const char *arg;

    /* Pin the next line before messing with the buffer. */
    buf = line;
    line = strtok_r(NULL, "\n", &saveptr_out);

    arg = pack(buf);
    if (!*arg)
      continue;

    cfg_load_arg(cfg, arg);
  }
}

static int cfg_load_defaults(cfg_t *cfg, const char *config_path) {
  int fd = -1, r;
  size_t fsize = 0;
  char *buffer = NULL;

  r = open_safely(&fd, &fsize, config_path ? config_path : CFG_DEFAULT_PATH);

  /* Only the default config file is allowed to be missing. */
  if (r == -ENOENT && config_path == NULL)
    return PAM_SUCCESS;

  if (r != 0)
    return PAM_SERVICE_ERR;

  r = slurp(fd, fsize, &buffer);
  if (r)
    goto exit;

  cfg_load_buffer(cfg, buffer);
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
  cfg->userpresence = -1;
  cfg->userverification = -1;
  cfg->pinverification = -1;
}

int cfg_init(cfg_t *cfg, int flags, int argc, const char **argv) {
  int i, r;
  const char *config_path = NULL;

  (void) flags; /* prevent unused warning when unit-testing. */

  cfg_reset(cfg);

  for (i = 0; i < argc; i++) {
    if (strncmp(argv[i], "conf=", strlen("conf=")) == 0)
      config_path = argv[i] + strlen("conf=");
    else
      cfg_load_arg_debug(cfg, argv[i]);
  }

  r = cfg_load_defaults(cfg, config_path);
  if (r != PAM_SUCCESS)
    goto exit;

  for (i = 0; i < argc; i++)
    cfg_load_arg(cfg, argv[i]);

exit:
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

  if (r != PAM_SUCCESS)
    cfg_free(cfg);

  return r;
}

void cfg_free(cfg_t *cfg) {
  free(cfg->defaults_buffer);
  cfg_reset(cfg);
}
