#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "cfg.h"
#include "debug.h"

#define DEFAULT_CONFIG_PATH SYSCONFDIR "/security/pam_u2f.conf"

static void cfg_load_arg(cfg_t *cfg, const char *source, const char *arg) {
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
  } else {
    debug_dbg(cfg, "WARNING: ignored config \"%s\" from %s", arg, source);
  }
}

static void cfg_load_defaults(cfg_t *cfg, const char *config_path) {
  int config_path_default = 0;
  FILE *config_file;
  char *buf = NULL;
  size_t bufsiz = 0;
  ssize_t len;

  if (!config_path) {
    config_path_default = 1;
    config_path = DEFAULT_CONFIG_PATH;
  } else if (*config_path != '/') {
    debug_dbg(cfg, "WARNING: config path \"%s\": must be absolute.",
              config_path);
    config_path = DEFAULT_CONFIG_PATH;
  }

  if ((config_file = fopen(config_path, "r")) == NULL) {
    if (errno != ENOENT || !config_path_default)
      debug_dbg(cfg, "WARNING: could not parse %s: %s", config_path,
                strerror(errno));
    return;
  }

  debug_dbg(cfg, "loading defaults from %s", config_path);

  while (errno = 0, (len = getline(&buf, &bufsiz, config_file)) != -1) {
    if (len <= 1)
      continue;
    if (buf[len - 1] == '\n')
      buf[--len] = '\0';

    cfg_load_arg(cfg, config_path, buf);
  }
  if (errno)
    debug_dbg(cfg, "WARNING: could not parse %s: %s", config_path,
              strerror(errno));
  free(buf);

  if (config_file) {
    fclose(config_file);
  }
}

void cfg_init(cfg_t *cfg, int flags, int argc, const char **argv) {
  int i;
  const char *config_path = NULL;

  memset(cfg, 0, sizeof(cfg_t));
  cfg->debug_file = DEFAULT_DEBUG_FILE;
  cfg->userpresence = -1;
  cfg->userverification = -1;
  cfg->pinverification = -1;

  for (i = 0; i < argc; i++) {
    if (strcmp(argv[i], "debug") == 0) {
      cfg->debug = 1;
      continue;
    }
    if (strncmp(argv[i], "config=", 7) == 0) {
      config_path = argv[i] + 7;
      continue;
    }
    if (strncmp(argv[i], "debug_file=", 11) == 0) {
      const char *filename = argv[i] + 11;
      debug_close(cfg->debug_file);
      cfg->debug_file = debug_open(filename);
      continue;
    }
  }
  cfg_load_defaults(cfg, config_path);

  for (i = 0; i < argc; i++) {
    if (strncmp(argv[i], "config=", 7) == 0) {
      continue;
    }
    cfg_load_arg(cfg, "argv", argv[i]);
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
}

void cfg_free(cfg_t *cfg) {
  debug_close(cfg->debug_file);
  cfg->debug_file = DEFAULT_DEBUG_FILE;
}
