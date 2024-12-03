#include <string.h>

#include "cfg.h"
#include "debug.h"

void cfg_init(cfg_t *cfg, int flags, int argc, const char **argv) {
  int i;

  memset(cfg, 0, sizeof(cfg_t));
  cfg->debug_file = DEFAULT_DEBUG_FILE;
  cfg->userpresence = -1;
  cfg->userverification = -1;
  cfg->pinverification = -1;

  for (i = 0; i < argc; i++) {
    if (strncmp(argv[i], "max_devices=", 12) == 0) {
      sscanf(argv[i], "max_devices=%u", &cfg->max_devs);
    } else if (strcmp(argv[i], "manual") == 0) {
      cfg->manual = 1;
    } else if (strcmp(argv[i], "debug") == 0) {
      cfg->debug = 1;
    } else if (strcmp(argv[i], "nouserok") == 0) {
      cfg->nouserok = 1;
    } else if (strcmp(argv[i], "openasuser") == 0) {
      cfg->openasuser = 1;
    } else if (strcmp(argv[i], "alwaysok") == 0) {
      cfg->alwaysok = 1;
    } else if (strcmp(argv[i], "interactive") == 0) {
      cfg->interactive = 1;
    } else if (strcmp(argv[i], "cue") == 0) {
      cfg->cue = 1;
    } else if (strcmp(argv[i], "nodetect") == 0) {
      cfg->nodetect = 1;
    } else if (strcmp(argv[i], "expand") == 0) {
      cfg->expand = 1;
    } else if (strncmp(argv[i], "userpresence=", 13) == 0) {
      sscanf(argv[i], "userpresence=%d", &cfg->userpresence);
    } else if (strncmp(argv[i], "userverification=", 17) == 0) {
      sscanf(argv[i], "userverification=%d", &cfg->userverification);
    } else if (strncmp(argv[i], "pinverification=", 16) == 0) {
      sscanf(argv[i], "pinverification=%d", &cfg->pinverification);
    } else if (strncmp(argv[i], "authfile=", 9) == 0) {
      cfg->auth_file = argv[i] + 9;
    } else if (strcmp(argv[i], "sshformat") == 0) {
      cfg->sshformat = 1;
    } else if (strncmp(argv[i], "authpending_file=", 17) == 0) {
      cfg->authpending_file = argv[i] + 17;
    } else if (strncmp(argv[i], "origin=", 7) == 0) {
      cfg->origin = argv[i] + 7;
    } else if (strncmp(argv[i], "appid=", 6) == 0) {
      cfg->appid = argv[i] + 6;
    } else if (strncmp(argv[i], "prompt=", 7) == 0) {
      cfg->prompt = argv[i] + 7;
    } else if (strncmp(argv[i], "cue_prompt=", 11) == 0) {
      cfg->cue_prompt = argv[i] + 11;
    } else if (strncmp(argv[i], "debug_file=", 11) == 0) {
      const char *filename = argv[i] + 11;
      debug_close(cfg->debug_file);
      cfg->debug_file = debug_open(filename);
    }
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
