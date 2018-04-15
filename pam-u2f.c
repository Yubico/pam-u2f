/*
 *  Copyright (C) 2014-2015 Yubico AB - See COPYING
 */

/* Define which PAM interfaces we provide */
#define PAM_SM_AUTH

/* Include PAM headers */
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <pwd.h>
#include <string.h>
#include <errno.h>

#include "util.h"

/* If secure_getenv is not defined, define it here */
#ifndef HAVE_SECURE_GETENV
char *secure_getenv(const char *);
char *secure_getenv(const char *name) {
  (void)name;
  return NULL;
}
#endif

static void parse_cfg(int flags, int argc, const char **argv, cfg_t *cfg) {
  int i;
  memset(cfg, 0, sizeof(cfg_t));
  cfg->debug_file = stderr;

  for (i = 0; i < argc; i++) {
    if (strncmp(argv[i], "max_devices=", 12) == 0)
      sscanf(argv[i], "max_devices=%u", &cfg->max_devs);
    if (strcmp(argv[i], "manual") == 0)
      cfg->manual = 1;
    if (strcmp(argv[i], "debug") == 0)
      cfg->debug = 1;
    if (strcmp(argv[i], "nouserok") == 0)
      cfg->nouserok = 1;
    if (strcmp(argv[i], "openasuser") == 0)
      cfg->openasuser = 1;
    if (strcmp(argv[i], "alwaysok") == 0)
      cfg->alwaysok = 1;
    if (strcmp(argv[i], "interactive") == 0)
      cfg->interactive = 1;
    if (strcmp(argv[i], "cue") == 0)
      cfg->cue = 1;
    if (strncmp(argv[i], "authfile=", 9) == 0)
      cfg->auth_file = argv[i] + 9;
    if (strncmp(argv[i], "origin=", 7) == 0)
      cfg->origin = argv[i] + 7;
    if (strncmp(argv[i], "appid=", 6) == 0)
      cfg->appid = argv[i] + 6;
    if (strncmp(argv[i], "prompt=", 7) == 0)
      cfg->prompt = argv[i] + 7;
    if (strncmp (argv[i], "debug_file=", 11) == 0) {
      const char *filename = argv[i] + 11;
      if(strncmp (filename, "stdout", 6) == 0) {
        cfg->debug_file = stdout;
      }
      else if(strncmp (filename, "stderr", 6) == 0) {
        cfg->debug_file = stderr;
      }
      else if( strncmp (filename, "syslog", 6) == 0) {
        openlog("pam_u2f.so", LOG_NDELAY|LOG_PID, LOG_AUTHPRIV);
        cfg->debug_file = (FILE *)-1;
      }
      else {
        struct stat st;
        FILE *file;
        if(lstat(filename, &st) == 0) {
          if(S_ISREG(st.st_mode)) {
            file = fopen(filename, "a");
            if(file != NULL) {
              cfg->debug_file = file;
            }
          }
        }
      }
    }
  }

  if (cfg->debug) {
    D(cfg->debug_file, "called.");
    D(cfg->debug_file, "flags %d argc %d", flags, argc);
    for (i = 0; i < argc; i++) {
      D(cfg->debug_file, "argv[%d]=%s", i, argv[i]);
    }
    D(cfg->debug_file, "max_devices=%d", cfg->max_devs);
    D(cfg->debug_file, "debug=%d", cfg->debug);
    D(cfg->debug_file, "interactive=%d", cfg->interactive);
    D(cfg->debug_file, "cue=%d", cfg->cue);
    D(cfg->debug_file, "manual=%d", cfg->manual);
    D(cfg->debug_file, "nouserok=%d", cfg->nouserok);
    D(cfg->debug_file, "openasuser=%d", cfg->openasuser);
    D(cfg->debug_file, "alwaysok=%d", cfg->alwaysok);
    D(cfg->debug_file, "authfile=%s", cfg->auth_file ? cfg->auth_file : "(null)");
    D(cfg->debug_file, "origin=%s", cfg->origin ? cfg->origin : "(null)");
    D(cfg->debug_file, "appid=%s", cfg->appid ? cfg->appid : "(null)");
    D(cfg->debug_file, "prompt=%s", cfg->prompt ? cfg->prompt : "(null)");
  }
}

#ifdef DBG
#undef DBG
#endif
#define DBG(...)                                                                 \
  if (cfg->debug) {                                                            \
    D(cfg->debug_file, __VA_ARGS__);                                                           \
  }

/* PAM entry point for authentication verification */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                        const char **argv) {

  struct passwd *pw = NULL, pw_s;
  const char *user = NULL;

  cfg_t cfg_st;
  cfg_t *cfg = &cfg_st;
  char buffer[BUFSIZE];
  char *buf = NULL;
  char *authfile_dir;
  size_t authfile_dir_len;
  int pgu_ret, gpn_ret;
  int retval = PAM_IGNORE;
  device_t *devices = NULL;
  unsigned n_devices = 0;
  int openasuser;

  parse_cfg(flags, argc, argv, cfg);

  if (!cfg->origin) {
    strcpy(buffer, DEFAULT_ORIGIN_PREFIX);

    if (gethostname(buffer + strlen(DEFAULT_ORIGIN_PREFIX),
                    BUFSIZE - strlen(DEFAULT_ORIGIN_PREFIX)) == -1) {
      DBG("Unable to get host name");
      goto done;
    }
    DBG("Origin not specified, using \"%s\"", buffer);
    cfg->origin = strdup(buffer);
    if (!cfg->origin) {
      DBG("Unable to allocate memory");
      goto done;
    }
  }

  if (!cfg->appid) {
    DBG("Appid not specified, using the same value of origin (%s)",
         cfg->origin);
    cfg->appid = strdup(cfg->origin);
    if (!cfg->appid) {
      DBG("Unable to allocate memory")
      goto done;
    }
  }

  if (cfg->max_devs == 0) {
    DBG("Maximum devices number not set. Using default (%d)", MAX_DEVS);
    cfg->max_devs = MAX_DEVS;
  }

  devices = malloc(sizeof(device_t) * cfg->max_devs);
  if (!devices) {
    DBG("Unable to allocate memory");
    retval = PAM_IGNORE;
    goto done;
  }

  pgu_ret = pam_get_user(pamh, &user, NULL);
  if (pgu_ret != PAM_SUCCESS || user == NULL) {
    DBG("Unable to access user %s", user);
    retval = PAM_CONV_ERR;
    goto done;
  }

  DBG("Requesting authentication for user %s", user);

  gpn_ret = getpwnam_r(user, &pw_s, buffer, sizeof(buffer), &pw);
  if (gpn_ret != 0 || pw == NULL || pw->pw_dir == NULL ||
      pw->pw_dir[0] != '/') {
    DBG("Unable to retrieve credentials for user %s, (%s)", user,
         strerror(errno));
    retval = PAM_USER_UNKNOWN;
    goto done;
  }

  DBG("Found user %s", user);
  DBG("Home directory for %s is %s", user, pw->pw_dir);

  if (!cfg->auth_file) {
    buf = NULL;
    authfile_dir = secure_getenv(DEFAULT_AUTHFILE_DIR_VAR);
    if (!authfile_dir) {
      DBG("Variable %s is not set. Using default value ($HOME/.config/)",
           DEFAULT_AUTHFILE_DIR_VAR);
      authfile_dir_len =
        strlen(pw->pw_dir) + strlen("/.config") + strlen(DEFAULT_AUTHFILE) + 1;
      buf = malloc(sizeof(char) * (authfile_dir_len));

      if (!buf) {
        DBG("Unable to allocate memory");
        retval = PAM_IGNORE;
        goto done;
      }

      snprintf(buf, authfile_dir_len,
               "%s/.config%s", pw->pw_dir, DEFAULT_AUTHFILE);
    } else {
      DBG("Variable %s set to %s", DEFAULT_AUTHFILE_DIR_VAR, authfile_dir);
      authfile_dir_len = strlen(authfile_dir) + strlen(DEFAULT_AUTHFILE) + 1;
      buf = malloc(sizeof(char) * (authfile_dir_len));

      if (!buf) {
        DBG("Unable to allocate memory");
        retval = PAM_IGNORE;
        goto done;
      }

      snprintf(buf, authfile_dir_len,
               "%s%s", authfile_dir, DEFAULT_AUTHFILE);
    }

    DBG("Using default authentication file %s", buf);

    cfg->auth_file = buf; /* cfg takes ownership */
    buf = NULL;
  } else {
    DBG("Using authentication file %s", cfg->auth_file);
  }

  openasuser = geteuid() == 0 && cfg->openasuser;
  if (openasuser) {
    if (seteuid(pw_s.pw_uid)) {
      DBG("Unable to switch user to uid %i", pw_s.pw_uid);
      retval = PAM_IGNORE;
      goto done;
    }
    DBG("Switched to uid %i", pw_s.pw_uid);
  }
  retval = get_devices_from_authfile(cfg->auth_file, user, cfg->max_devs,
                                     cfg->debug, cfg->debug_file,
                                     devices, &n_devices);
  if (openasuser) {
    if (seteuid(0)) {
      DBG("Unable to switch back to uid 0");
      retval = PAM_IGNORE;
      goto done;
    }
    DBG("Switched back to uid 0");
  }

  if (retval != 1) {
    // for nouserok; make sure errors in get_devices_from_authfile don't
    // result in valid devices
    n_devices = 0;
  }

  if (n_devices == 0) {
    if (cfg->nouserok) {
      DBG("Found no devices but nouserok specified. Skipping authentication");
      retval = PAM_SUCCESS;
      goto done;
    } else if (retval != 1) {
      DBG("Unable to get devices from file %s", cfg->auth_file);
      retval = PAM_AUTHINFO_UNAVAIL;
      goto done;
    } else {
      DBG("Found no devices. Aborting.");
      retval = PAM_AUTHINFO_UNAVAIL;
      goto done;
    }
  }

  if (cfg->manual == 0) {
    if (cfg->interactive) {
      converse(pamh, PAM_PROMPT_ECHO_ON,
               cfg->prompt != NULL ? cfg->prompt : DEFAULT_PROMPT);
    }

    retval = do_authentication(cfg, devices, n_devices, pamh);
  } else {
    retval = do_manual_authentication(cfg, devices, n_devices, pamh);
  }

  if (retval != 1) {
    DBG("do_authentication returned %d", retval);
    retval = PAM_AUTH_ERR;
    goto done;
  }

  retval = PAM_SUCCESS;

done:
  free_devices(devices, n_devices);

  if (buf) {
    free(buf);
    buf = NULL;
  }

  if (cfg->alwaysok && retval != PAM_SUCCESS) {
    DBG("alwaysok needed (otherwise return with %d)", retval);
    retval = PAM_SUCCESS;
  }
  DBG("done. [%s]", pam_strerror(pamh, retval));

  return retval;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv) {
  (void)pamh;
  (void)flags;
  (void)argc;
  (void)argv;

  return PAM_SUCCESS;
}
