/*
 *  Copyright (C) 2014 Yubico AB - See COPYING
 */

/* Define which PAM interfaces we provide */
#define PAM_SM_AUTH

/* Include PAM headers */
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <unistd.h>
#include <stdlib.h>
#include <pwd.h>
#include <string.h>

#include "util.h"

static void parse_cfg(int flags, int argc, const char **argv, cfg_t * cfg)
{
  int i;
  memset(cfg, 0, sizeof(cfg_t));
  for (i = 0; i < argc; i++) {
    if (strncmp(argv[i], "max_devices=", 12) == 0)
      sscanf(argv[i], "max_devices=%u", &cfg->max_devs);
    if (strcmp(argv[i], "debug") == 0)
      cfg->debug = 1;
    if (strcmp(argv[i], "alwaysok") == 0)
      cfg->alwaysok = 1;
    if (strncmp(argv[i], "authfile=", 9) == 0)
      cfg->auth_file = argv[i] + 9;
    if (strncmp(argv[i], "origin=", 7) == 0)
      cfg->origin = argv[i] + 7;
    if (strncmp(argv[i], "appid=", 6) == 0)
      cfg->appid = argv[i] + 6;
  }

  if (cfg->debug) {
    D(("called."));
    D(("flags %d argc %d", flags, argc));
    for (i = 0; i < argc; i++)
      D(("argv[%d]=%s", i, argv[i]));
    D(("max_devices=%d", cfg->max_devs));
    D(("debug=%d", cfg->debug));
    D(("alwaysok=%d", cfg->alwaysok));
    D(("authfile=%s", cfg->auth_file ? cfg->auth_file : "(null)"));
    D(("origin=%s", cfg->origin ? cfg->origin : "(null)"));
    D(("appid=%s", cfg->appid ? cfg->appid : "(null)"));
  }
}

#ifdef DBG
#undef DBG
#endif
#define DBG(x) if (cfg->debug) { D(x); }

/* PAM entry point for authentication verification */
int pam_sm_authenticate(pam_handle_t * pamh, int flags, int argc,
                        const char **argv)
{

  struct passwd *pw = NULL, pw_s;
  const char *user = NULL;
  cfg_t cfg_st;
  cfg_t *cfg = &cfg_st;
  char buffer[BUFSIZE];
  char *buf;
  int pgu_ret, gpn_ret;
  int retval = PAM_IGNORE;
  device_t *devices = NULL;
  unsigned n_devices = 0;

  parse_cfg(flags, argc, argv, cfg);

  if (!cfg->origin) {
    if (!strcpy(buffer, DEFAULT_ORIGIN_PREFIX)) {
      DBG(("Unable to create origin string"));
      goto done;
    }

    if (gethostname
        (buffer + strlen(DEFAULT_ORIGIN_PREFIX),
         BUFSIZE - strlen(DEFAULT_ORIGIN_PREFIX)) == -1) {
      DBG(("Unable to get host name"));
      goto done;
    }
    DBG(("Origin not specified, using \"%s\"", buffer));
    cfg->origin = strdup(buffer);
  }

  if (!cfg->origin) {
    DBG(("Unable to allocate memory"));
    goto done;
  }

  if (!cfg->appid) {
    DBG(("Appid not specified, using the same value of origin (%s)",
         cfg->origin));
    cfg->appid = strdup(cfg->origin);
  }

  if (!cfg->appid) {
    DBG(("Unable to allocate memory"));
    goto done;
  }

  if (cfg->max_devs == 0) {
    DBG(("Maximum devices number not set. Using default (%d)", MAX_DEVS));
    cfg->max_devs = MAX_DEVS;
  }

  devices = malloc(sizeof(device_t) * cfg->max_devs);
  if (!devices) {
    DBG(("Unable to allocate memory"));
    return PAM_IGNORE;
  }

  pgu_ret = pam_get_user(pamh, &user, NULL);
  if (pgu_ret != PAM_SUCCESS || user == NULL) {
    DBG(("Unable to access user %s", user));
    return PAM_CONV_ERR;
  }

  DBG(("Requesting authentication for user %s", user));

  gpn_ret = getpwnam_r(user, &pw_s, buffer, sizeof(buffer), &pw);
  if (gpn_ret != 0 || pw == NULL || pw->pw_dir == NULL
      || pw->pw_dir[0] != '/') {
    DBG(("Unable to retrieve credentials for user %s, (%s)", user,
         strerror(errno)));
    retval = PAM_USER_UNKNOWN;
    goto done;
  }

  DBG(("Found user %s", user));
  DBG(("Home directory for %s is %s", user, pw->pw_dir));

  if (!cfg->auth_file) {
    buf =
        malloc(sizeof(char) *
               (strlen(pw->pw_dir) + strlen(DEFAULT_AUTHFILE) + 1));
    if (!buf) {
      DBG(("Unable to allocate memory"));
      retval = PAM_IGNORE;
      goto done;
    }

    strcpy(buf, pw->pw_dir);
    strcat(buf, DEFAULT_AUTHFILE);
    DBG(("Using default authentication file %s", buf));

    cfg->auth_file = strdup(buf);
    if (!cfg->auth_file) {
      DBG(("Unable to allocate memory"));
      retval = PAM_IGNORE;
      goto done;
    }

    free(buf);
    buf = NULL;
  } else {
    DBG(("Using authentication file %s", cfg->auth_file));
  }
  retval =
      get_devices_from_authfile(cfg->auth_file, user, cfg->max_devs,
                                cfg->debug, devices, &n_devices);
  if (retval != 1) {
    DBG(("Unable to get devices from file %s", cfg->auth_file));
    retval = PAM_AUTHINFO_UNAVAIL;
    goto done;
  }

  retval = do_authentication(cfg, devices, n_devices);
  if (retval != 1) {
    DBG(("do_authentication returned %d", retval));
    if (retval == -2)
      retval = PAM_IGNORE;
    else
      retval = PAM_AUTH_ERR;
    goto done;
  }

  retval = PAM_SUCCESS;

done:
  free_devices(devices, n_devices);

  if (cfg->alwaysok && retval != PAM_SUCCESS) {
    DBG(("alwaysok needed (otherwise return with %d)", retval));
    retval = PAM_SUCCESS;
  }
  DBG(("done. [%s]", pam_strerror(pamh, retval)));
  pam_set_data(pamh, "yubico_setcred_return", (void *) (intptr_t) retval,
               NULL);
  return retval;


}
