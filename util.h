/*
 * Copyright (C) 2014 Yubico AB - See COPYING
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>

#define BUFSIZE 1024
#define MAX_DEVS 24
#define PK_LEN 130              // Public key
#define KH_LEN 86               // Key handle
#define RD_LEN 40               // Rounding
#define DEVSIZE (((PK_LEN)+(KH_LEN)+(RD_LEN)))
#define DEFAULT_AUTHFILE_DIR_VAR "XDG_CONFIG_HOME"
#define DEFAULT_AUTHFILE "/Yubico/u2f_keys"
#define DEFAULT_ORIGIN_PREFIX "pam://"

#if defined(DEBUG_PAM)
#if defined(HAVE_SECURITY__PAM_MACROS_H)
#define DEBUG
#include <security/_pam_macros.h>
#else
#define D(x) do {                                                     \
    printf ("debug: %s:%d (%s): ", __FILE__, __LINE__, __FUNCTION__); \
    printf x;                                                         \
    printf ("\n");                                                    \
  } while (0)
#endif                          /* HAVE_SECURITY__PAM_MACROS_H */
#else
#define D(x)
#endif                          /* DEBUG_PAM */

typedef struct {
  unsigned max_devs;
  const char *client_key;
  int manual;
  int debug;
  int nouserok;
  int alwaysok;
  int interactive;
  const char *auth_file;
  const char *origin;
  const char *appid;
} cfg_t;

typedef struct {
  unsigned char *publicKey;
  char *keyHandle;
  size_t key_len;
} device_t;

int get_devices_from_authfile(const char *authfile, const char *username,
                              unsigned max_devs, int verbose,
                              device_t * devices, unsigned *n_devs);
void free_devices(device_t * devices, const unsigned n_devs);

int do_authentication(const cfg_t * cfg, const device_t * devices,
                      const unsigned n_devs);
int do_manual_authentication(const cfg_t * cfg, const device_t * devices,
                      const unsigned n_devs);
char *converse(pam_handle_t *pamh, int echocode,
                          const char *prompt)
#endif                          /* UTIL_H */
