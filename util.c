/*
 * Copyright (C) 2014-2015 Yubico AB - See COPYING
 */

#include "util.h"

#include <u2f-server/u2f-server.h>
#include <u2f-host/u2f-host.h>

#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <string.h>

int
get_devices_from_authfile(const char *authfile, const char *username,
                          unsigned max_devs, int verbose,
                          device_t * devices, unsigned *n_devs)
{

  char *buf;
  char *s_user, *s_token;
  int retval = 0;
  int fd;
  struct stat st;
  FILE *opwfile;
  unsigned i, j;

  fd = open(authfile, O_RDONLY, 0);
  if (fd < 0) {
    if (verbose)
      D(("Cannot open file: %s (%s)", authfile, strerror(errno)));
    return retval;
  }

  if (fstat(fd, &st) < 0) {
    if (verbose)
      D(("Cannot stat file: %s (%s)", authfile, strerror(errno)));
    close(fd);
    return retval;
  }

  if (!S_ISREG(st.st_mode)) {
    if (verbose)
      D(("%s is not a regular file", authfile));
    close(fd);
    return retval;
  }

  if (st.st_size == 0) {
    if (verbose)
      D(("File %s is empty", authfile));
    close(fd);
    return retval;
  }

  opwfile = fdopen(fd, "r");
  if (opwfile == NULL) {
    if (verbose)
      D(("fdopen: %s", strerror(errno)));
    close(fd);
    return retval;
  }

  buf = malloc(sizeof(char) * (DEVSIZE * max_devs));
  if (!buf) {
    if (verbose)
      D(("Unable to allocate memory"));
    return retval;
  }

  retval = -2;
  while (fgets(buf, (int) (DEVSIZE * (max_devs - 1)), opwfile)) {
    char *saveptr = NULL;
    if (buf[strlen(buf) - 1] == '\n')
      buf[strlen(buf) - 1] = '\0';

    if (verbose)
      D(("Authorization line: %s", buf));

    s_user = strtok_r(buf, ":", &saveptr);
    if (s_user && strcmp(username, s_user) == 0) {
      if (verbose)
        D(("Matched user: %s", s_user));

      retval = -1;              //We found at least one line for the user

      *n_devs = 0;

      i = 0;
      while ((s_token = strtok_r(NULL, ",", &saveptr))) {

        if ((*n_devs)++ > MAX_DEVS - 1) {
          *n_devs = MAX_DEVS;
          if (verbose)
            D(("Found more than %d devices, ignoring the remaining ones",
               MAX_DEVS));
          break;
        }

        if (!s_token) {
          if (verbose)
            D(("Unable to retrieve keyHandle number %d", i + 1));
          fclose(opwfile);
          *n_devs = 0;
          free(buf);
          buf = NULL;
          return retval;
        }

        if (verbose)
          D(("KeyHandle for device number %d: %s", i + 1, s_token));

        devices[i].keyHandle = strdup(s_token);

        if (!devices[i].keyHandle) {
          if (verbose)
            D(("Unable to allocate memory for keyHandle number %d", i));
          *n_devs = 0;
          fclose(opwfile);
          free(buf);
          buf = NULL;
          return retval;
        }

        s_token = strtok_r(NULL, ":", &saveptr);

        if (!s_token) {
          if (verbose)
            D(("Unable to retrieve publicKey number %d", i + 1));
          *n_devs = 0;
          fclose(opwfile);
          free(buf);
          buf = NULL;
          return retval;
        }

        if (verbose)
          D(("publicKey for device number %d: %s", i + 1, s_token));

        if (strlen(s_token) % 2 != 0) {
          if (verbose)
            D(("Length of key number %d not even", i + 1));
          *n_devs = 0;
          fclose(opwfile);
          free(buf);
          buf = NULL;
          return retval;
        }

        devices[i].key_len = strlen(s_token) / 2;

        if (verbose)
          D(("Length of key number %d is %d", i + 1, devices[i].key_len));

        devices[i].publicKey =
            malloc((sizeof(unsigned char) * devices[i].key_len));

        if (!devices[i].publicKey) {
          if (verbose)
            D(("Unable to allocate memory for publicKey number %d", i));

          *n_devs = 0;
          fclose(opwfile);
          free(buf);
          buf = NULL;
          return retval;
        }

        for (j = 0; j < devices[i].key_len; j++) {
          sscanf(&s_token[2 * j], "%2x",
                 (unsigned int *) &(devices[i].publicKey[j]));
        }

        i++;
      }
    }
  }
  fclose(opwfile);

  if (verbose)
    D(("Found %d device(s) for user %s", *n_devs, username));

  free(buf);
  buf = NULL;

  retval = 1;
  return retval;
}

void free_devices(device_t * devices, const unsigned n_devs)
{
  unsigned i;

  if (!devices)
    return;

  for (i = 0; i < n_devs; i++) {
    free(devices[i].keyHandle);
    devices[i].keyHandle = NULL;

    free(devices[i].publicKey);
    devices[i].publicKey = NULL;
  }

  free(devices);
  devices = NULL;

}

int do_authentication(const cfg_t * cfg, const device_t * devices,
                      const unsigned n_devs, pam_handle_t * pamh)
{
  u2fs_ctx_t *ctx;
  u2fs_auth_res_t *auth_result;
  u2fs_rc s_rc;
  u2fh_rc h_rc;
  u2fh_devs *devs = NULL;
  char *response = NULL;
  char *buf;
  int retval = -2;
  unsigned i = 0;
  unsigned max_index = 0;
  unsigned max_index_prev = 0;

  if (u2fh_global_init(0) != U2FH_OK || u2fh_devs_init(&devs) != U2FH_OK) {
    D(("Unable to initialize libu2f-host"));
    return retval;
  }

  if ((h_rc = u2fh_devs_discover(devs, &max_index)) != U2FH_OK) {
    D(("Unable to discover device(s), %s", u2fh_strerror(h_rc)));
    return retval;
  } else if (cfg->manual == 0) {
    if (cfg->cue) {
      converse(pamh, PAM_TEXT_INFO, "Please touch the device.");
    }
  }
  max_index_prev = max_index;

  if (cfg->debug)
    D(("Device max index is %u", max_index));

  if (u2fs_global_init(0) != U2FS_OK || u2fs_init(&ctx) != U2FS_OK) {
    D(("Unable to initialize libu2f-server"));
    return retval;
  }

  if ((s_rc = u2fs_set_origin(ctx, cfg->origin)) != U2FS_OK) {
    D(("Unable to set origin: %s", u2fs_strerror(s_rc)));
    return retval;
  }

  if ((s_rc = u2fs_set_appid(ctx, cfg->appid)) != U2FS_OK) {
    D(("Unable to set appid: %s", u2fs_strerror(s_rc)));
    return retval;
  }

  i = 0;
  while (i < n_devs) {

    retval = -2;

    if (cfg->debug)
      D(("Attempting authentication with device number %d", i + 1));

    if ((s_rc = u2fs_set_keyHandle(ctx, devices[i].keyHandle)) != U2FS_OK) {
      D(("Unable to set keyHandle: %s", u2fs_strerror(s_rc)));
      return retval;
    }

    if ((s_rc = u2fs_set_publicKey(ctx, devices[i].publicKey)) != U2FS_OK) {
      D(("Unable to set publicKey %s", u2fs_strerror(s_rc)));
      return retval;
    }

    if ((s_rc = u2fs_authentication_challenge(ctx, &buf)) != U2FS_OK) {
      D(("Unable to produce authentication challenge: %s",
         u2fs_strerror(s_rc)));
      return retval;
    }

    if (cfg->debug)
      D(("Challenge: %s", buf));

    if ((h_rc =
         u2fh_authenticate(devs, buf, cfg->origin, &response,
                           1)) == U2FH_OK) {
      if (cfg->debug)
        D(("Response: %s", response));

      retval = -1;

      if (u2fs_authentication_verify(ctx, response, &auth_result) ==
          U2FS_OK) {
        retval = 1;
        break;
      }
    } else {
      if (cfg->debug)
        D(("Unable to communicate to the device, %s",
           u2fh_strerror(h_rc)));
    }

    i++;

    if (u2fh_devs_discover(devs, &max_index) != U2FH_OK) {
      D(("Unable to discover devices"));
      return retval;
    }

    if (max_index > max_index_prev) {
      if (cfg->debug)
        D(("Devices max_index has changed: %u (was %u). Starting over",
           max_index, max_index_prev));
      max_index_prev = max_index;
      i = 0;
    }
  }

  u2fh_devs_done(devs);
  u2fh_global_done();

  u2fs_done(ctx);
  u2fs_global_done();

  return retval;

}

#define MAX_PROMPT_LEN (1024)

int do_manual_authentication(const cfg_t * cfg, const device_t * devices,
                             const unsigned n_devs, pam_handle_t * pamh)
{
  u2fs_ctx_t *ctx_arr[n_devs];
  u2fs_auth_res_t *auth_result;
  u2fs_rc s_rc;
  char *response = NULL;
  char prompt[MAX_PROMPT_LEN];
  char *buf;
  int retval = -2;
  unsigned i = 0;

  if (u2fs_global_init(0) != U2FS_OK) {
    D(("Unable to initialize libu2f-server"));
    return retval;
  }

  for (i = 0; i < n_devs; ++i) {

    if (u2fs_init(ctx_arr + i) != U2FS_OK) {
      D(("Unable to initialize libu2f-server"));
      return retval;
    }

    if ((s_rc = u2fs_set_origin(ctx_arr[i], cfg->origin)) != U2FS_OK) {
      D(("Unable to set origin: %s", u2fs_strerror(s_rc)));
      return retval;
    }

    if ((s_rc = u2fs_set_appid(ctx_arr[i], cfg->appid)) != U2FS_OK) {
      D(("Unable to set appid: %s", u2fs_strerror(s_rc)));
      return retval;
    }

    if (cfg->debug)
      D(("Attempting authentication with device number %d", i + 1));

    if ((s_rc =
         u2fs_set_keyHandle(ctx_arr[i],
                            devices[i].keyHandle)) != U2FS_OK) {
      D(("Unable to set keyHandle: %s", u2fs_strerror(s_rc)));
      return retval;
    }

    if ((s_rc =
         u2fs_set_publicKey(ctx_arr[i],
                            devices[i].publicKey)) != U2FS_OK) {
      D(("Unable to set publicKey %s", u2fs_strerror(s_rc)));
      return retval;
    }

    if ((s_rc =
         u2fs_authentication_challenge(ctx_arr[i], &buf)) != U2FS_OK) {
      D(("Unable to produce authentication challenge: %s",
         u2fs_strerror(s_rc)));
      return retval;
    }

    if (cfg->debug)
      D(("Challenge: %s", buf));

    if (i == 0) {
      sprintf(prompt,
              "Now please copy-paste the below challenge(s) to 'u2f-host -aauthenticate -o %s'",
              cfg->origin);
      converse(pamh, PAM_TEXT_INFO, prompt);
    }
    converse(pamh, PAM_TEXT_INFO, buf);

  }

  converse(pamh, PAM_TEXT_INFO,
           "Now, please enter the response(s) below, one per line.");

  retval = -1;

  for (i = 0; (i < n_devs) && (retval != 1); ++i) {
    sprintf(prompt, "[%d]: ", i);
    response = converse(pamh, PAM_PROMPT_ECHO_ON, prompt);
    converse(pamh, PAM_TEXT_INFO, response);

    if (retval != 1 &&
        u2fs_authentication_verify(ctx_arr[i], response, &auth_result)
        == U2FS_OK) {
      retval = 1;
    }
    free(response);
  }

  for (i = 0; i < n_devs; ++i)
    u2fs_done(ctx_arr[i]);
  u2fs_global_done();

  return retval;

}

static int _converse(pam_handle_t * pamh, int nargs,
                     const struct pam_message **message,
                     struct pam_response **response)
{
  struct pam_conv *conv;
  int retval;

  retval = pam_get_item(pamh, PAM_CONV, (void *) &conv);

  if (retval != PAM_SUCCESS) {
    return retval;
  }

  return conv->conv(nargs, message, response, conv->appdata_ptr);
}

char *converse(pam_handle_t * pamh, int echocode, const char *prompt)
{
  const struct pam_message msg = {.msg_style = echocode,
    .msg = prompt
  };
  const struct pam_message *msgs = &msg;
  struct pam_response *resp = NULL;
  int retval = _converse(pamh, 1, &msgs, &resp);
  char *ret = NULL;

  if (retval != PAM_SUCCESS || resp == NULL || resp->resp == NULL ||
      *resp->resp == '\000') {

    if (retval == PAM_SUCCESS && resp && resp->resp) {
      ret = resp->resp;
    }
  } else {
    ret = resp->resp;
  }

  // Deallocate temporary storage.
  if (resp) {
    if (!ret) {
      free(resp->resp);
    }
    free(resp);
  }

  return ret;
}
