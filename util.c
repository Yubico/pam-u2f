/*
 * Copyright (C) 2014-2018 Yubico AB - See COPYING
 */

#include "util.h"

#include <u2f-server.h>
#include <u2f-host.h>

#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <syslog.h>
#include <pwd.h>
#include <errno.h>
#include <unistd.h>

#include <string.h>

int get_devices_from_authfile(const char *authfile, const char *username,
                              unsigned max_devs, int verbose, FILE *debug_file,
                              device_t *devices, unsigned *n_devs) {

  char *buf = NULL;
  char *s_user, *s_token;
  int retval = 0;
  int fd = -1;
  struct stat st;
  struct passwd *pw = NULL, pw_s;
  char buffer[BUFSIZE];
  int gpu_ret;
  FILE *opwfile = NULL;
  unsigned i, j;

  /* Ensure we never return uninitialized count. */
  *n_devs = 0;

  fd = open(authfile, O_RDONLY, 0);
  if (fd < 0) {
    if (verbose)
      D(debug_file, "Cannot open file: %s (%s)", authfile, strerror(errno));
    goto err;
  }

  if (fstat(fd, &st) < 0) {
    if (verbose)
      D(debug_file, "Cannot stat file: %s (%s)", authfile, strerror(errno));
    goto err;
  }

  if (!S_ISREG(st.st_mode)) {
    if (verbose)
      D(debug_file, "%s is not a regular file", authfile);
    goto err;
  }

  if (st.st_size == 0) {
    if (verbose)
      D(debug_file, "File %s is empty", authfile);
    goto err;
  }

  gpu_ret = getpwuid_r(st.st_uid, &pw_s, buffer, sizeof(buffer), &pw);
  if (gpu_ret != 0 || pw == NULL) {
    D(debug_file, "Unable to retrieve credentials for uid %u, (%s)", st.st_uid,
       strerror(errno));
    goto err;
  }

  if (strcmp(pw->pw_name, username) != 0 && strcmp(pw->pw_name, "root") != 0) {
    if (strcmp(username, "root") != 0) {
      D(debug_file, "The owner of the authentication file is neither %s nor root",
         username);
    } else {
      D(debug_file, "The owner of the authentication file is not root");
    }
    goto err;
  }

  opwfile = fdopen(fd, "r");
  if (opwfile == NULL) {
    if (verbose)
      D(debug_file, "fdopen: %s", strerror(errno));
    goto err;
  }

  buf = malloc(sizeof(char) * (DEVSIZE * max_devs));
  if (!buf) {
    if (verbose)
      D(debug_file, "Unable to allocate memory");
    goto err;
  }

  retval = -2;
  while (fgets(buf, (int)(DEVSIZE * (max_devs - 1)), opwfile)) {
    char *saveptr = NULL;
    if (buf[strlen(buf) - 1] == '\n')
      buf[strlen(buf) - 1] = '\0';

    if (verbose)
      D(debug_file, "Authorization line: %s", buf);

    s_user = strtok_r(buf, ":", &saveptr);
    if (s_user && strcmp(username, s_user) == 0) {
      if (verbose)
        D(debug_file, "Matched user: %s", s_user);

      retval = -1; // We found at least one line for the user

      // only keep last line for this user
      for (i = 0; i < *n_devs; i++) {
        free(devices[i].keyHandle);
        free(devices[i].publicKey);
        devices[i].keyHandle = NULL;
        devices[i].publicKey = NULL;
      }
      *n_devs = 0;

      i = 0;
      while ((s_token = strtok_r(NULL, ",", &saveptr))) {
        devices[i].keyHandle = NULL;
        devices[i].publicKey = NULL;

        if ((*n_devs)++ > MAX_DEVS - 1) {
          *n_devs = MAX_DEVS;
          if (verbose)
            D(debug_file, "Found more than %d devices, ignoring the remaining ones",
               MAX_DEVS);
          break;
        }

        if (verbose)
          D(debug_file, "KeyHandle for device number %d: %s", i + 1, s_token);

        devices[i].keyHandle = strdup(s_token);

        if (!devices[i].keyHandle) {
          if (verbose)
            D(debug_file, "Unable to allocate memory for keyHandle number %d", i);
          goto err;
        }

        s_token = strtok_r(NULL, ":", &saveptr);

        if (!s_token) {
          if (verbose)
            D(debug_file, "Unable to retrieve publicKey number %d", i + 1);
          goto err;
        }

        if (verbose)
          D(debug_file, "publicKey for device number %d: %s", i + 1, s_token);

        if (strlen(s_token) % 2 != 0) {
          if (verbose)
            D(debug_file, "Length of key number %d not even", i + 1);
          goto err;
        }

        devices[i].key_len = strlen(s_token) / 2;

        if (verbose)
          D(debug_file, "Length of key number %d is %zu", i + 1, devices[i].key_len);

        devices[i].publicKey =
          malloc((sizeof(unsigned char) * devices[i].key_len));

        if (!devices[i].publicKey) {
          if (verbose)
            D(debug_file, "Unable to allocate memory for publicKey number %d", i);
          goto err;
        }

        for (j = 0; j < devices[i].key_len; j++) {
          unsigned int x;
          if (sscanf(&s_token[2 * j], "%2x", &x) != 1) {
            if (verbose)
              D(debug_file, "Invalid hex number in key");
            goto err;
          }
          devices[i].publicKey[j] = (unsigned char)x;
        }

        i++;
      }
    }
  }

  if (verbose)
    D(debug_file, "Found %d device(s) for user %s", *n_devs, username);

  retval = 1;
  goto out;

err:
  for (i = 0; i < *n_devs; i++) {
    free(devices[i].keyHandle);
    free(devices[i].publicKey);
    devices[i].keyHandle = NULL;
    devices[i].publicKey = NULL;
  }

  *n_devs = 0;

out:
  if (buf) {
    free(buf);
    buf = NULL;
  }

  if (opwfile)
    fclose(opwfile);
  else if (fd >= 0)
    close(fd);
  return retval;
}

void free_devices(device_t *devices, const unsigned n_devs) {
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

int do_authentication(const cfg_t *cfg, const device_t *devices,
                      const unsigned n_devs, pam_handle_t *pamh) {
  u2fs_ctx_t *ctx;
  u2fs_auth_res_t *auth_result;
  u2fs_rc s_rc;
  u2fh_rc h_rc;
  u2fh_devs *devs = NULL;
  char *response = NULL;
  char *buf;
  int retval = -2;
  int cued = 0;
  unsigned i = 0;
  unsigned max_index = 0;
  unsigned max_index_prev = 0;

  h_rc = u2fh_global_init(cfg->debug ? U2FH_DEBUG : 0);
  if (h_rc != U2FH_OK) {
    D(cfg->debug_file, "Unable to initialize libu2f-host: %s", u2fh_strerror(h_rc));
    return retval;
  }
  h_rc = u2fh_devs_init(&devs);
  if (h_rc != U2FH_OK) {
    D(cfg->debug_file, "Unable to initialize libu2f-host device handles: %s",
       u2fh_strerror(h_rc));
    return retval;
  }

  if ((h_rc = u2fh_devs_discover(devs, &max_index)) != U2FH_OK) {
    if (cfg->debug)
      D(cfg->debug_file, "Unable to discover device(s), %s", u2fh_strerror(h_rc));
    return retval;
  }
  max_index_prev = max_index;

  if (cfg->debug)
    D(cfg->debug_file, "Device max index is %u", max_index);

  s_rc = u2fs_global_init(cfg->debug ? U2FS_DEBUG : 0);
  if (s_rc != U2FS_OK) {
    D(cfg->debug_file, "Unable to initialize libu2f-server: %s", u2fs_strerror(s_rc));
    return retval;
  }
  s_rc = u2fs_init(&ctx);
  if (s_rc != U2FS_OK) {
    D(cfg->debug_file, "Unable to initialize libu2f-server context: %s", u2fs_strerror(s_rc));
    return retval;
  }

  if ((s_rc = u2fs_set_origin(ctx, cfg->origin)) != U2FS_OK) {
    if (cfg->debug)
      D(cfg->debug_file, "Unable to set origin: %s", u2fs_strerror(s_rc));
    return retval;
  }

  if ((s_rc = u2fs_set_appid(ctx, cfg->appid)) != U2FS_OK) {
    if (cfg->debug)
      D(cfg->debug_file, "Unable to set appid: %s", u2fs_strerror(s_rc));
    return retval;
  }

  i = 0;
  while (i < n_devs) {

    retval = -2;

    if (cfg->debug)
      D(cfg->debug_file, "Attempting authentication with device number %d", i + 1);

    if ((s_rc = u2fs_set_keyHandle(ctx, devices[i].keyHandle)) != U2FS_OK) {
      if (cfg->debug)
        D(cfg->debug_file, "Unable to set keyHandle: %s", u2fs_strerror(s_rc));
      return retval;
    }

    if ((s_rc = u2fs_set_publicKey(ctx, devices[i].publicKey)) != U2FS_OK) {
      if (cfg->debug)
        D(cfg->debug_file, "Unable to set publicKey %s", u2fs_strerror(s_rc));
      return retval;
    }

    if ((s_rc = u2fs_authentication_challenge(ctx, &buf)) != U2FS_OK) {
      if (cfg->debug)
        D(cfg->debug_file, "Unable to produce authentication challenge: %s",
           u2fs_strerror(s_rc));
      free(buf);
      buf = NULL;
      return retval;
    }

    if (cfg->debug)
      D(cfg->debug_file, "Challenge: %s", buf);

    if (cfg->nodetect || (h_rc = u2fh_authenticate(devs, buf, cfg->origin, &response, 0)) == U2FH_OK ) {

      if (cfg->nodetect)
        D(cfg->debug_file, "nodetect option specified, suitable key detection skipped");

      if (cfg->manual == 0 && cfg->cue && !cued) {
        cued = 1;
        converse(pamh, PAM_TEXT_INFO, DEFAULT_CUE);
      }

      retval = -1;

      if ((h_rc = u2fh_authenticate(devs, buf, cfg->origin, &response, U2FH_REQUEST_USER_PRESENCE)) ==
          U2FH_OK) {
        if (cfg->debug)
          D(cfg->debug_file, "Response: %s", response);

        s_rc = u2fs_authentication_verify(ctx, response, &auth_result);
        u2fs_free_auth_res(auth_result);
        free(response);
        response = NULL;
        if (s_rc == U2FS_OK) {
          retval = 1;

          free(buf);
          buf = NULL;
          break;
        }
      } else {
        if (cfg->debug)
          D(cfg->debug_file, "Unable to communicate to the device, %s", u2fh_strerror(h_rc));
      }
    } else {
      if (cfg->debug)
        D(cfg->debug_file, "Device for this keyhandle is not present.");
    }
    free(buf);
    buf = NULL;

    i++;

    if (u2fh_devs_discover(devs, &max_index) != U2FH_OK) {
      if (cfg->debug)
        D(cfg->debug_file, "Unable to discover devices");
      return retval;
    }

    if (max_index > max_index_prev) {
      if (cfg->debug)
        D(cfg->debug_file, "Devices max_index has changed: %u (was %u). Starting over",
           max_index, max_index_prev);
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

int do_manual_authentication(const cfg_t *cfg, const device_t *devices,
                             const unsigned n_devs, pam_handle_t *pamh) {
  u2fs_ctx_t *ctx_arr[n_devs];
  u2fs_auth_res_t *auth_result;
  u2fs_rc s_rc;
  char *response = NULL;
  char prompt[MAX_PROMPT_LEN];
  char *buf;
  int retval = -2;
  unsigned i = 0;

  if (u2fs_global_init(0) != U2FS_OK) {
    if (cfg->debug)
      D(cfg->debug_file, "Unable to initialize libu2f-server");
    return retval;
  }

  for (i = 0; i < n_devs; ++i) {

    if (u2fs_init(ctx_arr + i) != U2FS_OK) {
      if (cfg->debug)
        D(cfg->debug_file, "Unable to initialize libu2f-server");
      return retval;
    }

    if ((s_rc = u2fs_set_origin(ctx_arr[i], cfg->origin)) != U2FS_OK) {
      if (cfg->debug)
        D(cfg->debug_file, "Unable to set origin: %s", u2fs_strerror(s_rc));
      return retval;
    }

    if ((s_rc = u2fs_set_appid(ctx_arr[i], cfg->appid)) != U2FS_OK) {
      if (cfg->debug)
        D(cfg->debug_file, "Unable to set appid: %s", u2fs_strerror(s_rc));
      return retval;
    }

    if (cfg->debug)
      D(cfg->debug_file, "Attempting authentication with device number %d", i + 1);

    if ((s_rc = u2fs_set_keyHandle(ctx_arr[i], devices[i].keyHandle)) !=
        U2FS_OK) {
      if (cfg->debug)
        D(cfg->debug_file, "Unable to set keyHandle: %s", u2fs_strerror(s_rc));
      return retval;
    }

    if ((s_rc = u2fs_set_publicKey(ctx_arr[i], devices[i].publicKey)) !=
        U2FS_OK) {
      if (cfg->debug)
        D(cfg->debug_file, "Unable to set publicKey %s", u2fs_strerror(s_rc));
      return retval;
    }

    if ((s_rc = u2fs_authentication_challenge(ctx_arr[i], &buf)) != U2FS_OK) {
      if (cfg->debug)
        D(cfg->debug_file, "Unable to produce authentication challenge: %s",
           u2fs_strerror(s_rc));
      return retval;
    }

    if (cfg->debug)
      D(cfg->debug_file, "Challenge: %s", buf);

    if (i == 0) {
      snprintf(prompt, sizeof(prompt),
                      "Now please copy-paste the below challenge(s) to "
                      "'u2f-host -aauthenticate -o %s'",
              cfg->origin);
      converse(pamh, PAM_TEXT_INFO, prompt);
    }
    converse(pamh, PAM_TEXT_INFO, buf);
    free(buf);
    buf = NULL;
  }

  converse(pamh, PAM_TEXT_INFO,
           "Now, please enter the response(s) below, one per line.");

  retval = -1;

  for (i = 0; i < n_devs; ++i) {
    snprintf(prompt, sizeof(prompt), "[%d]: ", i);
    response = converse(pamh, PAM_PROMPT_ECHO_ON, prompt);
    converse(pamh, PAM_TEXT_INFO, response);

    s_rc = u2fs_authentication_verify(ctx_arr[i], response, &auth_result);
    u2fs_free_auth_res(auth_result);
    if (s_rc == U2FS_OK) {
      retval = 1;
    }
    free(response);
    if (retval == 1) {
        break;
    }
  }

  for (i = 0; i < n_devs; ++i)
    u2fs_done(ctx_arr[i]);
  u2fs_global_done();

  return retval;
}

static int _converse(pam_handle_t *pamh, int nargs,
                     const struct pam_message **message,
                     struct pam_response **response) {
  struct pam_conv *conv;
  int retval;

  retval = pam_get_item(pamh, PAM_CONV, (void *)&conv);

  if (retval != PAM_SUCCESS) {
    return retval;
  }

  return conv->conv(nargs, message, response, conv->appdata_ptr);
}

char *converse(pam_handle_t *pamh, int echocode, const char *prompt) {
  const struct pam_message msg = {.msg_style = echocode, .msg = (char *)prompt};
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

#if defined(PAM_DEBUG)
void _debug(FILE *debug_file, const char *file, int line, const char *func, const char *fmt, ...) {
  va_list ap;
#ifdef __linux__
  unsigned int size;
  char buffer[BUFSIZE];
  char *out;

  size = (unsigned int)snprintf(NULL, 0, DEBUG_STR, file, line, func);
  va_start(ap, fmt);
  size += (unsigned int)vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);
  va_start(ap, fmt);
  if (size < (BUFSIZE - 1)) {
    out = buffer;
  }
  else {
    out = malloc(size);
  }

  size = (unsigned int)sprintf(out, DEBUG_STR, file, line, func);
  vsprintf(&out[size], fmt, ap);
  va_end(ap);

  if (debug_file == (FILE *)-1) {
    syslog(LOG_AUTHPRIV | LOG_DEBUG, "%s", out);
  }
  else {
    fprintf(debug_file, "%s\n", out);
  }

  if (out != buffer) {
    free(out);
  }
#else /* Windows, MAC */
  va_start(ap, fmt);
  fprintf(debug_file, DEBUG_STR, file, line, func );
  vfprintf(debug_file, fmt, ap);
  fprintf(debug_file, "\n");
  va_end(ap);
#endif /* __linux__ */
}
#endif /* PAM_DEBUG */
