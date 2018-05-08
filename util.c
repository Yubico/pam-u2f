/*
 * Copyright (C) 2014-2019 Yubico AB - See COPYING
 */

#include <fido.h>
#include <fido/es256.h>

#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <syslog.h>
#include <pwd.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include "b64.h"
#include "util.h"

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
  unsigned i;

  /* Ensure we never return uninitialized count. */
  *n_devs = 0;

  fd = open(authfile, O_RDONLY | O_CLOEXEC | O_NOCTTY);
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
  } else {
    fd = -1; /* fd belongs to opwfile */
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
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n')
      buf[len - 1] = '\0';

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
        if ((*n_devs)++ > max_devs - 1) {
          *n_devs = max_devs;
          if (verbose)
            D(debug_file, "Found more than %d devices, ignoring the remaining ones",
               max_devs);
          break;
        }

        devices[i].keyHandle = NULL;
        devices[i].publicKey = NULL;

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

        devices[i].publicKey = strdup(s_token);

        if (!devices[i].publicKey) {
          if (verbose)
            D(debug_file, "Unable to allocate memory for publicKey number %d", i);
          goto err;
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

  if (fd != -1)
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

static int find_authenticator(const cfg_t *cfg, fido_dev_t *dev,
                              const fido_dev_info_t *devlist,
                              size_t devlist_len, fido_assert_t *assert) {
  const fido_dev_info_t *di = NULL;
  int r;
  size_t i;

  if (cfg->debug)
    D(cfg->debug_file, "Working with %zu authenticator(s)", devlist_len);

  for (i = 0; i < devlist_len; i++) {
    if (cfg->debug)
      D(cfg->debug_file, "Checking whether key exists in authenticator %zu", i);

    di = fido_dev_info_ptr(devlist, i);
    if (!di) {
      if (cfg->debug)
        D(cfg->debug_file, "Unable to get device pointer");
      continue;
    }

    if (cfg->debug)
      D(cfg->debug_file, "Authenticator path: %s", fido_dev_info_path(di));

    r = fido_dev_open(dev, fido_dev_info_path(di));
    if (r != FIDO_OK) {
      if (cfg->debug)
        D(cfg->debug_file, "Failed to open authenticator: %s (%d)",
          fido_strerr(r), r);
      continue;
    }

    r = fido_dev_get_assert(dev, assert, NULL);
    if ((!fido_dev_is_fido2(dev) && r == FIDO_ERR_USER_PRESENCE_REQUIRED) ||
         (fido_dev_is_fido2(dev) && r == FIDO_OK)) {
      if (cfg->debug)
        D(cfg->debug_file, "Found key in authenticator %zu", i);
      return (1);
    }

    if (cfg->debug)
      D(cfg->debug_file, "Key not found in authenticator %zu", i);

    fido_dev_close(dev);
  }

  if (cfg->debug)
    D(cfg->debug_file, "Key not found");

  return (0);
}

int do_authentication(const cfg_t *cfg, const device_t *devices,
                      const unsigned n_devs, pam_handle_t *pamh) {
  es256_pk_t *es256_pk = NULL;
  fido_assert_t *assert = NULL;
  fido_dev_info_t *devlist = NULL;
  fido_dev_t *dev = NULL;
  int cued = 0;
  int r;
  int retval = -2;
  size_t kh_len;
  size_t ndevs = 0;
  size_t ndevs_prev = 0;
  size_t pk_len;
  unsigned char challenge[32];
  unsigned char *kh = NULL;
  unsigned char *pk = NULL;
  unsigned i = 0;

  fido_init(cfg->debug ? FIDO_DEBUG : 0);

  devlist = fido_dev_info_new(64);
  if (!devlist) {
    if (cfg->debug)
      D(cfg->debug_file, "Unable to allocate devlist");
   goto out;
  }

  r = fido_dev_info_manifest(devlist, 64, &ndevs);
  if (r != FIDO_OK) {
    if (cfg->debug)
      D(cfg->debug_file, "Unable to discover device(s), %s (%d)",
        fido_strerr(r), r);
    goto out;
  }

  ndevs_prev = ndevs;

  if (cfg->debug)
    D(cfg->debug_file, "Device max index is %u", ndevs);

  es256_pk = es256_pk_new();
  if (!es256_pk) {
    if (cfg->debug)
      D(cfg->debug_file, "Unable to allocate public key");
    goto out;
  }

  dev = fido_dev_new();
  if (!dev) {
    if (cfg->debug)
      D(cfg->debug_file, "Unable to allocate device");
    goto out;
  }

  assert = fido_assert_new();
  if (!assert) {
    if (cfg->debug)
      D(cfg->debug_file, "Unable to allocate assertion");
    goto out;
  }

  r = fido_assert_set_rp(assert, cfg->origin);
  if (r != FIDO_OK) {
    if (cfg->debug)
      D(cfg->debug_file, "Unable to set origin: %s (%d)", fido_strerr(r), r);
    goto out;
  }

  r = fido_assert_set_options(assert, false, false);
  if (r != FIDO_OK) {
    if (cfg->debug)
      D(cfg->debug_file, "Unable to set options: %s (%d)", fido_strerr(r), r);
    goto out;
  }

  if (cfg->nodetect && cfg->debug)
    D(cfg->debug_file, "nodetect option specified, suitable key detection will be skipped");

  i = 0;
  while (i < n_devs) {
    retval = -2;

    if (cfg->debug)
      D(cfg->debug_file, "Attempting authentication with device number %d", i + 1);

    if (!b64_decode(devices[i].keyHandle, (void **)&kh, &kh_len)) {
      if (cfg->debug)
        D(cfg->debug_file, "Failed to decode key handle");
      goto out;
    }

    r = fido_assert_allow_cred(assert, kh, kh_len);
    if (r != FIDO_OK) {
      if (cfg->debug)
        D(cfg->debug_file, "Unable to set keyHandle: %s (%d)", fido_strerr(r), r);
      goto out;
    }

    if (!b64_decode(devices[i].publicKey, (void **)&pk, &pk_len)) {
      if (cfg->debug)
        D(cfg->debug_file, "Failed to decode public key");
      goto out;
    }

    if (!random_bytes(challenge, sizeof(challenge))) {
      if (cfg->debug)
        D(cfg->debug_file, "Failed to generate challenge");
      goto out;
    }

    if (cfg->debug) {
      char *b64_challenge;
      if (!b64_encode(challenge, sizeof(challenge), &b64_challenge)) {
        D(cfg->debug_file, "Failed to encode challenge");
      } else {
        D(cfg->debug_file, "Challenge: %s", b64_challenge);
        free(b64_challenge);
      }
    }

    r = fido_assert_set_clientdata_hash(assert, challenge, sizeof(challenge));
    if (r != FIDO_OK) {
      if (cfg->debug)
        D(cfg->debug_file, "Unable to set challenge: %s( %d)", fido_strerr(r),
          r);
      goto out;
    }

    if (find_authenticator(cfg, dev, devlist, ndevs, assert)) {
      r = fido_dev_get_assert(dev, assert, NULL);
      if ((!fido_dev_is_fido2(dev) && r == FIDO_ERR_USER_PRESENCE_REQUIRED) ||
          r == FIDO_OK) {

        if (cfg->manual == 0 && cfg->cue && !cued) {
          cued = 1;
          converse(pamh, PAM_TEXT_INFO, DEFAULT_CUE);
        }

        retval = -1;

        fido_assert_set_options(assert, true, false);

        if ((r = fido_dev_get_assert(dev, assert, NULL)) == FIDO_OK) {
          if (es256_pk_from_ptr(es256_pk, pk, pk_len) == FIDO_OK) {
            r = fido_assert_verify(assert, 0, COSE_ES256, es256_pk);
            if (r == FIDO_OK) {
              retval = 1;
              break;
            }
          }
        } else {
          if (cfg->debug)
            D(cfg->debug_file, "Unable to communicate with the device, %s (%d)",
              fido_strerr(r), r);
        }
      }
    } else {
      if (cfg->debug)
        D(cfg->debug_file, "Device for this keyhandle is not present.");
    }

    i++;

    fido_dev_info_free(&devlist, ndevs);

    devlist = fido_dev_info_new(64);
    if (!devlist) {
      if (cfg->debug)
        D(cfg->debug_file, "Unable to allocate devlist");
      goto out;
    }

    r = fido_dev_info_manifest(devlist, 64, &ndevs);
    if (r != FIDO_OK) {
      if (cfg->debug)
        D(cfg->debug_file, "Unable to discover device(s), %s (%d)",
          fido_strerr(r), r);
      goto out;
    }

    if (ndevs > ndevs_prev) {
      if (cfg->debug)
        D(cfg->debug_file, "Devices max_index has changed: %zu (was %zu). Starting over",
          ndevs, ndevs_prev);
      ndevs_prev = ndevs;
      i = 0;
    }

    free(kh);
    free(pk);

    kh = NULL;
    pk = NULL;

    fido_dev_close(dev);
  }

out:
  es256_pk_free(&es256_pk);
  fido_assert_free(&assert);
  fido_dev_info_free(&devlist, ndevs);

  if (dev)
    fido_dev_close(dev);

  fido_dev_free(&dev);

  free(kh);
  free(pk);

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

  if (out) {
    size = (unsigned int)sprintf(out, DEBUG_STR, file, line, func);
    vsprintf(&out[size], fmt, ap);
    va_end(ap);
  }
  else {
    out = buffer;
    sprintf(out, "debug(pam_u2f): malloc failed when trying to log\n");
  }

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

#ifndef RANDOM_DEV
#define RANDOM_DEV "/dev/urandom"
#endif

int random_bytes(void *buf, size_t cnt) {
  int fd;
  ssize_t n;

  fd = open(RANDOM_DEV, O_RDONLY);
  if (fd < 0)
    return (0);

  n = read(fd, buf, cnt);
  close(fd);
  if (n < 0 || (size_t)n != cnt)
    return (0);

  return (1);
}
