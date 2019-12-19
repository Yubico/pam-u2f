/*
 *  Copyright (C) 2014-2018 Yubico AB - See COPYING
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

/* These #defines must be present according to PAM documentation. */
#define PAM_SM_AUTH

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#include <string.h>
#include "../util.h"

int main(int argc, const char **argv) {
  int rc;

  cfg_t cfg;

  memset(&cfg, 0, sizeof(cfg_t));
  cfg.auth_file = "credentials/ssh_credential";
  cfg.debug = 1;
  cfg.debug_file = stderr;
  cfg.max_devs = 24;
  cfg.sshformat = 1;

  device_t dev[24];
  unsigned n_devs;

  rc = get_devices_from_authfile(&cfg, "" /* not used of SSH format */, dev,
                                 &n_devs);
  assert(rc == 1);
  assert(n_devs == 1);
  assert(strcmp(dev[0].coseType, "es256") == 0);
  assert(strcmp(dev[0].attributes, "+presence") == 0);
  assert(
    strcmp(dev[0].keyHandle, "Li4NkUKcvFym8V6aGagSAI11MXPuKSu6kqdWhdxNmQo3i25Ab"
                             "1Lkun2I2H2bz4EjuwLD1UQpJjLG5vjbKG8efg==") == 0);
  assert(
    strcmp(dev[0].publicKey, "439pGle7126d1YORADduke347N2t2XyKzOSv8M4naCUjlFYDt"
                             "TVhP/MXO41wzHFUIzrrzfEzzCGWoOH5FU5Adw==") == 0);
  assert(dev[0].old_format == 0);

  free(dev[0].coseType);
  free(dev[0].attributes);
  free(dev[0].keyHandle);
  free(dev[0].publicKey);
  memset(dev, 0, sizeof(dev_t));

  cfg.auth_file = "credentials/new_credential";
  cfg.sshformat = 0;

  rc = get_devices_from_authfile(&cfg, "myuser", dev, &n_devs);
  assert(rc == 1);
  assert(n_devs == 1);
  assert(strcmp(dev[0].coseType, "es256") == 0);
  assert(strcmp(dev[0].attributes, "+presence") == 0);
  assert(
    strcmp(dev[0].keyHandle, "iIcshn6ednHo/Fjrhj/KJrodZutIi8fmnPOn5XjPEE1aTnod/"
                             "XKk86l2Im0t/Dh6qCs6G6yu07XhOuh78j9Wnw==") == 0);
  assert(strcmp(dev[0].publicKey,
                "Q15AMwjj/"
                "0O41hzsoXMSBlk0RxjF8XhARNMv7KkyVI+"
                "7pWLdraqIFtfyBC9UJesM5WUYyraf2fgmx9XXcnwijQ==") == 0);
  assert(dev[0].old_format == 0);

  free(dev[0].coseType);
  free(dev[0].attributes);
  free(dev[0].keyHandle);
  free(dev[0].publicKey);
  memset(dev, 0, sizeof(dev_t));

  cfg.auth_file = "credentials/old_credential";
  cfg.sshformat = 0;

  rc = get_devices_from_authfile(&cfg, "myuser", dev, &n_devs);
  assert(rc == 1);
  assert(n_devs == 1);
  assert(strcmp(dev[0].coseType, "es256") == 0);
  assert(strcmp(dev[0].attributes, "+presence") == 0);
  printf("kh %s\n", dev[0].publicKey);
  assert(
    strcmp(dev[0].keyHandle, "mGvXxDqTMSVkSlDnDRNTVsP5Ij9cceCkdZkSJYeaJCHCOpBtM"
                             "IFGQXKBBkvZpV5bWuEuJkoElIiMKirhCPAU8Q==") == 0);
  assert(
    strcmp(dev[0].publicKey,
           "0405a35641a6f5b63e2ef4449393e7e1cb2b96711e797fc74dbd63e99dbf410ffe7"
           "425e79f8c41d8f049c8f7241a803563a43c139f923f0ab9007fbd0dcc722927") ==
    0);
  assert(dev[0].old_format == 1);

  return 0;
}
