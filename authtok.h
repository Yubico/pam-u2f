#ifndef AUTHTOK_H
#define AUTHTOK_H

#include <fido.h>

#include "util.h"

#define HMAC_SALT_SIZE 32
#define HMAC_SECRET_SIZE 32
#define AEAD_TAG_SIZE 16

int get_authtok(const fido_assert_t *assert, const char *enc_authtok,
                char **authtok, size_t *authtok_len);

int generate_encrypted_authtok(fido_dev_t *dev, fido_cred_t *cred,
                               const char *authtok, fido_opt_t uv,
                               const char *pin, unsigned char **enc_authtok,
                               size_t *enc_authtok_len);

#endif /* UTIL_H */
