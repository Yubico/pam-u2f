#include <string.h>
#include <fido.h>
#include <openssl/evp.h>

#include "authtok.h"
#include "b64.h"

static int
encrypt_authtok(const unsigned char *plaintext, size_t plaintext_len,
                const unsigned char *key, /* 32 bytes */
                unsigned char *tag,       /* 16 bytes */
                unsigned char *ciphertext /* equal to plaintext_len */
) {
  EVP_CIPHER_CTX *ctx = NULL;
  int len;
  int retval = 0;
  unsigned char iv[12] = {0};

  if (!(ctx = EVP_CIPHER_CTX_new())) {
    goto err;
  }
  if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
    goto err;
  }
  if (plaintext_len > INT_MAX) {
    goto err;
  }
  if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext,
                         (int) plaintext_len)) {
    goto err;
  }
  if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
    goto err;
  }
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, (void *) tag)) {
    goto err;
  }
  retval = 1;

err:
  EVP_CIPHER_CTX_free(ctx);
  return retval;
}

static int
decrypt_authtok(const unsigned char *ciphertext, size_t ciphertext_len,
                const unsigned char *key, /* 32 bytes */
                const unsigned char *tag, /* 16 bytes */
                unsigned char *plaintext  /* equal to ciphertext_len */
) {
  EVP_CIPHER_CTX *ctx = NULL;
  int len;
  int retval = 0;
  unsigned char iv[12] = {0};

  if (!(ctx = EVP_CIPHER_CTX_new())) {
    goto err;
  }
  if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv)) {
    goto err;
  }
  if (ciphertext_len > INT_MAX) {
    goto err;
  }
  if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext,
                         (int) ciphertext_len)) {
    goto err;
  }
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void *) tag)) {
    goto err;
  }
  if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
    goto err;
  }
  retval = 1;

err:
  EVP_CIPHER_CTX_free(ctx);
  return retval;
}

int get_authtok(const fido_assert_t *assert, const char *enc_authtok,
                char **authtok, size_t *authtok_len) {
  unsigned char *buf = NULL;
  size_t buf_len;
  const unsigned char *key;
  int ok = 0;

  *authtok = NULL;

  if (!b64_decode(enc_authtok, (void **) &buf, &buf_len) ||
      buf_len <= HMAC_SALT_SIZE + AEAD_TAG_SIZE) {
    goto err;
  }

  if (fido_assert_count(assert) != 1) {
    goto err;
  }

  if ((key = fido_assert_hmac_secret_ptr(assert, 0)) == NULL) {
    goto err;
  }
  if (fido_assert_hmac_secret_len(assert, 0) != HMAC_SECRET_SIZE) {
    goto err;
  }

  *authtok_len = buf_len - HMAC_SALT_SIZE - AEAD_TAG_SIZE;
  if (!(*authtok = malloc(*authtok_len + 1))) {
    goto err;
  }
  if (!decrypt_authtok(buf + HMAC_SALT_SIZE,
                       buf_len - HMAC_SALT_SIZE - AEAD_TAG_SIZE, key,
                       buf + buf_len - AEAD_TAG_SIZE,
                       (unsigned char *) *authtok)) {
    goto err;
  }
  (*authtok)[*authtok_len] = '\0';

  ok = 1;

err:
  free(buf);
  if (!ok) {
    if (*authtok) {
      explicit_bzero(*authtok, *authtok_len);
      free(*authtok);
      *authtok = NULL;
      *authtok_len = 0;
    }
  }
  return ok;
}

static int get_hmac_secret(fido_dev_t *dev, fido_cred_t *cred, fido_opt_t uv,
                           const char *pin, const unsigned char *salt,
                           unsigned char *secret) {
  fido_assert_t *assert = NULL;
  unsigned char cdh[32];
  const unsigned char *kh = NULL;
  const unsigned char *hmac_secret;
  size_t kh_len;
  size_t hmac_secret_len;
  const char *id;
  int retval = 0;

  if (!random_bytes(cdh, sizeof(cdh))) {
    goto err;
  }

  if ((assert = fido_assert_new()) == NULL) {
    goto err;
  }

  if (!(id = fido_cred_rp_id(cred))) {
    goto err;
  }

  if (fido_assert_set_rp(assert, id) != FIDO_OK) {
    goto err;
  }

  if ((kh = fido_cred_id_ptr(cred)) == NULL) {
    goto err;
  }

  if ((kh_len = fido_cred_id_len(cred)) == 0) {
    goto err;
  }

  if (fido_assert_allow_cred(assert, kh, kh_len) != FIDO_OK) {
    goto err;
  }

  if (fido_assert_set_clientdata_hash(assert, cdh, 32) != FIDO_OK) {
    goto err;
  }

  if (fido_assert_set_uv(assert, uv) != FIDO_OK) {
    goto err;
  }

  if (fido_assert_set_extensions(assert, FIDO_EXT_HMAC_SECRET) != FIDO_OK) {
    goto err;
  }

  if (fido_assert_set_hmac_salt(assert, salt, HMAC_SALT_SIZE) != FIDO_OK) {
    goto err;
  }

  if (fido_dev_get_assert(dev, assert, pin) != FIDO_OK) {
    goto err;
  }

  if (fido_assert_count(assert) != 1) {
    goto err;
  }

  if (fido_assert_verify(assert, 0, fido_cred_type(cred),
                         fido_cred_pubkey_ptr(cred)) != FIDO_OK) {
    goto err;
  }

  if ((hmac_secret = fido_assert_hmac_secret_ptr(assert, 0)) == NULL) {
    goto err;
  }

  if ((hmac_secret_len = fido_assert_hmac_secret_len(assert, 0)) !=
      HMAC_SECRET_SIZE) {
    goto err;
  }

  memcpy(secret, hmac_secret, hmac_secret_len);
  retval = 1;

err:
  fido_assert_free(&assert);
  return retval;
}

int generate_encrypted_authtok(fido_dev_t *dev, fido_cred_t *cred,
                               const char *authtok, fido_opt_t uv,
                               const char *pin, unsigned char **enc_authtok,
                               size_t *enc_authtok_len) {
  size_t authtok_len;
  unsigned char key[32];
  int ok = 0;

  authtok_len = strlen(authtok);
  *enc_authtok_len = HMAC_SALT_SIZE + authtok_len + AEAD_TAG_SIZE;
  if ((*enc_authtok = malloc(*enc_authtok_len)) == NULL) {
    goto err;
  }
  if (!random_bytes(*enc_authtok, HMAC_SALT_SIZE)) {
    goto err;
  }
  if (!get_hmac_secret(dev, cred, uv, pin, *enc_authtok, key)) {
    goto err;
  }
  if (!encrypt_authtok((unsigned char *) authtok, authtok_len, key,
                       *enc_authtok + HMAC_SALT_SIZE + authtok_len,
                       *enc_authtok + HMAC_SALT_SIZE)) {
    goto err;
  }
  ok = 1;

err:
  explicit_bzero(key, sizeof(key));
  if (!ok) {
    if (*enc_authtok) {
      explicit_bzero(*enc_authtok, *enc_authtok_len);
      free(*enc_authtok);
      *enc_authtok = NULL;
      *enc_authtok_len = 0;
    }
  }
  return ok;
}
