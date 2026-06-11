/*
 *  Copyright (C) 2026 Yubico AB - See COPYING
 */

#undef NDEBUG
#include <assert.h>
#include <string.h>

#include <fido.h>

#include "util.h"

#define ASSERT_REASON_EQ(err, expected)                                       \
  do {                                                                        \
    const char *r = fido_failure_reason(err);                                \
    assert(r != NULL);                                                       \
    assert(!strcmp(r, expected));                                            \
  } while (0)

#define ASSERT_NO_REASON(err) assert(fido_failure_reason(err) == NULL)

int main(void) {
  ASSERT_REASON_EQ(FIDO_ERR_PIN_INVALID, "invalid PIN");
  ASSERT_REASON_EQ(FIDO_ERR_PIN_BLOCKED, "PIN blocked");
  ASSERT_REASON_EQ(FIDO_ERR_PIN_AUTH_BLOCKED, "PIN authentication blocked");
  ASSERT_REASON_EQ(FIDO_ERR_ACTION_TIMEOUT, "touch/action timeout");
  ASSERT_REASON_EQ(FIDO_ERR_UNSUPPORTED_OPTION, "unsupported option");
  ASSERT_REASON_EQ(FIDO_ERR_OPERATION_DENIED, "operation denied");

#ifdef FIDO_ERR_UV_INVALID
  ASSERT_REASON_EQ(FIDO_ERR_UV_INVALID, "user verification failed");
#endif
#ifdef FIDO_ERR_UV_BLOCKED
  ASSERT_REASON_EQ(FIDO_ERR_UV_BLOCKED, "user verification blocked");
#endif

  ASSERT_NO_REASON(FIDO_OK);
  ASSERT_NO_REASON(FIDO_ERR_INTERNAL);
  ASSERT_NO_REASON(FIDO_ERR_NOTFOUND);

  return 0;
}
