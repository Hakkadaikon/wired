#include "test.h"

/* token_is_retry tells a Retry-tagged token from a NEW_TOKEN one and from an
 * empty token (RFC 9000 8.1.1/8.1.3). */
static void test_tokentype_is_retry(void) {
  static const u8 retry[] = {TOKEN_TAG_RETRY, 0xAA, 0xBB};
  static const u8 fresh[] = {TOKEN_TAG_NEWTOKEN, 0xAA, 0xBB};
  CHECK(token_is_retry(retry, sizeof retry) == 1);
  CHECK(token_is_retry(retry, 1) == 1); /* tag byte alone */
  CHECK(token_is_retry(fresh, sizeof fresh) == 0);
  CHECK(token_is_retry((const u8*)0, 0) == 0);
}

void test_tokentype(void) { test_tokentype_is_retry(); }
