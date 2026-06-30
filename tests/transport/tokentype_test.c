#include "test.h"

static void test_tokentype_retry(void) {
  u8  body[] = {0xAA, 0xBB};
  u8  out[8];
  usz w = quic_token_tag_retry(out, sizeof(out), body, sizeof(body));
  CHECK(w == 1 + sizeof(body));
  CHECK(out[0] == QUIC_TOKEN_TAG_RETRY && out[1] == 0xAA && out[2] == 0xBB);
  CHECK(quic_token_is_retry(out, w) == 1);
}

static void test_tokentype_newtoken(void) {
  u8  body[] = {0xAA, 0xBB};
  u8  out[8];
  usz w = quic_token_tag_newtoken(out, sizeof(out), body, sizeof(body));
  CHECK(out[0] == QUIC_TOKEN_TAG_NEWTOKEN);
  CHECK(quic_token_is_retry(out, w) == 0);
}

static void test_tokentype_empty(void) {
  u8 out[4];
  /* an empty token is neither tag; is_retry must be false */
  CHECK(quic_token_is_retry((const u8 *)0, 0) == 0);
  /* tag with empty body still writes the tag byte */
  CHECK(quic_token_tag_retry(out, sizeof(out), (const u8 *)0, 0) == 1);
  CHECK(quic_token_is_retry(out, 1) == 1);
  /* no room */
  CHECK(quic_token_tag_retry(out, 0, (const u8 *)0, 0) == 0);
}

void test_tokentype(void) {
  test_tokentype_retry();
  test_tokentype_newtoken();
  test_tokentype_empty();
}
