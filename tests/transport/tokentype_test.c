#include "test.h"

static void test_tokentype_retry(void) {
  u8         body[] = {0xAA, 0xBB};
  u8         out[8];
  wired_obuf ob = obuf_of(out, sizeof(out));
  usz        w  = token_tag_retry(&ob, wired_span_of(body, sizeof(body)));
  CHECK(w == 1 + sizeof(body));
  CHECK(out[0] == TOKEN_TAG_RETRY && out[1] == 0xAA && out[2] == 0xBB);
  CHECK(token_is_retry(out, w) == 1);
}

static void test_tokentype_newtoken(void) {
  u8         body[] = {0xAA, 0xBB};
  u8         out[8];
  wired_obuf ob = obuf_of(out, sizeof(out));
  usz        w  = token_tag_newtoken(&ob, wired_span_of(body, sizeof(body)));
  CHECK(out[0] == TOKEN_TAG_NEWTOKEN);
  CHECK(token_is_retry(out, w) == 0);
}

static void test_tokentype_empty(void) {
  u8         out[4];
  wired_obuf ob = obuf_of(out, sizeof(out));
  /* an empty token is neither tag; is_retry must be false */
  CHECK(token_is_retry((const u8*)0, 0) == 0);
  /* tag with empty body still writes the tag byte */
  CHECK(token_tag_retry(&ob, wired_span_of((const u8*)0, 0)) == 1);
  CHECK(token_is_retry(out, 1) == 1);
  /* no room */
  wired_obuf ob0 = obuf_of(out, 0);
  CHECK(token_tag_retry(&ob0, wired_span_of((const u8*)0, 0)) == 0);
  /* room for the tag byte but not the 4-byte body */
  {
    static const u8 body[4] = {1, 2, 3, 4};
    wired_obuf      ob2     = obuf_of(out, 2);
    CHECK(token_tag_newtoken(&ob2, wired_span_of(body, 4)) == 0);
    CHECK(ob2.len == 0);
  }
}

void test_tokentype(void) {
  test_tokentype_retry();
  test_tokentype_newtoken();
  test_tokentype_empty();
}
