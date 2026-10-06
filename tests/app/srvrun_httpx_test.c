#include <string.h>

#include "app/http3/server/srvrun/httpx.h"
#include "test.h"

/* reply_text: status, text/plain, body appended; returns 1. */
static void test_srvrun_httpx_reply_text(void) {
  u8                  raw[16];
  wired_obuf          b = obuf_of(raw, sizeof raw);
  wired_http_exchange x = {0};
  x.body                = &b;
  CHECK(wired_http_reply_text(&x, 404, "not found") == 1);
  CHECK(x.status == 404 && strcmp(x.content_type, "text/plain") == 0);
  CHECK(b.len == 9 && memcmp(raw, "not found", 9) == 0);
}

/* add_field appends in order; boundary: a full table refuses the next. */
static void test_srvrun_httpx_add_field(void) {
  wired_http_exchange x = {0};
  CHECK(wired_http_add_field(&x, "location", "/target"));
  CHECK(x.field_count == 1 && x.fields[0].name.n == 8);
  CHECK(memcmp(x.fields[0].value.p, "/target", 7) == 0);
  while (x.field_count < WIRED_HTTP_MAX_FIELDS)
    CHECK(wired_http_add_field(&x, "x-a", "1"));
  CHECK(!wired_http_add_field(&x, "x-b", "2"));
  CHECK(x.field_count == WIRED_HTTP_MAX_FIELDS);
}

void test_srvrun_httpx(void) {
  test_srvrun_httpx_reply_text();
  test_srvrun_httpx_add_field();
}
