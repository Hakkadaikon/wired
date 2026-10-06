#include "app/http3/server/srvrun/httpx.h"

#include "common/bytes/text/text.h"
#include "common/fmt/fmt.h"

int wired_http_reply_text(
    wired_http_exchange* x, u16 status, const char* text) {
  x->status       = status;
  x->content_type = "text/plain";
  wired_obuf_printf(x->body, "%s", text);
  return 1;
}

int wired_http_add_field(
    wired_http_exchange* x, const char* name, const char* value) {
  if (x->field_count >= WIRED_HTTP_MAX_FIELDS) return 0;
  x->fields[x->field_count++] =
      (wired_http_field){wired_span_cstr(name), wired_span_cstr(value)};
  return 1;
}
