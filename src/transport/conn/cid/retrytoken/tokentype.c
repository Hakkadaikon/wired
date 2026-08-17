#include "transport/conn/cid/retrytoken/tokentype.h"

#include "common/bytes/util/bytes.h"

/* RFC 9000 8.1.1/8.1.3: prefix the body with one type-tag byte. */
static usz tag(wired_obuf* out, u8 t, wired_span body) {
  usz off = 1;
  if (out->cap < 1) return 0;
  out->p[0] = t;
  if (!bytes_put(
          wired_mspan_of(out->p, out->cap), &off,
          wired_span_of(body.p, body.n)))
    return 0;
  out->len = off;
  return off;
}

usz token_tag_retry(wired_obuf* out, wired_span body) {
  return tag(out, TOKEN_TAG_RETRY, body);
}

usz token_tag_newtoken(wired_obuf* out, wired_span body) {
  return tag(out, TOKEN_TAG_NEWTOKEN, body);
}

int token_is_retry(const u8* token, usz len) {
  return len > 0 && token[0] == TOKEN_TAG_RETRY;
}
