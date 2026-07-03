#include "transport/conn/cid/retrytoken/tokentype.h"

#include "common/bytes/util/bytes.h"

/* RFC 9000 8.1.1/8.1.3: prefix the body with one type-tag byte. */
static usz tag(quic_obuf *out, u8 t, quic_span body) {
  usz off = 1;
  if (out->cap < 1) return 0;
  out->p[0] = t;
  if (!quic_put_bytes(quic_mspan_of(out->p, out->cap), &off, quic_span_of(body.p, body.n))) return 0;
  out->len = off;
  return off;
}

usz quic_token_tag_retry(quic_obuf *out, quic_span body) {
  return tag(out, QUIC_TOKEN_TAG_RETRY, body);
}

usz quic_token_tag_newtoken(quic_obuf *out, quic_span body) {
  return tag(out, QUIC_TOKEN_TAG_NEWTOKEN, body);
}

int quic_token_is_retry(const u8 *token, usz len) {
  return len > 0 && token[0] == QUIC_TOKEN_TAG_RETRY;
}
