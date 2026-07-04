#include "transport/packet/header/packet/inittoken.h"

#include "common/bytes/util/bytes.h"
#include "common/bytes/varint/varint.h"

/* RFC 9000 17.2.2: Token Length(varint) + Token. */
usz quic_inittoken_put(u8* buf, usz cap, quic_span token) {
  usz off = 0;
  if (!quic_varint_put(quic_mspan_of(buf, cap), &off, token.n)) return 0;
  if (!quic_put_bytes(
          quic_mspan_of(buf, cap), &off, quic_span_of(token.p, token.n)))
    return 0;
  return off;
}

/* Read the Token Length varint and bound-check it against the remainder. */
static int take_tlen(quic_span in, usz* off, u64* tlen) {
  if (!quic_varint_take(quic_span_of(in.p, in.n), off, tlen)) return 0;
  return *tlen <= in.n - *off;
}

usz quic_inittoken_get(const u8* buf, usz n, quic_span* token) {
  usz off = 0;
  u64 tlen;
  if (!take_tlen(quic_span_of(buf, n), &off, &tlen)) return 0;
  token->p = tlen ? buf + off : (const u8*)0;
  token->n = (usz)tlen;
  return off + (usz)tlen;
}
