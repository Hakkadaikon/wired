#include "tls/ext/grease/grease.h"

#include "common/bytes/varint/varint.h"

usz quic_grease_encode(u8 *buf, usz cap) {
  usz off = 0;
  if (!quic_varint_put(quic_mspan_of(buf, cap), &off, QUIC_TP_GREASE_QUIC_BIT)) return 0;
  if (!quic_varint_put(quic_mspan_of(buf, cap), &off, 0)) return 0; /* empty value */
  return off;
}

/* Read the id varint and require it to be the grease_quic_bit id. */
static int take_grease_id(const u8 *buf, usz n, usz *off) {
  u64 id;
  if (!quic_varint_take(quic_span_of(buf, n), off, &id)) return 0;
  return id == QUIC_TP_GREASE_QUIC_BIT;
}

/* Read id then length; require the grease id and an empty value. */
static int take_grease(const u8 *buf, usz n, usz *off) {
  u64 len;
  if (!take_grease_id(buf, n, off)) return 0;
  if (!quic_varint_take(quic_span_of(buf, n), off, &len)) return 0;
  return len == 0; /* a non-empty value is a TRANSPORT_PARAMETER_ERROR */
}

usz quic_grease_decode(const u8 *buf, usz n) {
  usz off = 0;
  if (!take_grease(buf, n, &off)) return 0;
  return off;
}

int quic_grease_accept_byte0(u8 byte0, int peer_greases) {
  if (peer_greases) return 1;          /* any QUIC Bit value is acceptable */
  return (byte0 & QUIC_BIT_MASK) != 0; /* otherwise the bit must be set */
}
