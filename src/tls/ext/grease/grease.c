#include "tls/ext/grease/grease.h"

#include "common/bytes/varint/varint.h"

usz grease_encode(u8* buf, usz cap) {
  usz off = 0;
  if (!varint_put(wired_mspan_of(buf, cap), &off, TP_GREASE_QUIC_BIT)) {
    return 0;
  }
  if (!varint_put(wired_mspan_of(buf, cap), &off, 0)) {
    return 0; /* empty value */
  }
  return off;
}
