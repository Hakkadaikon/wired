#include "app/qpack/qpack/prefix.h"

#include "app/qpack/qpack/integer.h"

/* The Sign bit is the high bit of the Delta Base byte, above its 7-bit prefix.
 */
#define PREFIX_SIGN_BIT 0x80

/* The Delta Base prefix byte's high bits: PREFIX_SIGN_BIT when sign is set. */
static u8 sign_prefix(u8 sign) { return sign ? PREFIX_SIGN_BIT : 0; }

/* off + w, or 0 if either is 0 (an empty second field means failure). */
static usz prefix_join(usz off, usz w) { return (off && w) ? off + w : 0; }

usz quic_qpack_prefix_encode(u8* buf, usz cap, const quic_qpack_prefix* p) {
  quic_qpack_pfx ric = {8, 0};
  usz            off = quic_qpack_int_encode(
      quic_mspan_of(buf, cap), ric, p->required_insert_count);
  quic_qpack_pfx db = {7, sign_prefix(p->sign)};
  usz            w  = off ? quic_qpack_int_encode(
                    quic_mspan_of(buf + off, cap - off), db, p->delta_base)
                          : 0;
  return prefix_join(off, w);
}

usz quic_qpack_prefix_decode(const u8* buf, usz n, quic_qpack_prefix* p) {
  usz off =
      quic_qpack_int_decode(quic_span_of(buf, n), 8, &p->required_insert_count);
  if (off == 0) return 0;
  p->sign = (buf[off] & PREFIX_SIGN_BIT) ? 1 : 0;
  return prefix_join(
      off, quic_qpack_int_decode(
               quic_span_of(buf + off, n - off), 7, &p->delta_base));
}
