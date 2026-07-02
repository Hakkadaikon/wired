#include "app/qpack/qpack/integer.h"

/* The all-ones prefix value 2^prefix_bits - 1, the threshold that triggers the
 * continuation encoding (RFC 7541 5.1). */
static u64 prefix_max(u8 prefix_bits) { return ((u64)1 << prefix_bits) - 1; }

/* Append one byte, advancing o->len. Returns 1 ok, 0 if no room. */
static int put_byte(quic_obuf *o, u8 b) {
  if (o->len >= o->cap) return 0;
  o->p[o->len++] = b;
  return 1;
}

/* A continuation group needs the high bit when 7 or more bits remain. */
static int more_groups(u64 v) { return v >= 0x80; }

/* Write the trailing 7-bit continuation groups for v, all but the last
 * carrying the high bit. v is already reduced by prefix_max. Returns 1/0. */
static int put_groups(quic_obuf *o, u64 v) {
  int ok = 1;
  while (more_groups(v)) {
    ok = put_byte(o, (u8)(v & 0x7f) | 0x80);
    v >>= 7;
  }
  return put_byte(o, (u8)v) && ok;
}

/* The value carried in the prefix byte: the value itself, or all-ones. */
static u8 prefix_byte(u64 value, u64 pmax) {
  if (value < pmax) return (u8)value;
  return (u8)pmax;
}

/* Encode the body after the prefix byte: nothing if value fit, else groups. */
static int encode_body(quic_obuf *o, u64 value, u64 pmax) {
  if (value < pmax) return 1;
  return put_groups(o, value - pmax);
}

usz quic_qpack_int_encode(quic_mspan buf, quic_qpack_pfx pfx, u64 value) {
  quic_obuf o    = quic_obuf_of(buf.p, buf.n);
  u64       pmax = prefix_max(pfx.bits);
  if (!put_byte(&o, pfx.pattern | prefix_byte(value, pmax))) return 0;
  if (!encode_body(&o, value, pmax)) return 0;
  return o.len;
}

/* Decode cursor: the input bytes, the read offset, and the accumulator. */
typedef struct {
  quic_span in;
  usz       off;
  u64      *value;
} qint_cursor;

/* One decoded group: read a byte, fold its 7 bits in at shift m, report end. */
static int take_group(qint_cursor *c, u64 m, int *go) {
  u8 b;
  if (c->off >= c->in.n || m > 56) return 0;
  b = c->in.p[c->off++];
  *c->value += (u64)(b & 0x7f) << m;
  *go = (b & 0x80) != 0;
  return 1;
}

/* Accumulate the 7-bit continuation groups into the value. Returns 1 ok, 0 on
 * truncation or 64-bit overflow. */
static int take_groups(qint_cursor *c) {
  int go = 1, ok = 1;
  for (u64 m = 0; go && ok; m += 7) ok = take_group(c, m, &go);
  return ok;
}

/* Decode the body after the prefix value: done if it fit, else read groups. */
static usz decode_body(qint_cursor *c, u64 pmax) {
  if (*c->value < pmax) return c->off;
  if (!take_groups(c)) return 0;
  return c->off;
}

usz quic_qpack_int_decode(quic_span buf, u8 prefix_bits, u64 *value) {
  u64         pmax = prefix_max(prefix_bits);
  qint_cursor c    = {buf, 1, value};
  if (buf.n == 0) return 0;
  *value = buf.p[0] & pmax;
  return decode_body(&c, pmax);
}
