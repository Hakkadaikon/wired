#include "app/http3/core/capsule/capsule.h"

#include "common/bytes/varint/varint.h"

/* Remaining writable capacity of out, as an mspan starting right after the
 * bytes already written (out->p[out->len .. out->cap)). */
static quic_mspan capsule_out_tail(quic_obuf* out) {
  return quic_mspan_of(out->p + out->len, out->cap - out->len);
}

/* Total encoded size (type varint + length varint + value bytes), or 0 if
 * type/length is out of varint range. */
static usz capsule_wire_size(u64 type, quic_span value) {
  usz type_len = quic_varint_len(type);
  usz len_len  = quic_varint_len(value.n);
  if (type_len == 0 || len_len == 0) return 0;
  return type_len + len_len + value.n;
}

/* 1 iff `total` encoded bytes fit in out's remaining capacity. Computed
 * before any write so a too-small out is rejected without touching a
 * single byte of it. */
static int capsule_fits(const quic_obuf* out, usz total) {
  return total > 0 && out->len <= out->cap && total <= out->cap - out->len;
}

static void capsule_write(quic_obuf* out, u64 type, quic_span value, usz total) {
  usz        off  = 0;
  quic_mspan tail = capsule_out_tail(out);
  quic_varint_put(tail, &off, type);
  quic_varint_put(tail, &off, value.n);
  for (usz i = 0; i < value.n; i++) tail.p[off + i] = value.p[i];
  out->len += total;
}

int quic_capsule_encode(quic_obuf* out, u64 type, quic_span value) {
  usz total = capsule_wire_size(type, value);
  if (!capsule_fits(out, total)) return 0;
  capsule_write(out, type, value, total);
  return 1;
}

/* Decode the Type and Length varints at data+*at. On success, sets *type,
 * *len (declared Capsule Length) and *consumed (bytes used by the two
 * varints, i.e. where the Value begins relative to *at). Returns 0 if
 * either varint is truncated. */
static int capsule_header_read(quic_span data, usz at, u64* type, u64* len, usz* consumed) {
  usz off = at;
  if (!quic_varint_take(data, &off, type)) return 0;
  if (!quic_varint_take(data, &off, len)) return 0;
  *consumed = off - at;
  return 1;
}

int quic_capsule_decode(quic_span data, usz* at, u64* type, quic_span* value) {
  u64 t;
  u64 len;
  usz consumed;
  usz value_start;
  if (!capsule_header_read(data, *at, &t, &len, &consumed)) return 0;
  value_start = *at + consumed;
  if (len > data.n - value_start) return 0;
  *type  = t;
  *value = quic_span_of(data.p + value_start, len);
  *at    = value_start + len;
  return 1;
}
