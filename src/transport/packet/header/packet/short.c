#include "transport/packet/header/packet/short.h"

#include "common/bytes/util/bytes.h"

/* True if the short header arguments are in range and fit in cap. */
static int short_ok(usz cap, const quic_short_desc *d) {
  if (d->pn_len < 1 || d->pn_len > 4) return 0;
  return 1 + d->dcid.n + d->pn_len <= cap;
}

/* RFC 9000 17.3.1: fixed bit, latency spin, key phase, packet number length. */
static u8 short_byte0(u8 spin, u8 key_phase, usz pn_len) {
  return 0x40 | (u8)((spin & 1) << 5) | (u8)((key_phase & 1) << 2) |
         (u8)(pn_len - 1);
}

/* Write pn as pn_len big-endian bytes at dst (room already checked). */
static void put_pn(u8 *dst, u64 pn, usz pn_len) {
  for (usz i = 0; i < pn_len; i++) dst[i] = (u8)(pn >> ((pn_len - 1 - i) * 8));
}

usz quic_short_build(u8 *buf, usz cap, const quic_short_desc *d) {
  usz off = 1;
  if (!short_ok(cap, d)) return 0;
  buf[0] = short_byte0(d->spin, d->key_phase, d->pn_len);
  quic_put_bytes(buf, cap, &off, d->dcid.p, d->dcid.n); /* room checked */
  put_pn(buf + off, d->pn, d->pn_len);
  return off + d->pn_len;
}
