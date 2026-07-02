#include "transport/packet/header/shorthdr/shorthdr.h"

#include "common/bytes/util/bytes.h"

/* RFC 9000 17.3.1: 0 1 S R R K P P, reserved bits left clear. */
u8 quic_shorthdr_byte0(int spin, int key_phase, u8 pn_len) {
  return (u8)(0x40 | ((spin & 1) << 5) | ((key_phase & 1) << 2) |
              (u8)(pn_len - 1));
}

/* True if pn_len is in range and the header fits in cap. */
static int shorthdr_ok(usz cap, const quic_shorthdr_desc *d) {
  if (d->pn_len < 1 || d->pn_len > 4) return 0;
  return (usz)1 + d->dcid.n + d->pn_len <= cap;
}

/* Write pn as pn_len big-endian bytes at dst (room already checked). */
static void shdr_put_pn(u8 *dst, u64 pn, u8 pn_len) {
  for (u8 i = 0; i < pn_len; i++) dst[i] = (u8)(pn >> ((pn_len - 1 - i) * 8));
}

int quic_shorthdr_build(const quic_shorthdr_desc *d, quic_obuf *out) {
  usz off = 1;
  if (!shorthdr_ok(out->cap, d)) return 0;
  out->p[0] = quic_shorthdr_byte0(d->spin, d->key_phase, d->pn_len);
  quic_put_bytes(out->p, out->cap, &off, d->dcid.p, d->dcid.n); /* room ok */
  shdr_put_pn(out->p + off, d->pn, d->pn_len);
  out->len = off + d->pn_len;
  return 1;
}
