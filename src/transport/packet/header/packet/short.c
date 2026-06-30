#include "transport/packet/header/packet/short.h"

#include "common/bytes/util/bytes.h"

/* True if the short header arguments are in range and fit in cap. */
static int short_ok(usz cap, u8 dcid_len, usz pn_len) {
  if (pn_len < 1 || pn_len > 4) return 0;
  return 1 + (usz)dcid_len + pn_len <= cap;
}

/* RFC 9000 17.3.1: fixed bit, latency spin, key phase, packet number length. */
static u8 short_byte0(u8 spin, u8 key_phase, usz pn_len) {
  return 0x40 | (u8)((spin & 1) << 5) | (u8)((key_phase & 1) << 2) |
         (u8)(pn_len - 1);
}

/* Write pn as pn_len big-endian bytes at *off (room already checked). */
static void put_pn(u8 *buf, usz *off, u64 pn, usz pn_len) {
  for (usz i = 0; i < pn_len; i++)
    buf[*off + i] = (u8)(pn >> ((pn_len - 1 - i) * 8));
  *off += pn_len;
}

usz quic_short_build(
    u8       *buf,
    usz       cap,
    const u8 *dcid,
    u8        dcid_len,
    u8        spin,
    u8        key_phase,
    u64       pn,
    usz       pn_len) {
  usz off = 1;
  if (!short_ok(cap, dcid_len, pn_len)) return 0;
  buf[0] = short_byte0(spin, key_phase, pn_len);
  quic_put_bytes(buf, cap, &off, dcid, dcid_len); /* room checked above */
  put_pn(buf, &off, pn, pn_len);
  return off;
}
