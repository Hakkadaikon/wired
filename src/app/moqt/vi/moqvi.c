#include "app/moqt/vi/moqvi.h"

/* draft-ietf-moq-transport-19 1.4.1: length k has 7k usable bits for
 * k = 1..8 and 64 for k = 9; the first byte carries k-1 leading 1 bits,
 * then a 0 (k <= 8), then the top value bits. */

/* Leading-1-bit prefix of the first byte, indexed by encoded length. */
static const u8 moqvi_prefix[10] = {0,    0x00, 0x80, 0xC0, 0xE0,
                                    0xF0, 0xF8, 0xFC, 0xFE, 0xFF};

usz quic_moqvi_len(u64 v) {
  usz k = 1;
  while (k < 9 && (v >> (7 * k)) != 0) k++;
  return k;
}

/* Write the low n bytes of v big-endian into buf (v < 2^(8n) effective;
 * for n = 9 the top byte is 0 and later carries the 0xFF prefix). */
static void moqvi_store_be(u8* buf, u64 v, usz n) {
  usz i = n;
  while (i-- > 0) {
    buf[i] = (u8)(v & 0xFF);
    v >>= 8;
  }
}

usz quic_moqvi_encode(u8* buf, u64 v) {
  usz n = quic_moqvi_len(v);
  moqvi_store_be(buf, v, n);
  buf[0] |= moqvi_prefix[n];
  return n;
}

/* Encoded length from the first byte: leading 1 bits + 1. */
static usz moqvi_hdr_len(u8 b) {
  usz k = 1;
  while (b & 0x80) {
    k++;
    b = (u8)(b << 1);
  }
  return k;
}

/* Read n big-endian bytes; the first byte's n prefix bits are masked off
 * (0xFF >> n leaves its value bits; 0 for n >= 8). */
static u64 moqvi_get_be(const u8* buf, usz n) {
  u64 v = buf[0] & (u8)(0xFF >> n);
  for (usz i = 1; i < n; i++) v = (v << 8) | buf[i];
  return v;
}

usz quic_moqvi_decode(const u8* buf, usz n, u64* out) {
  usz need;
  if (n == 0) return 0;
  need = moqvi_hdr_len(buf[0]);
  if (n < need) return 0;
  *out = moqvi_get_be(buf, need);
  return need;
}

int quic_moqvi_take(wired_span buf, usz* off, u64* out) {
  usz used = quic_moqvi_decode(buf.p + *off, buf.n - *off, out);
  if (used == 0) return 0;
  *off += used;
  return 1;
}

int quic_moqvi_put(wired_mspan buf, usz* off, u64 v) {
  usz need = quic_moqvi_len(v);
  if (*off + need > buf.n) return 0;
  *off += quic_moqvi_encode(buf.p + *off, v);
  return 1;
}
