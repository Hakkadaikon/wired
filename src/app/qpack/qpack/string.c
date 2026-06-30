#include "app/qpack/qpack/string.h"

#include "app/qpack/qpack/huffman.h"
#include "app/qpack/qpack/integer.h"
#include "common/bytes/util/bytes.h"

/* The Huffman flag sits in the bit above the 7-bit length prefix. */
#define QPACK_STR_HUFFMAN 0x80

usz quic_qpack_string_encode(u8 *buf, usz cap, const u8 *src, usz len) {
  usz off = quic_qpack_int_encode(buf, cap, 7, 0, len);
  if (off == 0) return 0;
  if (!quic_put_bytes(buf, cap, &off, src, len)) return 0;
  return off;
}

/* Read the length header. Returns 1 ok, 0 on truncation, setting *huff to
 * the H flag and advancing *off past the length integer. */
static int take_header(const u8 *buf, usz n, usz *off, usz *len, int *huff) {
  u64 v;
  usz used;
  if (n == 0) return 0;
  *huff = (buf[0] & QPACK_STR_HUFFMAN) != 0;
  used  = quic_qpack_int_decode(buf, n, 7, &v);
  if (used == 0) return 0;
  *off = used;
  *len = (usz)v;
  return 1;
}

/* H=0: copy len octets at off into dst, bounded by dcap. Returns 1 ok, 0. */
static int str_raw(
    const u8 *buf, usz n, usz off, u8 *dst, usz dcap, usz len, usz *out_len) {
  if (len > dcap || !quic_take_bytes(buf, n, &off, dst, len)) return 0;
  *out_len = len;
  return 1;
}

/* Recover the value octets per the H flag (RFC 7541 5.2): H=1 is Huffman,
 * H=0 is raw. Truncated source octets fail either way. Returns 1 ok, 0. */
static int str_value(
    const u8 *buf,
    usz       n,
    usz       off,
    int       huff,
    u8       *dst,
    usz       dcap,
    usz       len,
    usz      *out_len) {
  if (off + len > n) return 0;
  return huff ? quic_qpack_huffman_decode(buf + off, len, dst, dcap, out_len)
              : str_raw(buf, n, off, dst, dcap, len, out_len);
}

usz quic_qpack_string_decode(
    const u8 *buf, usz n, u8 *dst, usz dcap, usz *out_len) {
  usz off, len;
  int huff;
  if (!take_header(buf, n, &off, &len, &huff)) return 0;
  if (!str_value(buf, n, off, huff, dst, dcap, len, out_len)) return 0;
  return off + len;
}
