#include "app/qpack/qpack/string.h"

#include "app/qpack/qpack/huffman.h"
#include "app/qpack/qpack/integer.h"
#include "common/bytes/util/bytes.h"

/* The Huffman flag sits in the bit above the 7-bit length prefix. */
#define QPACK_STR_HUFFMAN 0x80

usz quic_qpack_string_encode(quic_mspan buf, quic_span src) {
  quic_qpack_pfx pfx = {7, 0};
  usz            off = quic_qpack_int_encode(buf, pfx, src.n);
  if (off == 0) return 0;
  if (!quic_put_bytes(
          quic_mspan_of(buf.p, buf.n), &off, quic_span_of(src.p, src.n)))
    return 0;
  return off;
}

/* The decoded length header: the octet count, where it starts, and H. */
typedef struct {
  usz off;
  usz len;
  int huff;
} qstr_head;

/* Read the length header. Returns 1 ok, 0 on truncation. */
static int take_header(quic_span buf, qstr_head* h) {
  u64 v;
  usz used;
  if (buf.n == 0) return 0;
  h->huff = (buf.p[0] & QPACK_STR_HUFFMAN) != 0;
  used    = quic_qpack_int_decode(buf, 7, &v);
  if (used == 0) return 0;
  h->off = used;
  h->len = (usz)v;
  return 1;
}

/* H=0: copy the octets into dst. Returns 1 ok, 0 on overflow. */
static int str_raw(quic_span oct, quic_obuf* dst) {
  usz off = 0;
  if (oct.n > dst->cap) return 0;
  if (!quic_take_bytes(
          quic_span_of(oct.p, oct.n), &off, quic_mspan_of(dst->p, oct.n)))
    return 0;
  dst->len = oct.n;
  return 1;
}

/* Recover the value octets per the H flag (RFC 7541 5.2): H=1 is Huffman,
 * H=0 is raw. Truncated source octets fail either way. Returns 1 ok, 0. */
static int str_value(quic_span buf, const qstr_head* h, quic_obuf* dst) {
  if (h->off + h->len > buf.n) return 0;
  quic_span oct = quic_span_of(buf.p + h->off, h->len);
  return h->huff ? quic_qpack_huffman_decode(oct, dst) : str_raw(oct, dst);
}

usz quic_qpack_string_decode(quic_span buf, quic_obuf* dst) {
  qstr_head h;
  if (!take_header(buf, &h)) return 0;
  if (!str_value(buf, &h, dst)) return 0;
  return h.off + h.len;
}
