#include "app/qpack/qpack/literal.h"

#include "app/qpack/qpack/huffman.h"
#include "app/qpack/qpack/integer.h"
#include "app/qpack/qpack/string.h"
#include "common/bytes/util/bytes.h"

/* RFC 9204 4.5.4 first-byte bits. */
#define QPACK_NAMREF 0x40
#define QPACK_NAMREF_N 0x20
#define QPACK_NAMREF_T 0x10
/* RFC 9204 4.5.6 first-byte bits. */
#define QPACK_LITNAME 0x20
#define QPACK_LITNAME_N 0x10
#define QPACK_LITNAME_H 0x08

/* off + w, or 0 if either is 0 (an empty field means failure). */
static usz join(usz off, usz w) { return (off && w) ? off + w : 0; }

/* A first byte's flag bit as a 0/1 int. */
static int flag(u8 b, u8 mask) { return (b & mask) ? 1 : 0; }

/* mask if set, else 0: a flag selected into the first byte's high bits. */
static u8 bit(int set, u8 mask) { return set ? mask : 0; }

/* The buffer past its first off bytes, as a decode view. */
static quic_span tail_span(quic_span buf, usz off) {
  return quic_span_of(buf.p + off, buf.n - off);
}

/* After the header (off bytes), decode the trailing value string into val.
 * Returns total bytes, or 0 if the header failed or the value did not fit. */
static usz decode_value(quic_span buf, usz off, quic_obuf *val) {
  usz w = off ? quic_qpack_string_decode(tail_span(buf, off), val) : 0;
  return join(off, w);
}

/* Append the value string after the off-byte header already in buf. */
static usz encode_value(quic_mspan buf, usz off, quic_span value) {
  usz w = off ? quic_qpack_string_encode(
                    quic_mspan_of(buf.p + off, buf.n - off), value)
              : 0;
  return join(off, w);
}

/* High bits of the name-reference first byte for the given flags. */
static u8 namref_prefix(const quic_qpack_nameref *r) {
  return QPACK_NAMREF | bit(r->never, QPACK_NAMREF_N) |
         bit(r->is_static, QPACK_NAMREF_T);
}

usz quic_qpack_literal_namref_encode(
    quic_mspan buf, const quic_qpack_nameref *r, quic_span value) {
  quic_qpack_pfx pfx = {4, namref_prefix(r)};
  usz            off = quic_qpack_int_encode(buf, pfx, r->index);
  return encode_value(buf, off, value);
}

/* RFC 9204 4.5.4: bit 6 set marks a name-reference field line. */
static int is_namref(quic_span buf) {
  return buf.n != 0 && (buf.p[0] & 0xc0) == QPACK_NAMREF;
}

usz quic_qpack_literal_namref_decode(
    quic_span buf, quic_qpack_nameref *r, quic_obuf *val) {
  usz off;
  if (!is_namref(buf)) return 0;
  r->never     = flag(buf.p[0], QPACK_NAMREF_N);
  r->is_static = flag(buf.p[0], QPACK_NAMREF_T);
  off          = quic_qpack_int_decode(buf, 4, &r->index);
  return decode_value(buf, off, val);
}

/* Encode the 4.5.6 name: 3-bit prefixed length (H=0) then the name octets. */
static usz litname_name_encode(quic_mspan buf, int never, quic_span name) {
  quic_qpack_pfx pfx = {3, QPACK_LITNAME | bit(never, QPACK_LITNAME_N)};
  usz            off = quic_qpack_int_encode(buf, pfx, name.n);
  if (off == 0) return 0;
  if (!quic_put_bytes(quic_mspan_of(buf.p, buf.n), &off, quic_span_of(name.p, name.n))) return 0;
  return off;
}

usz quic_qpack_literal_name_encode(
    quic_mspan buf, int never, const quic_qpack_field *f) {
  usz off = litname_name_encode(buf, never, f->name);
  return encode_value(buf, off, f->value);
}

/* RFC 9204 4.5.6: top three bits 001 mark a literal-name field line. The H
 * bit (name Huffman) is read separately and both H=0 and H=1 are accepted. */
static int is_litname(quic_span buf) {
  return buf.n != 0 && (buf.p[0] & 0xe0) == QPACK_LITNAME;
}

/* H=0: copy the name octets into nm. Returns 1 ok, 0 on overflow. */
static int name_raw(quic_span oct, quic_obuf *nm) {
  usz off = 0;
  if (oct.n > nm->cap) return 0;
  if (!quic_take_bytes(quic_span_of(oct.p, oct.n), &off, quic_mspan_of(nm->p, oct.n))) return 0;
  nm->len = oct.n;
  return 1;
}

/* Recover the name octets per the H flag (RFC 7541 5.2): H=1 is Huffman, H=0
 * is raw. Returns 1 ok, 0. */
static int name_octets(quic_span oct, int huff, quic_obuf *nm) {
  return huff ? quic_qpack_huffman_decode(oct, nm) : name_raw(oct, nm);
}

/* The name length header parsed and its octets in range. */
static int litname_bounds(usz off, u64 len, usz n) {
  return off != 0 && off + len <= n;
}

/* Decode the 4.5.6 name into nm. Returns bytes used from buf, or 0 on
 * truncation or overflow. huff is the first byte's H flag. */
static usz litname_name_decode(quic_span buf, int huff, quic_obuf *nm) {
  u64 len;
  usz off = quic_qpack_int_decode(buf, 3, &len);
  if (!litname_bounds(off, len, buf.n)) return 0;
  if (!name_octets(quic_span_of(buf.p + off, (usz)len), huff, nm)) return 0;
  return off + (usz)len;
}

usz quic_qpack_literal_name_decode(
    quic_span buf, int *never, quic_qpack_fieldbuf *out) {
  usz off;
  if (!is_litname(buf)) return 0;
  *never = flag(buf.p[0], QPACK_LITNAME_N);
  off = litname_name_decode(buf, flag(buf.p[0], QPACK_LITNAME_H), &out->name);
  return decode_value(buf, off, &out->value);
}
