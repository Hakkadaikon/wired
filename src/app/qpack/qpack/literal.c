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

/* After the header (off bytes), decode the trailing value string into val.
 * Returns total bytes, or 0 if the header failed or the value did not fit. */
static usz decode_value(
    const u8 *buf, usz n, usz off, u8 *val, usz vcap, usz *vlen) {
  usz w =
      off ? quic_qpack_string_decode(buf + off, n - off, val, vcap, vlen) : 0;
  return join(off, w);
}

/* High bits of the name-reference first byte for the given flags. */
static u8 namref_prefix(int is_static, int never) {
  return QPACK_NAMREF | bit(never, QPACK_NAMREF_N) |
         bit(is_static, QPACK_NAMREF_T);
}

usz quic_qpack_literal_namref_encode(
    u8       *buf,
    usz       cap,
    u64       index,
    int       is_static,
    int       never,
    const u8 *value,
    usz       vlen) {
  usz off = quic_qpack_int_encode(
      buf, cap, 4, namref_prefix(is_static, never), index);
  usz w = off ? quic_qpack_string_encode(buf + off, cap - off, value, vlen) : 0;
  return join(off, w);
}

/* RFC 9204 4.5.4: bit 6 set marks a name-reference field line. */
static int is_namref(const u8 *buf, usz n) {
  return n != 0 && (buf[0] & 0xc0) == QPACK_NAMREF;
}

usz quic_qpack_literal_namref_decode(
    const u8 *buf,
    usz       n,
    u64      *index,
    int      *is_static,
    int      *never,
    u8       *val,
    usz       vcap,
    usz      *vlen) {
  usz off;
  if (!is_namref(buf, n)) return 0;
  *never     = flag(buf[0], QPACK_NAMREF_N);
  *is_static = flag(buf[0], QPACK_NAMREF_T);
  off        = quic_qpack_int_decode(buf, n, 4, index);
  return decode_value(buf, n, off, val, vcap, vlen);
}

/* Encode the 4.5.6 name: 3-bit prefixed length (H=0) then nlen octets. */
static usz litname_name_encode(
    u8 *buf, usz cap, int never, const u8 *name, usz nlen) {
  u8  hi  = QPACK_LITNAME | bit(never, QPACK_LITNAME_N);
  usz off = quic_qpack_int_encode(buf, cap, 3, hi, nlen);
  if (off == 0) return 0;
  if (!quic_put_bytes(buf, cap, &off, name, nlen)) return 0;
  return off;
}

usz quic_qpack_literal_name_encode(
    u8       *buf,
    usz       cap,
    int       never,
    const u8 *name,
    usz       nlen,
    const u8 *value,
    usz       vlen) {
  usz off = litname_name_encode(buf, cap, never, name, nlen);
  usz w = off ? quic_qpack_string_encode(buf + off, cap - off, value, vlen) : 0;
  return join(off, w);
}

/* RFC 9204 4.5.6: top three bits 001 mark a literal-name field line. The H
 * bit (name Huffman) is read separately and both H=0 and H=1 are accepted. */
static int is_litname(const u8 *buf, usz n) {
  return n != 0 && (buf[0] & 0xe0) == QPACK_LITNAME;
}

/* H=0: copy len name octets at off into nm, bounded by ncap. Returns 1 ok, 0.
 */
static int name_raw(
    const u8 *buf, usz n, usz off, u8 *nm, usz ncap, u64 len, usz *nlen) {
  if (len > ncap || !quic_take_bytes(buf, n, &off, nm, (usz)len)) return 0;
  *nlen = (usz)len;
  return 1;
}

/* Recover the name octets per the H flag (RFC 7541 5.2): H=1 is Huffman, H=0
 * is raw. Truncated source octets fail either way. Returns 1 ok, 0. */
static int name_octets(
    const u8 *buf,
    usz       n,
    usz       off,
    int       huff,
    u8       *nm,
    usz       ncap,
    u64       len,
    usz      *nlen) {
  if (off + len > n) return 0;
  return huff ? quic_qpack_huffman_decode(buf + off, len, nm, ncap, nlen)
              : name_raw(buf, n, off, nm, ncap, len, nlen);
}

/* Decode the 4.5.6 name into nm (ncap), length to *nlen. Returns bytes used
 * from buf, or 0 on truncation or overflow. huff is the first byte's H flag. */
static usz litname_name_decode(
    const u8 *buf, usz n, int huff, u8 *nm, usz ncap, usz *nlen) {
  u64 len;
  usz off = quic_qpack_int_decode(buf, n, 3, &len);
  if (off == 0) return 0;
  if (!name_octets(buf, n, off, huff, nm, ncap, len, nlen)) return 0;
  return off + (usz)len;
}

usz quic_qpack_literal_name_decode(
    const u8 *buf,
    usz       n,
    int      *never,
    u8       *nm,
    usz       ncap,
    usz      *nlen,
    u8       *val,
    usz       vcap,
    usz      *vlen) {
  usz off;
  if (!is_litname(buf, n)) return 0;
  *never = flag(buf[0], QPACK_LITNAME_N);
  off    = litname_name_decode(
      buf, n, flag(buf[0], QPACK_LITNAME_H), nm, ncap, nlen);
  return decode_value(buf, n, off, val, vcap, vlen);
}
