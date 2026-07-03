#include "crypto/pki/cert/selfcert/derenc.h"

#include "common/bytes/util/bytes.h"

/* X.690 8.1.3. Length-field octet count for len: 1 short, 2 (0x81), 3 (0x82).
 * 0 if len exceeds the supported 0x82 long-form ceiling (65535). */
static usz len_octets(usz len) {
  static const usz cap[] = {0x80, 0x100, 0x10000};
  for (usz i = 0; i < 3; i++)
    if (len < cap[i]) return i + 1;
  return 0;
}

/* Write nb big-endian length octets of len at out. */
static void der_put_be(u8 *out, usz nb, usz len) {
  for (usz i = 0; i < nb; i++) out[i] = (u8)(len >> ((nb - 1 - i) * 8));
}

/* X.690 8.1.3. Write the length field for len at out (lo octets total).
 * Short form (lo==1): one octet. Long form: 0x80+nb lead then nb octets. */
static void der_put_len(u8 *out, usz lo, usz len) {
  if (lo == 1) {
    der_put_be(out, 1, len);
    return;
  }
  out[0] = (u8)(0x80 + (lo - 1));
  der_put_be(out + 1, lo - 1, len);
}

int quic_selfcert_der_tlv(u8 tag, quic_span val, quic_obuf *out) {
  usz lo = len_octets(val.n), off = 0;
  if (lo == 0) return 0;
  if (1 + lo + val.n > out->cap) return 0;
  out->p[off++] = tag;
  der_put_len(out->p + off, lo, val.n);
  off += lo;
  quic_put_bytes(quic_mspan_of(out->p, out->cap), &off, quic_span_of(val.p, val.n));
  out->len = off;
  return 1;
}
