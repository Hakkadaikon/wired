#include "crypto/asymmetric/ecc/ecdsasig/der_int.h"

#include "crypto/pki/cert/selfcert/derenc.h"
#include "crypto/pki/encoding/asn1/der.h"

/* SEC1 C.5. Keep stripping while a leading 0x00 is redundant: more octets
 * remain (i < 31) and this one is zero. The last octet is always retained so a
 * zero value encodes as a single 0x00. */
static int der_int_strip_more(const u8 val[32], usz i) {
  return i < 31 && val[i] == 0;
}

/* SEC1 C.5. Index of the first significant octet (minimal big-endian form). */
static usz der_int_strip(const u8 val[32]) {
  usz i = 0;
  while (der_int_strip_more(val, i)) i++;
  return i;
}

/* RFC 5280. A positive INTEGER needs a 0x00 prefix when the top bit is set. */
static int der_int_needs_pad(u8 lead) { return (lead & 0x80) != 0; }

/* Build the INTEGER content (value octets, with optional 0x00 sign prefix) into
 * buf (33 octets max). Returns the content length. */
static usz der_int_content(const u8 val[32], usz start, u8* buf) {
  usz off = 0;
  if (der_int_needs_pad(val[start])) buf[off++] = 0;
  for (usz i = start; i < 32; i++) buf[off++] = val[i];
  return off;
}

int quic_ecdsasig_encode_integer(
    const u8 val[32], u8* out, usz cap, usz* out_len) {
  u8        buf[33];
  usz       start = der_int_strip(val);
  usz       n     = der_int_content(val, start, buf);
  quic_obuf o     = quic_obuf_of(out, cap);
  if (!quic_selfcert_der_tlv(QUIC_DER_INTEGER, quic_span_of(buf, n), &o))
    return 0;
  *out_len = o.len;
  return 1;
}
