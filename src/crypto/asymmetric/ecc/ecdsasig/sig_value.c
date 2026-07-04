#include "crypto/asymmetric/ecc/ecdsasig/sig_value.h"

#include "crypto/asymmetric/ecc/ecdsasig/der_int.h"
#include "crypto/pki/cert/selfcert/derenc.h"
#include "crypto/pki/encoding/asn1/der.h"

/* SEC1 C.5. Concatenate INTEGER r and INTEGER s into body. Each INTEGER TLV is
 * at most 35 octets (0x02, len, 0x00 pad, 32 value), so body holds 2*35.
 * Returns 1 ok with *len set, 0 on encode failure. */
static int sig_body(const u8 r[32], const u8 s[32], u8* body, usz* len) {
  usz rn = 0, sn = 0;
  if (!quic_ecdsasig_encode_integer(r, body, 35, &rn)) return 0;
  if (!quic_ecdsasig_encode_integer(s, body + rn, 35, &sn)) return 0;
  *len = rn + sn;
  return 1;
}

int quic_ecdsasig_encode(
    const u8 r[32], const u8 s[32], u8* out, usz cap, usz* out_len) {
  u8        body[70];
  usz       len = 0;
  quic_obuf o   = quic_obuf_of(out, cap);
  if (!sig_body(r, s, body, &len)) return 0;
  if (!quic_selfcert_der_tlv(QUIC_DER_SEQUENCE, quic_span_of(body, len), &o))
    return 0;
  *out_len = o.len;
  return 1;
}
