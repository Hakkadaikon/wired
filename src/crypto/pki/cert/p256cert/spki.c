#include "crypto/pki/cert/p256cert/spki.h"

#include "crypto/pki/cert/p256cert/enc.h"
#include "crypto/pki/encoding/asn1/der.h"

/* RFC 5480 2.1.1. id-ecPublicKey OID 1.2.840.10045.2.1. */
static const u8 oid_ec_pub[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
/* RFC 5480 2.1.1.1 / SEC2 2.4.2. secp256r1 (prime256v1) 1.2.840.10045.3.1.7. */
static const u8 oid_secp256r1[] = {0x2a, 0x86, 0x48, 0xce,
                                   0x3d, 0x03, 0x01, 0x07};

/* RFC 5480 2.1.1. AlgorithmIdentifier SEQUENCE{ id-ecPublicKey, secp256r1 }. */
static usz pc_build_alg(quic_obuf *out) {
  u8                inner[32];
  quic_p256cert_enc e = {inner, sizeof(inner), 0, 1};
  quic_p256cert_put(
      &e, QUIC_DER_OID, quic_span_of(oid_ec_pub, sizeof(oid_ec_pub)));
  quic_p256cert_put(
      &e, QUIC_DER_OID, quic_span_of(oid_secp256r1, sizeof(oid_secp256r1)));
  return quic_p256cert_wrap(&e, QUIC_DER_SEQUENCE, out);
}

/* SEC1 2.3.3. Pack the uncompressed point 0x04 || X || Y after the BIT STRING
 * unused-bits octet 0x00 into bits[66]. */
static void pack_point(u8 bits[66], const u8 x[32], const u8 y[32]) {
  static const u8 hdr[] = {0x00, 0x04}; /* unused-bits || uncompressed tag */
  usz             off   = 0;
  quic_put_bytes(bits, 66, &off, hdr, sizeof(hdr));
  quic_put_bytes(bits, 66, &off, x, 32);
  quic_put_bytes(bits, 66, &off, y, 32);
}

int quic_p256cert_spki(const u8 x[32], const u8 y[32], quic_obuf *out) {
  u8                alg[32], bits[66], inner[128];
  quic_obuf         ao = quic_obuf_of(alg, sizeof(alg));
  quic_p256cert_enc e  = {inner, sizeof(inner), 0, 1};
  pack_point(bits, x, y);
  quic_p256cert_put_pre(&e, quic_span_of(alg, pc_build_alg(&ao)));
  quic_p256cert_put(&e, QUIC_DER_BIT_STRING, quic_span_of(bits, sizeof(bits)));
  out->len = quic_p256cert_wrap(&e, QUIC_DER_SEQUENCE, out);
  return out->len != 0;
}
