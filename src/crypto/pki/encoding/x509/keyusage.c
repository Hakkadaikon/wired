#include "crypto/pki/encoding/x509/keyusage.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/x509/x509.h"

/* id-ce-keyUsage = 2.5.29.15 */
static const u8 oid_ku[] = {0x55, 0x1d, 0x0f};

/* RFC 5280 4.2.1.3. KeyUsage bit positions, numbered MSB-first from bit0. */
#define KEYUSAGE_BIT_DIGITALSIGNATURE 0
#define KEYUSAGE_BIT_NONREPUDIATION 1
#define KEYUSAGE_BIT_KEYAGREEMENT 4
#define KEYUSAGE_BIT_KEYCERTSIGN 5
#define KEYUSAGE_BIT_CRLSIGN 6

/* X.690 8.6. A DER BIT STRING value: a leading unused-bits count octet,
 * then the data octets. Well-formed needs at least that leading octet. */
static int ku_bitstring_wf(quic_span v) { return v.n >= 1; }

/* RFC 5280 4.2.1.3 / X.690 8.6. 1 if bit `pos` (MSB-first from the start of
 * the data octets, ignoring the unused-bits count octet) is set. A bit past
 * the encoded data is treated as absent (0), matching DER's convention that
 * trailing zero bits may be omitted. */
static int ku_bit_set(quic_span v, usz pos) {
  usz byte_off = 1 + pos / 8;
  u8  mask     = (u8)(0x80 >> (pos % 8));
  if (byte_off >= v.n) return 0;
  return (v.p[byte_off] & mask) != 0;
}

/* X.690 8.6. val decodes as a well-formed BIT STRING TLV. */
static int ku_read_bitstring(quic_span val, quic_span* bits) {
  quic_der_tlv t;
  if (!quic_der_read(val, &t)) return 0;
  if (t.tag != QUIC_DER_BIT_STRING) return 0;
  *bits = t.val;
  return ku_bitstring_wf(*bits);
}

/* The keyUsage extnValue: an OCTET STRING wrapping the KeyUsage BIT STRING.
 */
static int ku_locate(quic_span tbs, quic_span* bits) {
  quic_span val;
  if (!quic_x509_find_ext(tbs, quic_span_of(oid_ku, sizeof(oid_ku)), &val))
    return 0;
  return ku_read_bitstring(val, bits);
}

int quic_x509_can_sign_certs(quic_span tbs) {
  quic_span bits;
  if (!ku_locate(tbs, &bits)) return 1;
  return ku_bit_set(bits, KEYUSAGE_BIT_KEYCERTSIGN);
}

/* 1 if bit `a` or bit `b` is set. */
static int ku_bit_set_2(quic_span v, usz a, usz b) {
  return ku_bit_set(v, a) || ku_bit_set(v, b);
}

/* 1 if any of bits `a`, `b`, `c`, `d` is set. */
static int ku_bit_set_4(quic_span v, usz a, usz b, usz c, usz d) {
  return ku_bit_set_2(v, a, b) || ku_bit_set_2(v, c, d);
}

/* RFC 8410 5. id-X25519/id-X448 SubjectPublicKeyInfo: keyUsage, if present,
 * must assert keyAgreement. Absent keyUsage is unconstrained (RFC 5280
 * default). */
int quic_x509_keyagreement_ok(quic_span tbs) {
  quic_span bits;
  if (!ku_locate(tbs, &bits)) return 1;
  return ku_bit_set(bits, KEYUSAGE_BIT_KEYAGREEMENT);
}

/* RFC 8410 5. id-Ed25519/id-Ed448 end-entity SubjectPublicKeyInfo: keyUsage,
 * if present, must assert nonRepudiation and/or digitalSignature. Absent
 * keyUsage is unconstrained. */
int quic_x509_ed_leaf_sig_ok(quic_span tbs) {
  quic_span bits;
  if (!ku_locate(tbs, &bits)) return 1;
  return ku_bit_set_2(
      bits, KEYUSAGE_BIT_DIGITALSIGNATURE, KEYUSAGE_BIT_NONREPUDIATION);
}

/* RFC 8410 5. id-Ed25519/id-Ed448 CA SubjectPublicKeyInfo: keyUsage, if
 * present, must assert one or more of nonRepudiation, digitalSignature,
 * keyCertSign, cRLSign. Absent keyUsage is unconstrained. */
int quic_x509_ed_ca_ok(quic_span tbs) {
  quic_span bits;
  if (!ku_locate(tbs, &bits)) return 1;
  return ku_bit_set_4(
      bits, KEYUSAGE_BIT_DIGITALSIGNATURE, KEYUSAGE_BIT_NONREPUDIATION,
      KEYUSAGE_BIT_KEYCERTSIGN, KEYUSAGE_BIT_CRLSIGN);
}
