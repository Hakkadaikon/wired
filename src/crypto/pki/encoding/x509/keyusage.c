#include "crypto/pki/encoding/x509/keyusage.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/x509/x509.h"

/* id-ce-keyUsage = 2.5.29.15 */
static const u8 oid_ku[] = {0x55, 0x1d, 0x0f};

/* RFC 5280 4.2.1.3. Bit position of keyCertSign within KeyUsage, numbered
 * MSB-first from bit0 (digitalSignature): bit5. */
#define KEYUSAGE_BIT_KEYCERTSIGN 5

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
