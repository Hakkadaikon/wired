#include "crypto/asymmetric/ecc/ecdsasig/sig_value.h"
#include "crypto/pki/encoding/asn1/der.h"
#include "test.h"
#include "x509_golden.h"

/* The ECDSA-Sig-Value SEQUENCE sits inside the cert's signatureValue BIT STRING
 * (offset 323, 71 octets): octet 323 is the unused-bits count (0x00), so the
 * 70-octet DER SEQUENCE starts at offset 324. */
static const u8 *golden_sig(void) { return quic_x509_golden + 324; }

/* SEC1 C.5. Pull the two 32-octet INTEGER values out of the golden SEQUENCE. */
static int golden_rs(u8 r[32], u8 s[32]) {
  quic_der_tlv seq, ri, si;
  if (!quic_der_read(quic_span_of(golden_sig(), 70), &seq)) return 0;
  quic_der_read(seq.val, &ri);
  quic_der_read(quic_span_of(seq.val.p + ri.used, seq.val.n - ri.used), &si);
  for (usz i = 0; i < 32; i++) {
    r[i] = ri.val.p[i];
    s[i] = si.val.p[i];
  }
  return ri.val.n == 32 && si.val.n == 32;
}

/* Round-trip: re-encode the golden r,s and expect the exact golden 70 octets.
 */
static void test_sig_golden_roundtrip(void) {
  u8  r[32], s[32], out[80];
  usz n = 0;
  CHECK(golden_rs(r, s) == 1);
  CHECK(quic_ecdsasig_encode(r, s, out, sizeof(out), &n) == 1);
  CHECK(n == 70);
  for (usz i = 0; i < 70; i++) CHECK(out[i] == golden_sig()[i]);
}

/* The encoded SEQUENCE reads back through the DER parser as INTEGER, INTEGER.
 */
static void test_sig_reparse(void) {
  u8           r[32] = {0}, s[32] = {0}, out[80];
  quic_der_tlv seq, v;
  usz          n = 0;
  r[0]           = 0x80;
  s[0]           = 0x01;
  CHECK(quic_ecdsasig_encode(r, s, out, sizeof(out), &n) == 1);
  CHECK(
      quic_der_read(quic_span_of(out, n), &seq) == 1 &&
      seq.tag == QUIC_DER_SEQUENCE);
  CHECK(quic_der_read(seq.val, &v) == 1 && v.tag == QUIC_DER_INTEGER);
  CHECK(v.val.n == 33 && v.val.p[0] == 0x00 && v.val.p[1] == 0x80);
}

/* No room is rejected. */
static void test_sig_nofit(void) {
  u8  r[32] = {0}, s[32] = {0}, out[8];
  usz n = 0;
  r[0]  = 0x80;
  s[0]  = 0x80;
  CHECK(quic_ecdsasig_encode(r, s, out, sizeof(out), &n) == 0);
}

void test_ecdsasig_sig_value(void) {
  test_sig_golden_roundtrip();
  test_sig_reparse();
  test_sig_nofit();
}
