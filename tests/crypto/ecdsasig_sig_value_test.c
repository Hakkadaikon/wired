#include "crypto/asymmetric/ecc/ecdsasig/sig_value.h"
#include "crypto/pki/encoding/asn1/der.h"
#include "test.h"
#include "x509_golden.h"

/* The ECDSA-Sig-Value SEQUENCE sits inside the cert's signatureValue BIT STRING
 * (offset 323, 71 octets): octet 323 is the unused-bits count (0x00), so the
 * 70-octet DER SEQUENCE starts at offset 324. */
static const u8* golden_sig(void) { return x509_golden + 324; }

/* SEC1 C.5. Pull the two 32-octet INTEGER values out of the golden SEQUENCE. */
static int golden_rs(u8 r[32], u8 s[32]) {
  der_tlv seq, ri, si;
  if (!der_read(wired_span_of(golden_sig(), 70), &seq)) return 0;
  der_read(seq.val, &ri);
  der_read(wired_span_of(seq.val.p + ri.used, seq.val.n - ri.used), &si);
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
  CHECK(ecdsasig_encode(r, s, out, sizeof(out), &n) == 1);
  CHECK(n == 70);
  for (usz i = 0; i < 70; i++) CHECK(out[i] == golden_sig()[i]);
}

/* The encoded SEQUENCE reads back through the DER parser as INTEGER, INTEGER.
 */
static void test_sig_reparse(void) {
  u8      r[32] = {0}, s[32] = {0}, out[80];
  der_tlv seq, v;
  usz     n = 0;
  r[0]      = 0x80;
  s[0]      = 0x01;
  CHECK(ecdsasig_encode(r, s, out, sizeof(out), &n) == 1);
  CHECK(der_read(wired_span_of(out, n), &seq) == 1 && seq.tag == DER_SEQUENCE);
  CHECK(der_read(seq.val, &v) == 1 && v.tag == DER_INTEGER);
  CHECK(v.val.n == 33 && v.val.p[0] == 0x00 && v.val.p[1] == 0x80);
}

/* No room is rejected. */
static void test_sig_nofit(void) {
  u8  r[32] = {0}, s[32] = {0}, out[8];
  usz n = 0;
  r[0]  = 0x80;
  s[0]  = 0x80;
  CHECK(ecdsasig_encode(r, s, out, sizeof(out), &n) == 0);
}

/* Strict decode of the golden SEQUENCE recovers the same r,s the raw DER
 * walk finds, and the 48-byte form left-pads them (P-384 width). */
static void test_sig_decode_golden(void) {
  u8 r[32], s[32], dr[32], ds[32], r48[48], s48[48];
  CHECK(golden_rs(r, s) == 1);
  CHECK(ecdsasig_decode(wired_span_of(golden_sig(), 70), dr, ds, 32) == 1);
  for (usz i = 0; i < 32; i++) CHECK(dr[i] == r[i] && ds[i] == s[i]);
  CHECK(ecdsasig_decode(wired_span_of(golden_sig(), 70), r48, s48, 48) == 1);
  for (usz i = 0; i < 16; i++) CHECK(r48[i] == 0 && s48[i] == 0);
  for (usz i = 0; i < 32; i++) CHECK(r48[16 + i] == r[i]);
}

/* X.690 / CVE-2018-1000180 class: bytes after the SEQUENCE are rejected. */
static void test_sig_decode_rejects_trailing_data(void) {
  u8 buf[71], r[32], s[32];
  for (usz i = 0; i < 70; i++) buf[i] = golden_sig()[i];
  buf[70] = 0x00;
  CHECK(ecdsasig_decode(wired_span_of(buf, 71), r, s, 32) == 0);
}

/* A third element inside ECDSA-Sig-Value is rejected (SEC1 C.5: exactly
 * two INTEGERs). */
static void test_sig_decode_rejects_extra_element(void) {
  static const u8 sig[] = {0x30, 0x09, 0x02, 0x01, 0x01, 0x02,
                           0x01, 0x01, 0x02, 0x01, 0x01};
  u8              r[32], s[32];
  CHECK(ecdsasig_decode(wired_span_of(sig, sizeof(sig)), r, s, 32) == 0);
}

/* X.690 10.1: a long-form length that fits the short form (0x81 0x06) is
 * not DER and is rejected. */
static void test_sig_decode_rejects_nonminimal_length(void) {
  static const u8 sig[] = {0x30, 0x81, 0x06, 0x02, 0x01,
                           0x01, 0x02, 0x01, 0x01};
  u8              r[32], s[32];
  CHECK(ecdsasig_decode(wired_span_of(sig, sizeof(sig)), r, s, 32) == 0);
}

/* X.690 8.3.2: a leading 0x00 before a byte without its top bit set is a
 * non-minimal INTEGER and is rejected; the pad before 0x80 is the one
 * legitimate form and must still decode. */
static void test_sig_decode_integer_padding(void) {
  static const u8 bad[]  = {0x30, 0x07, 0x02, 0x02, 0x00,
                            0x01, 0x02, 0x01, 0x01};
  static const u8 good[] = {0x30, 0x07, 0x02, 0x02, 0x00,
                            0x80, 0x02, 0x01, 0x01};
  u8              r[32], s[32];
  CHECK(ecdsasig_decode(wired_span_of(bad, sizeof(bad)), r, s, 32) == 0);
  CHECK(ecdsasig_decode(wired_span_of(good, sizeof(good)), r, s, 32) == 1);
  CHECK(r[31] == 0x80 && s[31] == 0x01);
}

/* A negative INTEGER (top bit set, no pad) and an empty INTEGER are both
 * invalid ECDSA scalars. */
static void test_sig_decode_rejects_negative_and_empty(void) {
  static const u8 neg[]   = {0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x01};
  static const u8 empty[] = {0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x01};
  u8              r[32], s[32];
  CHECK(ecdsasig_decode(wired_span_of(neg, sizeof(neg)), r, s, 32) == 0);
  CHECK(ecdsasig_decode(wired_span_of(empty, sizeof(empty)), r, s, 32) == 0);
}

/* An INTEGER value wider than the scalar width is rejected. */
static void test_sig_decode_rejects_oversized_integer(void) {
  u8 sig[42], r[32], s[32];
  sig[0] = 0x30;
  sig[1] = 40; /* 35-byte r INTEGER + 3-byte s INTEGER + 2 headers */
  sig[2] = 0x02;
  sig[3] = 33; /* 33-byte positive value: 0x01 then 32 zeros */
  sig[4] = 0x01;
  for (usz i = 5; i < 37; i++) sig[i] = 0x00;
  sig[37] = 0x02;
  sig[38] = 0x01;
  sig[39] = 0x01;
  CHECK(ecdsasig_decode(wired_span_of(sig, 40), r, s, 32) == 0);
}

void test_ecdsasig_sig_value(void) {
  test_sig_golden_roundtrip();
  test_sig_reparse();
  test_sig_nofit();
  test_sig_decode_golden();
  test_sig_decode_rejects_trailing_data();
  test_sig_decode_rejects_extra_element();
  test_sig_decode_rejects_nonminimal_length();
  test_sig_decode_integer_padding();
  test_sig_decode_rejects_negative_and_empty();
  test_sig_decode_rejects_oversized_integer();
}
