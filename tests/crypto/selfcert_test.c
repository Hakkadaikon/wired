#include "crypto/pki/cert/selfcert/derenc.h"
#include "crypto/pki/encoding/asn1/der.h"
#include "test.h"

/* X.690 8.1. der_tlv emits a well-formed TLV that der_read parses back. */
static void test_der_tlv_roundtrip(void) {
  u8         out[8];
  wired_obuf o   = obuf_of(out, sizeof(out));
  const u8   v[] = {0xaa, 0xbb};
  CHECK(selfcert_der_tlv(DER_INTEGER, wired_span_of(v, 2), &o) == 1);
  CHECK(o.len == 4 && out[0] == 0x02 && out[1] == 0x02);

  der_tlv t;
  CHECK(der_read(wired_span_of(out, o.len), &t) == 1);
  CHECK(
      t.tag == 0x02 && t.val.n == 2 && t.val.p[0] == 0xaa &&
      t.val.p[1] == 0xbb);
}

/* X.690 8.1.3.5. A 200-octet value uses the 0x81 long form. */
static void test_der_tlv_longform(void) {
  u8         big[200] = {0};
  u8         out[210];
  wired_obuf o = obuf_of(out, sizeof(out));
  CHECK(selfcert_der_tlv(DER_OCTET_STRING, wired_span_of(big, 200), &o) == 1);
  CHECK(out[1] == 0x81 && out[2] == 200 && o.len == 203);
}

/* der_tlv refuses to overflow the caller buffer. */
static void test_der_tlv_overflow(void) {
  u8         out[3];
  wired_obuf o   = obuf_of(out, sizeof(out));
  const u8   v[] = {1, 2, 3, 4};
  CHECK(selfcert_der_tlv(DER_INTEGER, wired_span_of(v, 4), &o) == 0);
}

/* X.690 8.1.3.5: a value of 65536 octets needs a 3-octet length, past the
 * 0x82 long-form ceiling this encoder supports, so it is refused. */
static u8   sct_big[0x10000];
static void test_der_tlv_length_ceiling(void) {
  u8         out[8];
  wired_obuf o = obuf_of(out, sizeof(out));
  CHECK(
      selfcert_der_tlv(
          DER_OCTET_STRING, wired_span_of(sct_big, sizeof(sct_big)), &o) == 0);
}

void test_selfcert(void) {
  test_der_tlv_length_ceiling();
  test_der_tlv_roundtrip();
  test_der_tlv_longform();
  test_der_tlv_overflow();
}
