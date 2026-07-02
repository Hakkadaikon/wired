#include "crypto/pki/encoding/asn1/der.h"

#include "test.h"

/* X.690 8.1. Short-form length: INTEGER 0x02 len 0x01 value 0x05. */
static void test_der_short_form(void) {
  const u8     in[] = {0x02, 0x01, 0x05};
  quic_der_tlv t;
  CHECK(quic_der_read(quic_span_of(in, sizeof(in)), &t) == 1);
  CHECK(
      t.tag == QUIC_DER_INTEGER && t.val.n == 1 && t.val.p[0] == 0x05 &&
      t.used == 3);
}

/* X.690 8.1.3.5. Long form 0x81: a 200-octet OCTET STRING. */
static void test_der_long_form_1(void) {
  u8 in[3 + 200];
  in[0] = QUIC_DER_OCTET_STRING;
  in[1] = 0x81;
  in[2] = 200;
  for (usz i = 0; i < 200; i++) in[3 + i] = (u8)i;
  quic_der_tlv t;
  CHECK(quic_der_read(quic_span_of(in, sizeof(in)), &t) == 1);
  CHECK(t.tag == QUIC_DER_OCTET_STRING && t.val.n == 200 && t.used == 203);
  CHECK(t.val.p[0] == 0 && t.val.p[199] == 199);
}

/* X.690 8.1.3.5. Long form 0x82: a 300-octet value. */
static void test_der_long_form_2(void) {
  u8 in[4 + 300];
  in[0] = QUIC_DER_OCTET_STRING;
  in[1] = 0x82;
  in[2] = 0x01; /* 0x012C = 300 */
  in[3] = 0x2C;
  quic_der_tlv t;
  CHECK(quic_der_read(quic_span_of(in, sizeof(in)), &t) == 1);
  CHECK(t.val.n == 300 && t.used == 304 && t.val.p == in + 4);
}

static void test_der_truncated(void) {
  quic_der_tlv t;
  /* header says 5 octets, only 2 present */
  const u8 a[] = {0x02, 0x05, 0x01, 0x02};
  CHECK(quic_der_read(quic_span_of(a, sizeof(a)), &t) == 0);
  /* too short for any TLV */
  const u8 b[] = {0x02};
  CHECK(quic_der_read(quic_span_of(b, 1), &t) == 0);
  /* long form 0x82 announced but length octets missing */
  const u8 c[] = {0x04, 0x82, 0x01};
  CHECK(quic_der_read(quic_span_of(c, sizeof(c)), &t) == 0);
  /* unsupported indefinite/reserved length octet 0x80 */
  const u8 d[] = {0x04, 0x80, 0x00};
  CHECK(quic_der_read(quic_span_of(d, sizeof(d)), &t) == 0);
}

void test_der(void) {
  test_der_short_form();
  test_der_long_form_1();
  test_der_long_form_2();
  test_der_truncated();
}
