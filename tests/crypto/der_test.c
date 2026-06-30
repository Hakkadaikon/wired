#include "crypto/pki/encoding/asn1/der.h"

#include "test.h"

/* X.690 8.1. Short-form length: INTEGER 0x02 len 0x01 value 0x05. */
static void test_der_short_form(void) {
  const u8  in[] = {0x02, 0x01, 0x05};
  u8        tag;
  const u8 *val;
  usz       vlen, used;
  CHECK(quic_der_read(in, sizeof(in), &tag, &val, &vlen, &used) == 1);
  CHECK(tag == QUIC_DER_INTEGER && vlen == 1 && val[0] == 0x05 && used == 3);
}

/* X.690 8.1.3.5. Long form 0x81: a 200-octet OCTET STRING. */
static void test_der_long_form_1(void) {
  u8 in[3 + 200];
  in[0] = QUIC_DER_OCTET_STRING;
  in[1] = 0x81;
  in[2] = 200;
  for (usz i = 0; i < 200; i++) in[3 + i] = (u8)i;
  u8        tag;
  const u8 *val;
  usz       vlen, used;
  CHECK(quic_der_read(in, sizeof(in), &tag, &val, &vlen, &used) == 1);
  CHECK(tag == QUIC_DER_OCTET_STRING && vlen == 200 && used == 203);
  CHECK(val[0] == 0 && val[199] == 199);
}

/* X.690 8.1.3.5. Long form 0x82: a 300-octet value. */
static void test_der_long_form_2(void) {
  u8 in[4 + 300];
  in[0] = QUIC_DER_OCTET_STRING;
  in[1] = 0x82;
  in[2] = 0x01; /* 0x012C = 300 */
  in[3] = 0x2C;
  u8        tag;
  const u8 *val;
  usz       vlen, used;
  CHECK(quic_der_read(in, sizeof(in), &tag, &val, &vlen, &used) == 1);
  CHECK(vlen == 300 && used == 304 && val == in + 4);
}

static void test_der_truncated(void) {
  u8        tag;
  const u8 *val;
  usz       vlen, used;
  /* header says 5 octets, only 2 present */
  const u8 a[] = {0x02, 0x05, 0x01, 0x02};
  CHECK(quic_der_read(a, sizeof(a), &tag, &val, &vlen, &used) == 0);
  /* too short for any TLV */
  const u8 b[] = {0x02};
  CHECK(quic_der_read(b, 1, &tag, &val, &vlen, &used) == 0);
  /* long form 0x82 announced but length octets missing */
  const u8 c[] = {0x04, 0x82, 0x01};
  CHECK(quic_der_read(c, sizeof(c), &tag, &val, &vlen, &used) == 0);
  /* unsupported indefinite/reserved length octet 0x80 */
  const u8 d[] = {0x04, 0x80, 0x00};
  CHECK(quic_der_read(d, sizeof(d), &tag, &val, &vlen, &used) == 0);
}

void test_der(void) {
  test_der_short_form();
  test_der_long_form_1();
  test_der_long_form_2();
  test_der_truncated();
}
