#include "crypto/pki/encoding/asn1/derseq.h"

#include "crypto/pki/encoding/asn1/der.h"
#include "test.h"

/* X.690 8.9. Walk a SEQUENCE of two INTEGERs. */
static void test_derseq_two_ints(void) {
  /* SEQUENCE { INTEGER 1, INTEGER 256 } value bytes */
  const u8 seq[] = {0x02, 0x01, 0x01, 0x02, 0x02, 0x01, 0x00};
  derseq   c;
  derseq_init(&c, wired_span_of(seq, sizeof(seq)));
  u8         tag;
  wired_span val;
  CHECK(derseq_next(&c, &tag, &val) == 1);
  CHECK(tag == QUIC_DER_INTEGER && val.n == 1 && val.p[0] == 0x01);
  CHECK(derseq_next(&c, &tag, &val) == 1);
  CHECK(
      tag == QUIC_DER_INTEGER && val.n == 2 && val.p[0] == 0x01 &&
      val.p[1] == 0x00);
  CHECK(derseq_next(&c, &tag, &val) == 0); /* end */
}

/* Nested SEQUENCE: outer holds an inner SEQUENCE then an INTEGER. */
static void test_derseq_nested(void) {
  /* inner SEQUENCE {INTEGER 7} = 30 03 02 01 07 ; then INTEGER 9 */
  const u8 seq[] = {0x30, 0x03, 0x02, 0x01, 0x07, 0x02, 0x01, 0x09};
  derseq   c;
  derseq_init(&c, wired_span_of(seq, sizeof(seq)));
  u8         tag;
  wired_span val;
  CHECK(derseq_next(&c, &tag, &val) == 1);
  CHECK(tag == QUIC_DER_SEQUENCE && val.n == 3);
  /* descend into the inner sequence's value */
  derseq inner;
  derseq_init(&inner, val);
  u8         itag;
  wired_span ival;
  CHECK(derseq_next(&inner, &itag, &ival) == 1);
  CHECK(itag == QUIC_DER_INTEGER && ival.n == 1 && ival.p[0] == 0x07);
  CHECK(derseq_next(&inner, &itag, &ival) == 0);
  /* back to outer */
  CHECK(derseq_next(&c, &tag, &val) == 1);
  CHECK(tag == QUIC_DER_INTEGER && val.n == 1 && val.p[0] == 0x09);
  CHECK(derseq_next(&c, &tag, &val) == 0);
}

static void test_derseq_truncated_element(void) {
  /* element claims 4 octets but only 1 remains */
  const u8 seq[] = {0x02, 0x04, 0xAA};
  derseq   c;
  derseq_init(&c, wired_span_of(seq, sizeof(seq)));
  u8         tag;
  wired_span val;
  CHECK(derseq_next(&c, &tag, &val) == 0);
}

void test_derseq(void) {
  test_derseq_two_ints();
  test_derseq_nested();
  test_derseq_truncated_element();
}
