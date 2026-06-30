#include "app/qpack/qpack/insertcount.h"

#include "test.h"

/* RFC 9204 4.5.1.1: a Required Insert Count of 0 encodes to 0 and decodes back
 * to 0 regardless of MaxEntries or inserts. */
static void test_qpack_ric_zero(void) {
  CHECK(quic_qpack_ric_encode(0, 3) == 0);
  u64 ric = 99;
  CHECK(quic_qpack_ric_decode(0, 3, 0, &ric) == 1 && ric == 0);
}

/* RFC 9204 4.5.1.1 worked example: MaxEntries 3, 10 total inserts, RIC 9
 * encodes to 4 and decodes back to 9. */
static void test_qpack_ric_example(void) {
  CHECK(quic_qpack_ric_encode(9, 3) == 4);
  u64 ric = 0;
  CHECK(quic_qpack_ric_decode(4, 3, 10, &ric) == 1 && ric == 9);
}

/* RFC 9204 4.5.1.1: EncodedInsertCount above 2*MaxEntries is invalid, and a
 * non-zero encoding that resolves to RIC 0 is rejected. */
static void test_qpack_ric_invalid(void) {
  u64 ric = 0;
  CHECK(quic_qpack_ric_decode(7, 3, 10, &ric) == 0);
  /* encoded 1 with no inserts wraps to candidate 0, which is invalid. */
  CHECK(quic_qpack_ric_decode(1, 3, 0, &ric) == 0);
}

/* Round-trip across the wrap boundary: every RIC up to one full range decodes
 * back to itself when TotalNumberOfInserts equals RIC (RFC 9204 4.5.1.1). */
static void test_qpack_ric_roundtrip(void) {
  u64 max_entries = 4;
  for (u64 r = 1; r <= 2 * max_entries; r++) {
    u64 enc = quic_qpack_ric_encode(r, max_entries);
    u64 ric = 0;
    CHECK(quic_qpack_ric_decode(enc, max_entries, r, &ric) == 1);
    CHECK(ric == r);
  }
}

void test_insertcount(void) {
  test_qpack_ric_zero();
  test_qpack_ric_example();
  test_qpack_ric_invalid();
  test_qpack_ric_roundtrip();
}
