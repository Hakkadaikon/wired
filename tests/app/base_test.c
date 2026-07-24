#include "app/qpack/qpack/base.h"

#include "test.h"

/* RFC 9204 4.5.1.2: with Sign 0 the Base is RIC plus Delta Base. */
static void test_qpack_base_positive(void) {
  CHECK(quic_qpack_base(6, 0, 0) == 6);
  CHECK(quic_qpack_base(6, 0, 2) == 8);
}

/* RFC 9204 4.5.1.2: with Sign 1 the Base is RIC minus Delta Base minus 1. */
static void test_qpack_base_negative(void) {
  CHECK(quic_qpack_base(6, 1, 0) == 5);
  CHECK(quic_qpack_base(6, 1, 2) == 3);
  /* Sign 1, Delta Base RIC-1 yields Base 0, the lowest legal value. */
  CHECK(quic_qpack_base(6, 1, 5) == 0);
}

/* RFC 9204 4.5.1.2: Sign 0 is always valid, regardless of RIC/DeltaBase. */
static void test_qpack_base_valid_sign0_always_ok(void) {
  CHECK(quic_qpack_base_valid(0, 0, 0));
  CHECK(quic_qpack_base_valid(1, 0, 5));
}

/* RFC 9204 4.5.1.2: Sign 1 with RIC greater than DeltaBase is valid (Base
 * stays non-negative). */
static void test_qpack_base_valid_sign1_ok(void) {
  CHECK(quic_qpack_base_valid(6, 1, 0));
  CHECK(quic_qpack_base_valid(6, 1, 5)); /* Base == 0, still valid */
}

/* RFC 9204 4.5.1.2: Sign 1 with RIC <= DeltaBase MUST be treated as invalid
 * (Base would be negative). */
static void test_qpack_base_valid_sign1_rejected(void) {
  CHECK(!quic_qpack_base_valid(5, 1, 5)); /* RIC == DeltaBase */
  CHECK(!quic_qpack_base_valid(4, 1, 5)); /* RIC < DeltaBase */
  CHECK(!quic_qpack_base_valid(0, 1, 0)); /* RIC == DeltaBase == 0 */
}

void test_base(void) {
  test_qpack_base_positive();
  test_qpack_base_negative();
  test_qpack_base_valid_sign0_always_ok();
  test_qpack_base_valid_sign1_ok();
  test_qpack_base_valid_sign1_rejected();
}
