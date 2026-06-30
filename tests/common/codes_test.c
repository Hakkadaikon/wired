#include "test.h"

/* Every enumerated transport code and the CRYPTO range classify as standard. */
static void test_codes_standard(void) {
  CHECK(quic_error_is_standard(QUIC_EC_NO_ERROR) == 1);
  CHECK(quic_error_is_standard(QUIC_EC_VERSION_NEGOTIATION_ERROR) == 1);
  /* 0x12 is just past the enumerated range: not standard */
  CHECK(quic_error_is_standard(0x12) == 0);
  /* CRYPTO_ERROR range boundaries */
  CHECK(quic_error_is_standard(QUIC_EC_CRYPTO_LO) == 1);
  CHECK(quic_error_is_standard(QUIC_EC_CRYPTO_HI) == 1);
  CHECK(quic_error_is_standard(0x00ff) == 0); /* just below */
  CHECK(quic_error_is_standard(0x0200) == 0); /* just above */
}

/* GREASE values have the form 31*N+27. */
static void test_codes_grease(void) {
  CHECK(quic_error_is_grease(27) == 1); /* N=0 */
  CHECK(quic_error_is_grease(58) == 1); /* N=1: 31+27 */
  CHECK(quic_error_is_grease(31 * 100 + 27) == 1);
  CHECK(quic_error_is_grease(26) == 0);
  CHECK(quic_error_is_grease(28) == 0);
}

/* App codes are exactly the values outside the standard transport space. */
static void test_codes_app(void) {
  CHECK(quic_error_is_app(QUIC_EC_NO_ERROR) == 0);
  CHECK(quic_error_is_app(0x12) == 1);
  CHECK(quic_error_is_app(0x0200) == 1);
  /* standard and app partition the space at every probed point */
  CHECK(
      quic_error_is_standard(QUIC_EC_PROTOCOL_VIOLATION) !=
      quic_error_is_app(QUIC_EC_PROTOCOL_VIOLATION));
}

void test_codes(void) {
  test_codes_standard();
  test_codes_grease();
  test_codes_app();
}
