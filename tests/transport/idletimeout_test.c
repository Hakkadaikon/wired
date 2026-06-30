#include "test.h"

/* Effective timeout is the min of two non-zero values. */
static void test_idle_effective_min(void) {
  CHECK(quic_idle_effective(30, 50) == 30);
  CHECK(quic_idle_effective(50, 30) == 30);
  CHECK(quic_idle_effective(40, 40) == 40);
}

/* A zero value means "no limit": the other one wins; both zero stays zero. */
static void test_idle_effective_zero(void) {
  CHECK(quic_idle_effective(0, 50) == 50);
  CHECK(quic_idle_effective(50, 0) == 50);
  CHECK(quic_idle_effective(0, 0) == 0);
}

/* Expiry fires at/after the boundary, not before; never with a 0 timeout. */
static void test_idle_expired(void) {
  CHECK(quic_idle_expired(100, 129, 30) == 0); /* 29 elapsed < 30 */
  CHECK(quic_idle_expired(100, 130, 30) == 1); /* 30 elapsed == limit */
  CHECK(quic_idle_expired(100, 200, 30) == 1);
  CHECK(quic_idle_expired(100, 999, 0) == 0); /* 0 = no limit */
}

void test_idletimeout(void) {
  test_idle_effective_min();
  test_idle_effective_zero();
  test_idle_expired();
}
