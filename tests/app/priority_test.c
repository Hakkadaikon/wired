#include "test.h"

/* RFC 9218 4.1: defaults are urgency 3, non-incremental. */
static void test_priority_init_defaults(void) {
  quic_h3_priority p;
  quic_h3_priority_init(&p);
  CHECK(p.urgency == 3);
  CHECK(p.incremental == 0);
}

/* Lower urgency value is higher priority; equal is not higher. */
static void test_priority_higher(void) {
  CHECK(quic_h3_priority_higher(0, 7));
  CHECK(quic_h3_priority_higher(2, 3));
  CHECK(!quic_h3_priority_higher(3, 3));
  CHECK(!quic_h3_priority_higher(7, 0));
}

/* Urgency boundaries: 0 and 7 valid, 8 (and above) invalid. */
static void test_urgency_valid_bounds(void) {
  CHECK(quic_h3_urgency_valid(0));
  CHECK(quic_h3_urgency_valid(3));
  CHECK(quic_h3_urgency_valid(7));
  CHECK(!quic_h3_urgency_valid(8));
  CHECK(!quic_h3_urgency_valid(255));
}

void test_priority(void) {
  test_priority_init_defaults();
  test_priority_higher();
  test_urgency_valid_bounds();
}
