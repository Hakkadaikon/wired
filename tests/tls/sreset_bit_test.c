#include "test.h"

/* RFC 9287 3.1: any QUIC Bit value is acceptable on a stateless reset. */
static void test_sreset_bit_any(void) {
  CHECK(quic_greasebit_sreset_ok(0x00) == 1); /* bit cleared */
  CHECK(quic_greasebit_sreset_ok(0x40) == 1); /* bit set */
  CHECK(quic_greasebit_sreset_ok(0xFF) == 1);
}

void test_sreset_bit(void) { test_sreset_bit_any(); }
