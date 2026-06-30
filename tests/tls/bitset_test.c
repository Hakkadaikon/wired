#include "test.h"

/* RFC 9287 3: clearing the QUIC Bit is permitted only when the peer
 * advertised grease_quic_bit. */
static void test_bitset_may_clear(void) {
  CHECK(quic_greasebit_may_clear(0) == 0);
  CHECK(quic_greasebit_may_clear(1) == 1);
}

/* RFC 9287 3: apply clears or sets 0x40, leaving other bits intact. */
static void test_bitset_apply(void) {
  CHECK(quic_greasebit_apply(0xC0, 1) == 0x80); /* clear 0x40 */
  CHECK(quic_greasebit_apply(0x80, 0) == 0xC0); /* set 0x40 */
  CHECK(quic_greasebit_apply(0x80, 1) == 0x80); /* already clear */
  CHECK(quic_greasebit_apply(0xC0, 0) == 0xC0); /* already set */
}

void test_bitset(void) {
  test_bitset_may_clear();
  test_bitset_apply();
}
