#include "test.h"

/* RFC 9001 5.4.2 worked example (Client Initial): byte0 0xc3, mask[0] 0x43.
 * Long header masks the low 4 bits: 0xc3 ^ (0x43 & 0x0f) = 0xc3 ^ 0x03 = 0xc0.
 */
static void test_hpapply_byte0_long(void) {
  CHECK(quic_hp_protect_byte0(0xc3, 0x43, 1) == 0xc0);
}

/* Short header masks the low 5 bits instead of 4. */
static void test_hpapply_byte0_short(void) {
  /* 0x43 & 0x1f = 0x03, so same low bits here; use a mask whose bit 4
   * differs to prove 5 bits are used: 0xff & 0x1f = 0x1f. */
  CHECK(quic_hp_protect_byte0(0x40, 0xff, 0) == 0x5f); /* 0x40 ^ 0x1f */
  CHECK(quic_hp_protect_byte0(0x40, 0xff, 1) == 0x4f); /* long: ^ 0x0f */
}

/* XOR is self-inverse: protecting twice restores the original byte0. */
static void test_hpapply_byte0_roundtrip(void) {
  u8 b = quic_hp_protect_byte0(0xc3, 0x43, 1);
  CHECK(quic_hp_protect_byte0(b, 0x43, 1) == 0xc3);
}

/* RFC 9001 5.4.2: pn bytes use mask[1..]. */
static void test_hpapply_pn(void) {
  u8 mask[5] = {0x43, 0x7b, 0x9a, 0xec, 0x36};
  u8 pn[4]   = {0x00, 0x00, 0x00, 0x02};
  quic_hp_protect_pn(pn, 4, mask);
  CHECK(pn[0] == 0x7b && pn[1] == 0x9a && pn[2] == 0xec && pn[3] == 0x34);
  quic_hp_protect_pn(pn, 4, mask); /* self-inverse */
  CHECK(pn[0] == 0x00 && pn[1] == 0x00 && pn[2] == 0x00 && pn[3] == 0x02);
}

void test_hpapply(void) {
  test_hpapply_byte0_long();
  test_hpapply_byte0_short();
  test_hpapply_byte0_roundtrip();
  test_hpapply_pn();
}
