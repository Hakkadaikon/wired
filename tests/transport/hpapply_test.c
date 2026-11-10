#include "test.h"

/* RFC 9001 5.4.2: pn bytes use mask[1..]. */
static void test_hpapply_pn(void) {
  u8 mask[5] = {0x43, 0x7b, 0x9a, 0xec, 0x36};
  u8 pn[4]   = {0x00, 0x00, 0x00, 0x02};
  hp_protect_pn(pn, 4, mask);
  CHECK(pn[0] == 0x7b && pn[1] == 0x9a && pn[2] == 0xec && pn[3] == 0x34);
  hp_protect_pn(pn, 4, mask); /* self-inverse */
  CHECK(pn[0] == 0x00 && pn[1] == 0x00 && pn[2] == 0x00 && pn[3] == 0x02);
}

void test_hpapply(void) { test_hpapply_pn(); }
