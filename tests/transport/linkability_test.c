#include "test.h"

void test_linkability(void) {
  CHECK(quic_linkability_broken(7, 9) == 1); /* CID changed */
  CHECK(quic_linkability_broken(7, 7) == 0); /* same CID */

  CHECK(quic_linkability_at_risk(1, 0) == 1); /* migrated, CID kept */
  CHECK(quic_linkability_at_risk(1, 1) == 0); /* migrated, CID changed */
  CHECK(quic_linkability_at_risk(0, 0) == 0); /* no migration */
}
