#include "test.h"

void test_linkability(void) {
  CHECK(linkability_broken(7, 9) == 1); /* CID changed */
  CHECK(linkability_broken(7, 7) == 0); /* same CID */

  CHECK(linkability_at_risk(1, 0) == 1); /* migrated, CID kept */
  CHECK(linkability_at_risk(1, 1) == 0); /* migrated, CID changed */
  CHECK(linkability_at_risk(0, 0) == 0); /* no migration */
}
