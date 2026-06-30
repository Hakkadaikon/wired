#include "test.h"
#include "transport/version/version/version.h"
#include "transport/version/versmgr/downgrade.h"

void test_versdowngrade(void) {
  /* server offers [v2, v1], negotiated v2 -> ok (most preferred) */
  u32 av[] = {QUIC_VERSION_2, QUIC_VERSION_1};
  CHECK(quic_vers_no_downgrade(QUIC_VERSION_2, av, 2) == 1);

  /* negotiated v1 while v2 (usable) precedes it -> downgrade */
  CHECK(quic_vers_no_downgrade(QUIC_VERSION_1, av, 2) == 0);

  /* GREASE before negotiated is ignored -> still ok */
  u32 grease[] = {0x0a0a0a0au, QUIC_VERSION_1};
  CHECK(quic_vers_no_downgrade(QUIC_VERSION_1, grease, 2) == 1);

  /* negotiated absent from server's list -> downgrade */
  u32 only_v2[] = {QUIC_VERSION_2};
  CHECK(quic_vers_no_downgrade(QUIC_VERSION_1, only_v2, 1) == 0);
}
