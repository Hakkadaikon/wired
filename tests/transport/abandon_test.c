#include "test.h"

/* The connection is abandoned only when no offered version (ignoring reserved
 * GREASE values) is one we support. */
void test_abandon(void) {
  u32     support[2] = {QUIC_VERSION_1, QUIC_VERSION_2};
  verlist sup        = verlist_of(support, 2);

  /* a supported version is offered -> do not abandon */
  u32 ok[1] = {QUIC_VERSION_2};
  CHECK(version_must_abandon(verlist_of(ok, 1), sup) == 0);

  /* only unsupported versions offered -> abandon */
  u32 bad[2] = {0x11112222u, 0x33334444u};
  CHECK(version_must_abandon(verlist_of(bad, 2), sup) == 1);

  /* empty offer -> abandon */
  CHECK(version_must_abandon(verlist_of(bad, 0), sup) == 1);

  /* reserved GREASE value matching our support must be ignored: a reserved
   * 0x?a?a?a?a value is never a usable offer */
  u32 grease[1] = {0x0a0a0a0au};
  CHECK(version_is_reserved(0x0a0a0a0au) == 1);
  CHECK(version_must_abandon(verlist_of(grease, 1), sup) == 1);

  /* GREASE alongside a supported version -> not abandoned */
  u32 mixed[2] = {0x0a0a0a0au, QUIC_VERSION_1};
  CHECK(version_must_abandon(verlist_of(mixed, 2), sup) == 0);
}
