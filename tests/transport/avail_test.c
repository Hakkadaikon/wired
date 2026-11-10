#include "transport/version/versmgr/avail.h"

#include "test.h"
#include "transport/version/version/version.h"

void test_avail(void) {
  vers_set s;
  vers_init_mask(&s, 0);

  /* supports v1 and v2, not unknown */
  CHECK(vers_supports(&s, VERSION_1) == 1);
  CHECK(vers_supports(&s, VERSION_2) == 1);
  CHECK(vers_supports(&s, 0x00000005u) == 0);
}
