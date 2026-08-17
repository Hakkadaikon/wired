#include "transport/version/versmgr/avail.h"

#include "test.h"
#include "transport/version/version/version.h"

void test_avail(void) {
  vers_set s;
  vers_init(&s);

  /* supports v1 and v2, not unknown */
  CHECK(vers_supports(&s, VERSION_1) == 1);
  CHECK(vers_supports(&s, VERSION_2) == 1);
  CHECK(vers_supports(&s, 0x00000005u) == 0);

  /* common version: peer offers v1 only -> v1 */
  u32 peer_v1[] = {VERSION_1};
  u32 chosen    = 0;
  CHECK(vers_choose_compatible(&s, verlist_of(peer_v1, 1), &chosen) == 1);
  CHECK(chosen == VERSION_1);

  /* peer offers both -> our most preferred (v2) */
  u32 peer_both[] = {VERSION_1, VERSION_2};
  chosen          = 0;
  CHECK(vers_choose_compatible(&s, verlist_of(peer_both, 2), &chosen) == 1);
  CHECK(chosen == VERSION_2);

  /* no common version */
  u32 peer_none[] = {0x00000005u};
  chosen          = 0xdead;
  CHECK(vers_choose_compatible(&s, verlist_of(peer_none, 1), &chosen) == 0);
  CHECK(chosen == 0xdead);
}
