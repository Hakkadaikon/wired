#include "test.h"

/* RFC 9368 2.2: Chosen Version must match the version used on the packet. */
static void test_verselect_chosen_ok(void) {
  CHECK(verinfo_chosen_ok(VERSION_1, VERSION_1) == 1);
  CHECK(verinfo_chosen_ok(VERSION_1, VERSION_2) == 0);
}

/* RFC 9368 3: Available Versions is in the client's preference order --
 * a client preferring v1 stays on v1 even though we also support v2. */
static void test_verselect_pick_client_order(void) {
  version_information vi   = {VERSION_1, 2, {VERSION_1, VERSION_2}};
  u32                 we[] = {VERSION_2, VERSION_1};
  u32                 out  = 0;
  CHECK(verinfo_pick_compatible(&vi, verlist_of(we, 2), &out) == 1);
  CHECK(out == VERSION_1);
}

/* A client listing v2 first is upgraded to v2. */
static void test_verselect_pick_v2_first(void) {
  version_information vi   = {VERSION_1, 2, {VERSION_2, VERSION_1}};
  u32                 we[] = {VERSION_2, VERSION_1};
  u32                 out  = 0;
  CHECK(verinfo_pick_compatible(&vi, verlist_of(we, 2), &out) == 1);
  CHECK(out == VERSION_2);
}

/* RFC 9368 3: a GREASE entry in Available Versions is never selected. */
static void test_verselect_skips_grease(void) {
  version_information vi   = {VERSION_1, 2, {0x1a2a3a4au, VERSION_2}};
  u32                 we[] = {0x1a2a3a4au, VERSION_2};
  u32                 out  = 0;
  CHECK(verinfo_pick_compatible(&vi, verlist_of(we, 2), &out) == 1);
  CHECK(out == VERSION_2);
}

/* No mutually supported compatible version yields 0. */
static void test_verselect_none(void) {
  version_information vi   = {VERSION_1, 1, {VERSION_1}};
  u32                 we[] = {0xdeadbeefu};
  u32                 out  = 0xffffffffu;
  CHECK(verinfo_pick_compatible(&vi, verlist_of(we, 1), &out) == 0);
  CHECK(out == 0xffffffffu); /* untouched */
}

void test_verselect(void) {
  test_verselect_chosen_ok();
  test_verselect_pick_client_order();
  test_verselect_pick_v2_first();
  test_verselect_skips_grease();
  test_verselect_none();
}
