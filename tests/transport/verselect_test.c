#include "test.h"

/* RFC 9368 2.2: Chosen Version must match the version used on the packet. */
static void test_verselect_chosen_ok(void) {
  CHECK(quic_verinfo_chosen_ok(QUIC_VERSION_1, QUIC_VERSION_1) == 1);
  CHECK(quic_verinfo_chosen_ok(QUIC_VERSION_1, QUIC_VERSION_2) == 0);
}

/* Pick the most-preferred mutually supported compatible version. */
static void test_verselect_pick(void) {
  quic_version_information vi = {
      QUIC_VERSION_1, 2, {QUIC_VERSION_1, QUIC_VERSION_2}};
  u32 we[] = {QUIC_VERSION_2, QUIC_VERSION_1}; /* prefer v2 */
  u32 out  = 0;
  CHECK(quic_verinfo_pick_compatible(&vi, quic_verlist_of(we, 2), &out) == 1);
  CHECK(out == QUIC_VERSION_2);
}

/* RFC 9368 3: a GREASE entry in Available Versions is never selected. */
static void test_verselect_skips_grease(void) {
  quic_version_information vi = {
      QUIC_VERSION_1, 2, {0x1a2a3a4au, QUIC_VERSION_2}};
  u32 we[] = {0x1a2a3a4au, QUIC_VERSION_2};
  u32 out  = 0;
  CHECK(quic_verinfo_pick_compatible(&vi, quic_verlist_of(we, 2), &out) == 1);
  CHECK(out == QUIC_VERSION_2);
}

/* No mutually supported compatible version yields 0. */
static void test_verselect_none(void) {
  quic_version_information vi   = {QUIC_VERSION_1, 1, {QUIC_VERSION_1}};
  u32                      we[] = {0xdeadbeefu};
  u32                      out  = 0xffffffffu;
  CHECK(quic_verinfo_pick_compatible(&vi, quic_verlist_of(we, 1), &out) == 0);
  CHECK(out == 0xffffffffu); /* untouched */
}

void test_verselect(void) {
  test_verselect_chosen_ok();
  test_verselect_pick();
  test_verselect_skips_grease();
  test_verselect_none();
}
