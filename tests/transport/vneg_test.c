#include "test.h"

static void init2(vneg* v) {
  u32 sup[2] = {VERSION_1, VERSION_2};
  vneg_init(v, sup, 2);
}

/* version_information passes only with a consistent, non-empty, in-list set. */
static void test_vneg_downgrade_checks(void) {
  vneg         v;
  version_info vi = {.chosen = VERSION_1, .n_available = 2};
  vi.available[0] = VERSION_1;
  vi.available[1] = VERSION_2;

  init2(&v);
  CHECK(vneg_check_downgrade(&v, &vi, VERSION_1) == 1);

  /* Chosen != in_use */
  init2(&v);
  CHECK(vneg_check_downgrade(&v, &vi, VERSION_2) == 0);
  CHECK(v.phase == VNEG_ERROR);

  /* empty Available */
  init2(&v);
  version_info empty = {.chosen = VERSION_1, .n_available = 0};
  CHECK(vneg_check_downgrade(&v, &empty, VERSION_1) == 0);

  /* Chosen not in Available */
  init2(&v);
  version_info bad = {.chosen = VERSION_2, .n_available = 1};
  bad.available[0] = VERSION_1;
  CHECK(vneg_check_downgrade(&v, &bad, VERSION_2) == 0);
}

/* A VN listing our original version is ignored; otherwise we pick a mutual
 * version exactly once. */
static void test_vneg_reaction(void) {
  vneg v;
  u32  chosen;
  /* VN that lists our original (v1) is ignored */
  init2(&v);
  u32       offered_with_orig[2] = {VERSION_1, VERSION_2};
  vn_packet pkt_with_orig = {VERSION_1, verlist_of(offered_with_orig, 2)};
  CHECK(vneg_react(&v, &pkt_with_orig, &chosen) == 0);

  /* VN offering v2 (not our original v1) -> we pick v2, once */
  init2(&v);
  u32       offered[1] = {VERSION_2};
  vn_packet pkt        = {VERSION_1, verlist_of(offered, 1)};
  CHECK(vneg_react(&v, &pkt, &chosen) == 1);
  CHECK(chosen == VERSION_2 && v.reacted == 1);
  /* a second VN is ignored (one-shot) */
  CHECK(vneg_react(&v, &pkt, &chosen) == 0);
}

/* Confirm fixes the negotiated version; an errored negotiation never confirms.
 */
static void test_vneg_confirm(void) {
  vneg v;
  init2(&v);
  vneg_confirm(&v, VERSION_2);
  CHECK(v.phase == VNEG_CONFIRMED && v.negotiated == VERSION_2);

  init2(&v);
  version_info bad = {.chosen = VERSION_2, .n_available = 0};
  vneg_check_downgrade(&v, &bad, VERSION_1); /* -> ERROR */
  vneg_confirm(&v, VERSION_1);
  CHECK(v.phase == VNEG_ERROR); /* error does not confirm */
}

void test_vneg(void) {
  test_vneg_downgrade_checks();
  test_vneg_reaction();
  test_vneg_confirm();
}
