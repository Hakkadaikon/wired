#include "test.h"

static void init2(quic_vneg *v) {
  u32 sup[2] = {QUIC_VERSION_1, QUIC_VERSION_2};
  quic_vneg_init(v, sup, 2);
}

/* version_information passes only with a consistent, non-empty, in-list set. */
static void test_vneg_downgrade_checks(void) {
  quic_vneg         v;
  quic_version_info vi = {.chosen = QUIC_VERSION_1, .n_available = 2};
  vi.available[0]      = QUIC_VERSION_1;
  vi.available[1]      = QUIC_VERSION_2;

  init2(&v);
  CHECK(quic_vneg_check_downgrade(&v, &vi, QUIC_VERSION_1) == 1);

  /* Chosen != in_use */
  init2(&v);
  CHECK(quic_vneg_check_downgrade(&v, &vi, QUIC_VERSION_2) == 0);
  CHECK(v.phase == QUIC_VNEG_ERROR);

  /* empty Available */
  init2(&v);
  quic_version_info empty = {.chosen = QUIC_VERSION_1, .n_available = 0};
  CHECK(quic_vneg_check_downgrade(&v, &empty, QUIC_VERSION_1) == 0);

  /* Chosen not in Available */
  init2(&v);
  quic_version_info bad = {.chosen = QUIC_VERSION_2, .n_available = 1};
  bad.available[0]      = QUIC_VERSION_1;
  CHECK(quic_vneg_check_downgrade(&v, &bad, QUIC_VERSION_2) == 0);
}

/* A VN listing our original version is ignored; otherwise we pick a mutual
 * version exactly once. */
static void test_vneg_reaction(void) {
  quic_vneg v;
  u32       chosen;
  /* VN that lists our original (v1) is ignored */
  init2(&v);
  u32 offered_with_orig[2] = {QUIC_VERSION_1, QUIC_VERSION_2};
  CHECK(
      quic_vneg_react(&v, QUIC_VERSION_1, offered_with_orig, 2, &chosen) == 0);

  /* VN offering v2 (not our original v1) -> we pick v2, once */
  init2(&v);
  u32 offered[1] = {QUIC_VERSION_2};
  CHECK(quic_vneg_react(&v, QUIC_VERSION_1, offered, 1, &chosen) == 1);
  CHECK(chosen == QUIC_VERSION_2 && v.reacted == 1);
  /* a second VN is ignored (one-shot) */
  CHECK(quic_vneg_react(&v, QUIC_VERSION_1, offered, 1, &chosen) == 0);
}

/* Confirm fixes the negotiated version; an errored negotiation never confirms.
 */
static void test_vneg_confirm(void) {
  quic_vneg v;
  init2(&v);
  quic_vneg_confirm(&v, QUIC_VERSION_2);
  CHECK(v.phase == QUIC_VNEG_CONFIRMED && v.negotiated == QUIC_VERSION_2);

  init2(&v);
  quic_version_info bad = {.chosen = QUIC_VERSION_2, .n_available = 0};
  quic_vneg_check_downgrade(&v, &bad, QUIC_VERSION_1); /* -> ERROR */
  quic_vneg_confirm(&v, QUIC_VERSION_1);
  CHECK(v.phase == QUIC_VNEG_ERROR); /* error does not confirm */
}

void test_vneg(void) {
  test_vneg_downgrade_checks();
  test_vneg_reaction();
  test_vneg_confirm();
}
