#include "test.h"
#include "transport/version/version/version.h"
#include "transport/version/vndrive/accept.h"
#include "transport/version/vndrive/reconnect.h"
#include "transport/version/vndrive/select.h"

/* RFC 9000 6.2: accept VN only before handshake completion. */
static void test_accept_pre_handshake(void) {
  u32 offered[2] = {VERSION_2, 0x0a0a0a0a};
  CHECK(vndrive_accept(0, VERSION_1, verlist_of(offered, 2)) == 1);
  CHECK(vndrive_accept(1, VERSION_1, verlist_of(offered, 2)) == 0);
}

/* RFC 9000 6.2: sent version present in the offered list is a downgrade. */
static void test_accept_downgrade(void) {
  u32 offered[2] = {VERSION_1, VERSION_2};
  CHECK(vndrive_accept(0, VERSION_1, verlist_of(offered, 2)) == 0);
  CHECK(vndrive_accept(0, VERSION_2, verlist_of(offered, 2)) == 0);
}

/* RFC 8999 6: select the most-preferred mutual version (our order wins). */
static void test_select_pref(void) {
  u32 offered[2] = {VERSION_1, VERSION_2};
  u32 sup2[2]    = {VERSION_2, VERSION_1};
  u32 chosen     = 0;
  CHECK(
      vndrive_select(verlist_of(offered, 2), verlist_of(sup2, 2), &chosen) ==
      1);
  CHECK(chosen == VERSION_2);

  u32 sup1[2] = {VERSION_1, VERSION_2};
  chosen      = 0;
  CHECK(
      vndrive_select(verlist_of(offered, 2), verlist_of(sup1, 2), &chosen) ==
      1);
  CHECK(chosen == VERSION_1);
}

/* No common version: returns 0. */
static void test_select_none(void) {
  u32 offered[1] = {0x0a0a0a0a};
  u32 sup[2]     = {VERSION_2, VERSION_1};
  u32 chosen     = 0xdead;
  CHECK(
      vndrive_select(verlist_of(offered, 1), verlist_of(sup, 2), &chosen) == 0);
}

/* RFC 9000 6.2: retry once with a chosen version, then give up. */
static void test_should_retry(void) {
  CHECK(vndrive_should_retry(VERSION_2, 0) == 1); /* 1st time */
  CHECK(vndrive_should_retry(VERSION_2, 1) == 0); /* already retried */
  CHECK(vndrive_should_retry(0, 0) == 0);         /* no common version */
}

void test_vndrive(void) {
  test_accept_pre_handshake();
  test_accept_downgrade();
  test_select_pref();
  test_select_none();
  test_should_retry();
}
