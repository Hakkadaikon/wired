#include "app/moqt/ver/moqver.h"

#include "common/bytes/util/bytes.h"
#include "common/bytes/util/ct.h"
#include "test.h"

/* @file
 * MOQT version table: token lookup, per-draft capability bits, and the
 * server subprotocol offer generated from the same table. */

static wired_span moqver_test_tok(const char* s) {
  return wired_span_of((const u8*)s, wired_cstr_len(s));
}

static void test_moqver_find_each_token(void) {
  CHECK(moqver_find(moqver_test_tok("moqt-18")) == MOQVER_D18);
  CHECK(moqver_find(moqver_test_tok("moqt-19")) == MOQVER_D19);
  CHECK(moqver_find(moqver_test_tok("moqt-22")) == MOQVER_D22);
}

static void test_moqver_find_empty_is_d19(void) {
  CHECK(moqver_find(wired_span_of(0, 0)) == MOQVER_D19);
}

static void test_moqver_find_unknown(void) {
  CHECK(moqver_find(moqver_test_tok("moqt-20")) == -1);
  CHECK(moqver_find(moqver_test_tok("moqt-1")) == -1);
  CHECK(moqver_find(moqver_test_tok("moqt-190")) == -1);
  CHECK(moqver_find(moqver_test_tok("MOQT-19")) == -1);
}

static void test_moqver_caps_d18(void) {
  CHECK(
      moqver_caps(MOQVER_D18) ==
      (MOQVER_CAP_GOAWAY_REQID | MOQVER_CAP_DUP_SUBSCRIPTION |
       MOQVER_CAP_FIN_CANCEL_NS | MOQVER_CAP_PUBLISH_OK_ALIAS |
       MOQVER_CAP_SUBSCRIPTION_ENDED));
}

static void test_moqver_caps_d19(void) {
  CHECK(
      moqver_caps(MOQVER_D19) ==
      (MOQVER_CAP_RANGE_FILTERS | MOQVER_CAP_MAX_REQUEST_UPDATES |
       MOQVER_CAP_SUBSCRIPTION_ENDED));
}

static void test_moqver_caps_d22(void) {
  CHECK(
      moqver_caps(MOQVER_D22) ==
      (MOQVER_CAP_LOCFILTER_TYPED | MOQVER_CAP_FETCH_BODY_V22 |
       MOQVER_CAP_FILL_FETCH | MOQVER_CAP_PUBLISH_STATE_NOTIFY |
       MOQVER_CAP_FETCH_END_INCLUSIVE | MOQVER_CAP_RANGE_FILTERS |
       MOQVER_CAP_MAX_REQUEST_UPDATES | MOQVER_CAP_NS_PREFIX_MATCH |
       MOQVER_CAP_EOR_TIMED_OUT));
}

static void test_moqver_offer(void) {
  static const char want[]  = "moqt-22 moqt-19 moqt-18";
  char              out[32] = {0};
  CHECK(wired_moqt_wt_protocols(out, sizeof out) == sizeof want - 1);
  CHECK(ct_diffn((const u8*)out, (const u8*)want, sizeof want) == 0);
}

/* Exactly fits (string + NUL) at sizeof want; one byte less fails. */
static void test_moqver_offer_cap_boundary(void) {
  static const char want[]           = "moqt-22 moqt-19 moqt-18";
  char              out[sizeof want] = {0};
  CHECK(wired_moqt_wt_protocols(out, sizeof want) == sizeof want - 1);
  CHECK(wired_moqt_wt_protocols(out, sizeof want - 1) == 0);
  CHECK(wired_moqt_wt_protocols(out, 0) == 0);
}

void test_moqver(void) {
  test_moqver_find_each_token();
  test_moqver_find_empty_is_d19();
  test_moqver_find_unknown();
  test_moqver_caps_d18();
  test_moqver_caps_d19();
  test_moqver_caps_d22();
  test_moqver_offer();
  test_moqver_offer_cap_boundary();
}
