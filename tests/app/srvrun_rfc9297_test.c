#include "test.h"

/* RFC 9297 rows pinned on the server's shipping path (the sr_sl_* and
 * rfcpin_* fixtures, srvrun_test.c). */

/* RFC 9297 2.1.1 (9297-015): SETTINGS_H3_DATAGRAM is only ever sent as 1.
 * Read off the confirmation packet: with DATAGRAM negotiated the setting
 * is present with value 1 (also with 0-RTT acceptance staged, which the
 * SETTINGS do not depend on); without it the setting is absent -- no
 * other value is ever sent. */
static void test_srvrun_rfc9297_h3_datagram_setting_is_one(void) {
  static rfcpin_wire w;
  for (int i = 0; i < 3; i++) {
    struct lp_fix        f;
    const rfcpin_stream* s;
    u64                  v     = ~0ULL;
    int                  dgram = i != 0;
    rfcpin_confirm(&f, &w, dgram, i == 2);
    s = rfcpin_wire_stream(&w, SRVRUN_CTRL_STREAM);
    CHECK(s != 0);
    CHECK(s && rfcpin_setting(s, H3_SETTING_H3_DATAGRAM, &v) == dgram);
    CHECK(!dgram || v == 1);
  }
}

/* RFC 9297 3.2 / 3.5 (9297-026, 9297-027): a DATAGRAM capsule (type 0x00)
 * longer than the CONNECT stream's receive window is not buffered -- it
 * could not fit -- but skipped by its length across windows: the stream
 * keeps its credit growing for all of it, no datagram reaches the
 * session, and the WT_CLOSE_SESSION after it is still applied. */
static void test_srvrun_rfc9297_datagram_capsule_past_window_skipped(void) {
  static u8             caps[SR_REQ_BUF_CAP + 3000], dg[SR_REQ_BUF_CAP + 2000];
  wired_obuf            cb   = obuf_of(caps, sizeof caps);
  srvrun_conn*          c    = sr_sl_fixture();
  usz                   hlen = sr_sl_send_headers(c, 0, "CONNECT", 0);
  wired_srvrun_wt_usage before, after;
  CHECK(c->wt_active == 1);
  wired_srvrun_env_wt_usage(&g_srvrun_env, &before);
  CHECK(capsule_encode(&cb, 0x00, wired_span_of(dg, sizeof dg)) == 1);
  CHECK(
      wired_wtcapsule_encode_close(&cb, 7, wired_span_of((const u8*)"", 0)) ==
      1);
  sr_h3data(&cb, 0);
  CHECK(sr_cap_send(c, hlen, caps, cb.len) == cb.len);
  wired_srvrun_env_wt_usage(&g_srvrun_env, &after);
  CHECK(after.datagrams == before.datagrams);
  CHECK(g_sl_closes == 1);
  CHECK(c->wt_active == 0);
}

void test_srvrun_rfc9297(void) {
  test_srvrun_rfc9297_h3_datagram_setting_is_one();
  test_srvrun_rfc9297_datagram_capsule_past_window_skipped();
}
