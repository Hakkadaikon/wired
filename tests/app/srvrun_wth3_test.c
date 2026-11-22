#include "test.h"

/* draft-ietf-webtrans-http3 rows pinned on the server's shipping path:
 * client packets sealed for real and stepped through the sr_sl_* fixture
 * (srvrun_test.c), what the server sends read back off a loopback socket
 * (rfch3_*, srvrun_test.c). */

/* A WT_CLOSE_SESSION capsule (draft-ietf-webtrans-http3-16 6) inside one
 * DATA frame (RFC 9297 3.2) into cap; its length. */
static usz wth3_close_capsule(u8* cap, usz n) {
  wired_obuf cb = obuf_of(cap, n);
  CHECK(wired_wtcapsule_encode_close(&cb, 7, wired_span_of(cap, 0)) == 1);
  sr_h3data(&cb, 0);
  return cb.len;
}

/* 1 if w carries a HEADERS frame (a response) on stream id. */
static int wth3_answered(rfcpin_wire* w, u64 id) {
  const rfcpin_stream* s = rfcpin_wire_stream(w, id);
  u64                  t[4];
  return s && rfcpin_h3_types(s, 0, t, 4) && t[0] == H3_FRAME_HEADERS;
}

/* draft-ietf-webtrans-http3-16 4.7 (WTH3-047): after a GOAWAY, an Extended
 * CONNECT for a new session at or above its stream id is not accepted. GET
 * 0 is answered and the GOAWAY carries 4; CONNECTs on 4 (at) and 8 (above)
 * then establish no session, get no response, and are reset with
 * H3_REQUEST_REJECTED on the wire (RFC 9114 5.2). */
static void test_srvrun_wth3_connect_past_goaway_rejected(void) {
  static rfcpin_wire w;
  sr_net             n;
  srvrun_conn*       c = rfch3_fixture(&n);
  u64                before;
  sr_sl_send_headers(c, 0, "GET", 1);
  CHECK(sr_sl_goaway(c) == 4);
  before = sr_sl_sessions();
  sr_sl_send_headers(c, 4, "CONNECT", 0);
  sr_sl_send_headers(c, 8, "CONNECT", 0);
  CHECK(sr_sl_sessions() == before);
  CHECK(c->wt_active == 0 && c->wt1_active == 0);
  rfch3_wire(&w, &n);
  for (u64 id = 4; id <= 8; id += 4) {
    CHECK(rfcpin_wire_reset_code(&w, id) == H3_REQUEST_REJECTED);
    CHECK(!wth3_answered(&w, id));
  }
  CHECK(wth3_answered(&w, 0));
  sr_net_close(&n);
}

/* draft-ietf-webtrans-http3-16 3.2 (WTH3-075), before the 2xx: a CONNECT
 * arriving ahead of the client's SETTINGS is held unanswered; a
 * WT_CLOSE_SESSION capsule sent on it meanwhile is not processed (no
 * close, no response on the wire). The SETTINGS then let the session be
 * accepted and the 200 goes out; the buffered capsule is processed by the
 * next receive pass at the latest (here the client's next packet, a
 * PING). Today it waits for that pass: srvrun_wt_rx_capsules runs in
 * srvrun_on_step, before srvrun_sess_on_step starts held CONNECTs. */
static void test_srvrun_wth3_capsule_before_2xx_waits(void) {
  static const u8    ping[] = {0x01};
  static rfcpin_wire w;
  sr_net             n;
  srvrun_conn*       c = rfch3_fixture(&n);
  u8                 cap[32];
  usz                hlen, cl = wth3_close_capsule(cap, sizeof cap);
  c->l.h3peer.ctrl.settings_seen = 0;
  hlen                           = sr_sl_send_headers(c, 0, "CONNECT", 0);
  rfch3_send_stream(c, 0, hlen, cap, cl, 0);
  CHECK(c->wt_active == 0 && g_sl_closes == 0);
  rfch3_wire(&w, &n);
  CHECK(!wth3_answered(&w, 0));
  sr_sl_send_settings(c);
  rfcpin_wire_drain(&w, &g_sl_f, n.afd);
  CHECK(wth3_answered(&w, 0));
  sr_sl_step(c, ping, sizeof ping);
  CHECK(g_sl_closes == 1 && c->wt_active == 0);
  sr_net_close(&n);
}

/* draft-ietf-webtrans-http3-16 3.2 (WTH3-075), rejected: with a session
 * on 0 and flow control off (one session only, 5.1), a CONNECT on 4 is
 * rejected (429, reset H3_REQUEST_REJECTED); the WT_CLOSE_SESSION capsule
 * following its HEADERS is discarded -- the session on 0 does not close
 * and no new one appears. */
static void test_srvrun_wth3_capsule_on_rejected_discarded(void) {
  static rfcpin_wire w;
  sr_net             n;
  srvrun_conn*       c = rfch3_fixture(&n);
  u8                 cap[32];
  usz                hlen, cl = wth3_close_capsule(cap, sizeof cap);
  u64                before;
  sr_sl_send_headers(c, 0, "CONNECT", 0);
  CHECK(c->wt_active == 1);
  before = sr_sl_sessions();
  hlen   = sr_sl_send_headers(c, 4, "CONNECT", 0);
  rfch3_send_stream(c, 4, hlen, cap, cl, 0);
  CHECK(g_sl_closes == 0 && c->wt_active == 1);
  CHECK(sr_sl_sessions() == before);
  rfch3_wire(&w, &n);
  CHECK(rfcpin_wire_reset_code(&w, 4) == H3_REQUEST_REJECTED);
  sr_net_close(&n);
}

/* draft-ietf-webtrans-http3-16 3.4 (WTH3-026): a PRIORITY_UPDATE (RFC 9218
 * 7.1) naming an established WebTransport CONNECT stream is accepted and
 * applied: the connection and the session stay up and stream 0's
 * priority becomes u=1. */
static void test_srvrun_wth3_priority_update_on_connect(void) {
  static const u64 none[] = {0};
  sr_net           n;
  srvrun_conn*     c = rfch3_fixture(&n);
  u8               ctrl[64], pu[32];
  h3_priupdate     f = {0, 0, wired_span_of((const u8*)"u=1", 3)};
  usz              len, pl;
  const wired_srvloop_stream_slot* s;
  c->l.h3peer.ctrl.settings_seen = 0;
  len = rfch3_ctrl(ctrl, sizeof ctrl, none, 0, wired_span_of(0, 0));
  rfch3_send_stream(c, 2, 0, ctrl, len, 0);
  sr_sl_send_headers(c, 0, "CONNECT", 0);
  CHECK(c->wt_active == 1);
  s = srvrun_req_slot_of(c, 0);
  CHECK(s != 0 && s->priority.urgency == 3); /* RFC 9218 4.1 default */
  pl = h3_priupdate_put(pu, sizeof pu, &f);
  CHECK(pl != 0);
  rfch3_send_stream(c, 2, len, pu, pl, 0);
  CHECK(!c->closing && c->wt_active == 1);
  s = srvrun_req_slot_of(c, 0);
  CHECK(s != 0 && s->priority.urgency == 1);
  sr_net_close(&n);
}

void test_srvrun_wth3(void) {
  test_srvrun_wth3_connect_past_goaway_rejected();
  test_srvrun_wth3_capsule_before_2xx_waits();
  test_srvrun_wth3_capsule_on_rejected_discarded();
  test_srvrun_wth3_priority_update_on_connect();
}
