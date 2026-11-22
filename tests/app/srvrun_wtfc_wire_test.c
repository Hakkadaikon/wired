/* @file
 * Session flow control (srvrun_wtfc.c) through the production path: a real
 * Extended CONNECT accepted by srvrun_start_wt, then client 1-RTT packets
 * through srvrun_on_step (draft-ietf-webtrans-http3-16 5.3/5.6.2). Reuses
 * srvrun_test.c's sr_sl_* and srvrun_wtfc_test.c's fc_* helpers, included
 * earlier in the same unity TU.
 *
 * Test list:
 * - a session holding 20 long-lived bidi streams stays open, none refused.
 * - the 25th bidi stream closes the session with WT_FLOW_CONTROL_ERROR.
 * - an ended stream draws WT_MAX_STREAMS(25) in the same step. */

/* A real client: SETTINGS_WT_INITIAL_* latched (as priority_ctrl.c does),
 * then an Extended CONNECT on stream 0 accepted by srvrun_start_wt. */
static srvrun_conn* fc_wire_session(void) {
  srvrun_conn* c             = sr_sl_fixture();
  c->l.peer_wt_initial[0]    = 1;
  c->l.peer_wt_initial[1]    = 1;
  c->l.peer_wt_initial[2]    = 1;
  g_sl_cfg.wt_on_stream_data = fc_on_data;
  sr_sl_send_headers(c, 0, "CONNECT", 0);
  CHECK(c->wt_active == 1);
  return c;
}

/* One client packet opening WT bidi stream id for session 0 (0x41 as a
 * 2-byte varint, session id 0, one byte of data). */
static void fc_wire_bidi(srvrun_conn* c, u64 id, int fin) {
  static const u8 d[] = {0x40, 0x41, 0x00, 'x'};
  u8              pl[64];
  wired_obuf      sob = obuf_of(pl, sizeof pl);
  stream_frame    sf  = {id, 0, sizeof d, d, (u8)fin};
  CHECK(appdata_stream_frame(&sf, &sob) == 1);
  sr_sl_step(c, pl, sob.len);
}

/* A MoQT client keeps its request streams open for the whole session:
 * 20 of them at once stay open, none refused. */
static void test_srvrun_wtfc_wire_holds_long_lived_bidi(void) {
  srvrun_conn* c = fc_wire_session();
  for (u64 k = 0; k < 20; k++) {
    fc_wire_bidi(c, 4 + 4 * k, 0);
  }
  CHECK(c->wt_active == 1);
  CHECK(srvrun_wt_bidi_slots_in_use(c) == 20);
  CHECK(c->wtx.fc[0].opened[1] == 20);
  CHECK(sr_kept_reset_of(c, 80) == 0);
}

/* The 25th bidi stream is past the limit of 24: the session closes with
 * WT_FLOW_CONTROL_ERROR (the stream itself is refused by the full table). */
static void test_srvrun_wtfc_wire_bidi_past_limit_closes(void) {
  srvrun_conn* c = fc_wire_session();
  for (u64 k = 0; k < H3SETTINGS_WT_INIT_STREAMS_BIDI_VALUE; k++) {
    fc_wire_bidi(c, 4 + 4 * k, 0);
  }
  CHECK(c->wt_active == 1);
  fc_wire_bidi(c, 4 + 4 * H3SETTINGS_WT_INIT_STREAMS_BIDI_VALUE, 0);
  fc_check_closed(c, 4);
}

/* A stream that ends (FIN, delivered, reaped) draws WT_MAX_STREAMS(25) on
 * the CONNECT stream in the same step. */
static void test_srvrun_wtfc_wire_stream_end_raises(void) {
  srvrun_conn* c = fc_wire_session();
  usz          n;
  fc_wire_bidi(c, 4, 1);
  CHECK(fc_sent_on(c, 0, 1, &n) == H3SETTINGS_WT_INIT_STREAMS_BIDI_VALUE + 1);
  CHECK(n == 1);
}

void test_srvrun_wtfc_wire(void) {
  test_srvrun_wtfc_wire_holds_long_lived_bidi();
  test_srvrun_wtfc_wire_bidi_past_limit_closes();
  test_srvrun_wtfc_wire_stream_end_raises();
}
