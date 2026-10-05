/* @file
 * Connection and WebTransport session close behaviour of srvrun.c (ledger
 * 12-21/12-22/12-23, TLA+ tasks/loopeng/moqt/MoqtRawConn D1/D2):
 *   - draft-ietf-webtrans-http3-16 SS6: the peer's WT_CLOSE_SESSION or FIN
 *     on the CONNECT stream is answered with this server's own FIN on it;
 *   - RFC 9000 10.2/10.2.1: a server CONNECTION_CLOSE enters the closing
 *     state (T-E14);
 *   - WT stream bytes stay with the session they were offered to (T-E13).
 * Reuses srvrun_test.c's fixtures (sr_sl_*, sr_wtsend_fixture,
 * sr_stream_data_handler), included earlier in the same unity TU. */

/* The CONNECT stream's (id 0, sr_sl_fixture's session) server send slot:
 * its FIN is on the wire once append_open dropped with no FIN round still
 * pending, at the stream's current end (every byte sent so far). */
static int src_connect_fin_sent(srvrun_conn* c) {
  srvrun_wtsend* w = srvrun_wtsend_find(c, 0);
  if (!w) return 0;
  return w->append_open == 0 && w->fin_only_pending == 0 &&
         w->fin_requested == 0 && w->stream_off == c->wt_connect_sent_len[0];
}

/* In-use server send slots on stream id. */
static int src_wtsend_count(const srvrun_conn* c, u64 id) {
  int n = 0;
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++)
    n += c->wtsend[i].in_use && c->wtsend[i].stream_id == id;
  return n;
}

/* One STREAM frame on CONNECT stream 0 at offset `at`, as a client packet. */
static void src_connect_send(
    srvrun_conn* c, u64 at, const u8* d, usz n, int fin) {
  u8           pl[256];
  wired_obuf   sob = obuf_of(pl, sizeof pl);
  stream_frame sf  = {0, at, n, d, (u8)fin};
  CHECK(appdata_stream_frame(&sf, &sob) == 1);
  sr_sl_step(c, pl, sob.len);
}

/* A WT_CLOSE_SESSION (code 7, "bye") capsule in one DATA frame. */
static usz src_close_capsule(u8* out, usz cap) {
  wired_obuf b = obuf_of(out, cap);
  CHECK(
      wired_wtcapsule_encode_close(&b, 7, wired_span_of((const u8*)"bye", 3)) ==
      1);
  sr_h3data(&b, 0);
  return b.len;
}

/* 12-21: the client's WT_CLOSE_SESSION (no FIN) ends the session and this
 * server FINs its side of the CONNECT stream in the same step. */
static void test_srvrun_close_peer_capsule_fins_connect(void) {
  srvrun_conn* c    = sr_sl_fixture();
  usz          hlen = sr_sl_send_headers(c, 0, "CONNECT", 0);
  u8           cap[64];
  usz          n = src_close_capsule(cap, sizeof cap);
  CHECK(c->wt_active == 1);
  src_connect_send(c, hlen, cap, n, 0);
  CHECK(g_sl_closes == 1);
  CHECK(c->wt_active == 0);
  CHECK(src_connect_fin_sent(c));
}

/* 12-21: the client's bare FIN on the CONNECT stream (a close with code 0,
 * WTH3-068) is answered with this server's FIN. */
static void test_srvrun_close_peer_fin_fins_connect(void) {
  srvrun_conn* c    = sr_sl_fixture();
  usz          hlen = sr_sl_send_headers(c, 0, "CONNECT", 0);
  src_connect_send(c, hlen, 0, 0, 1);
  CHECK(g_sl_closes == 1);
  CHECK(c->wt_active == 0);
  CHECK(src_connect_fin_sent(c));
}

/* 12-21: WT_CLOSE_SESSION and FIN in one frame -- exactly one FIN round. */
static void test_srvrun_close_peer_capsule_and_fin_one_fin(void) {
  srvrun_conn* c    = sr_sl_fixture();
  usz          hlen = sr_sl_send_headers(c, 0, "CONNECT", 0);
  u8           cap[64];
  usz          n = src_close_capsule(cap, sizeof cap);
  src_connect_send(c, hlen, cap, n, 1);
  CHECK(g_sl_closes == 1);
  CHECK(src_wtsend_count(c, 0) == 1);
  CHECK(src_connect_fin_sent(c));
}

/* 12-21 boundary: an invalid WT_CLOSE_SESSION resets the CONNECT stream
 * (H3_MESSAGE_ERROR, WTH3-072) -- no FIN after the reset. */
static void test_srvrun_close_bad_capsule_resets_no_fin(void) {
  static const u8 bad[] = {0, 0, 0, 7, 0xC3}; /* code 7, invalid UTF-8 */
  srvrun_conn*    c     = sr_sl_fixture();
  usz             hlen  = sr_sl_send_headers(c, 0, "CONNECT", 0);
  u8              cap[64];
  wired_obuf      b = obuf_of(cap, sizeof cap);
  CHECK(
      capsule_encode(
          &b, WTCAPSULE_TYPE_CLOSE, wired_span_of(bad, sizeof bad)) == 1);
  sr_h3data(&b, 0);
  src_connect_send(c, hlen, cap, b.len, 0);
  CHECK(g_sl_closes == 1);
  CHECK(src_wtsend_count(c, 0) == 0);
}

/* T-E13 (D1, wtroute DeliverToOwner): with WT flow control on, session A in
 * slot 0 and B in slot 1; A closes, stream 12 is offered to B, then C
 * reuses slot 0. The next chunk of stream 12 still goes to B. */
static void test_srvrun_close_stream_stays_with_owner(void) {
  struct lp_fix                 f;
  u8                            obuf[1024];
  wired_obuf                    ob = obuf_of(obuf, sizeof obuf);
  srvrun_conn*                  c  = sr_test_conns();
  wired_srvloop_wt_stream_slot* x;
  srvrun_cfg                    cfg = {0};
  cfg.fd                            = -1;
  cfg.env                           = &g_srvrun_env;
  cfg.wt_on_stream_data             = sr_stream_data_handler;
  sr_make_confirmed_conn(c, &f, &ob);
  c->l.peer_wt_initial[0] = 1;
  wired_wt_session_init(&c->wt, 4);
  wired_wt_session_establish(&c->wt);
  c->wt_active = 1;
  wired_wt_session_init(&c->wt1, 8);
  wired_wt_session_establish(&c->wt1);
  c->wt1_active = 1;
  srvrun_close_wt_session_slot(&cfg, c, 0, WTERR_SESSION_GONE);
  x            = &c->l.wt_streams[0];
  x->in_use    = 1;
  x->stream_id = 12;
  x->buf[0]    = 'a';
  sr_wt_slot_set_frontier(x, 1);
  g_srsd_calls = 0;
  srvrun_offer_wt_streams(&cfg, c);
  CHECK(x->wt_session_slot == 1);
  CHECK(g_srsd_calls == 1 && g_srsd_last_sess == &c->wt1);
  wired_wt_session_init(&c->wt, 16); /* C takes slot 0 */
  wired_wt_session_establish(&c->wt);
  c->wt_active            = 1;
  x->buf[1 - x->win.base] = 'b'; /* the window slid past delivered 'a' */
  sr_wt_slot_set_frontier(x, 2 - x->win.base);
  srvrun_offer_wt_streams(&cfg, c);
  CHECK(g_srsd_calls == 2);
  CHECK(g_srsd_last_sess == &c->wt1); /* B's, not C's */
  CHECK(g_srsd_last_len == 1 && g_srsd_last_buf[0] == 'b');
}

/* T-E13 "offered later" row (review F7): a stream that arrived while no
 * session was open is neither offered nor delivered; once a session opens
 * (slot 1 here, slot 0 free) it is offered there and delivers there. */
static void test_srvrun_close_stream_offered_later(void) {
  struct lp_fix                 f;
  u8                            obuf[1024];
  wired_obuf                    ob = obuf_of(obuf, sizeof obuf);
  srvrun_conn*                  c  = sr_test_conns();
  wired_srvloop_wt_stream_slot* x;
  srvrun_cfg                    cfg = {0};
  cfg.fd                            = -1;
  cfg.env                           = &g_srvrun_env;
  cfg.wt_on_stream_data             = sr_stream_data_handler;
  sr_make_confirmed_conn(c, &f, &ob);
  c->l.peer_wt_initial[0] = 1;
  x                       = &c->l.wt_streams[0];
  x->in_use               = 1;
  x->stream_id            = 12;
  x->offered              = 0;
  x->wt_session_slot      = -1;
  x->buf[0]               = 'a';
  sr_wt_slot_set_frontier(x, 1);
  g_srsd_calls = 0;
  srvrun_offer_wt_streams(&cfg, c);
  CHECK(x->offered == 0 && g_srsd_calls == 0);
  wired_wt_session_init(&c->wt1, 8);
  wired_wt_session_establish(&c->wt1);
  c->wt1_active = 1;
  srvrun_offer_wt_streams(&cfg, c);
  CHECK(x->offered == 1 && x->wt_session_slot == 1);
  CHECK(g_srsd_calls == 1 && g_srsd_last_sess == &c->wt1);
}

/* T-E14 setup: an established session (sr_sl_fixture, CONNECT stream 0)
 * whose app gets WT stream data, plus a real routing table so the reap can
 * free the slot. */
static conntable g_src_table[WIRED_CONNTABLE_CAP];

static srvrun_conn* src_closing_fixture(void) {
  srvrun_conn* c = sr_sl_fixture();
  conntable_init(g_src_table, WIRED_CONNTABLE_CAP);
  g_sl_st.table              = g_src_table;
  g_sl_cfg.wt_on_stream_data = sr_stream_data_handler;
  sr_sl_send_headers(c, 0, "CONNECT", 0);
  CHECK(c->wt_active == 1);
  g_srsd_calls = 0;
  return c;
}

/* The close frame c kept, decoded. */
static conn_close_frame src_kept_close(const srvrun_conn* c) {
  conn_close_frame ccf = {0};
  CHECK(frame_get_conn_close(c->close_pl, c->close_pln, &ccf) == c->close_pln);
  return ccf;
}

/* A client bidi WT stream (signal 0x41 as a 2-byte varint, session 0) with
 * 2 bytes. */
static void src_wt_stream_packet(srvrun_conn* c, u64 id) {
  static const u8 d[] = {0x40, 0x41, 0x00, 'h', 'i'};
  u8              pl[64];
  wired_obuf      sob = obuf_of(pl, sizeof pl);
  stream_frame    sf  = {id, 0, sizeof d, d, 0};
  CHECK(appdata_stream_frame(&sf, &sob) == 1);
  sr_sl_step(c, pl, sob.len);
}

/* T-E14 / RFC 9000 10.2: a violation CONNECTION_CLOSE ends every session in
 * the same step (wt_on_session_close once) and enters the closing state. */
static void test_srvrun_close_violation_closes_sessions_now(void) {
  srvrun_conn* c = src_closing_fixture();
  srvrun_test_reset_send_count();
  srvrun_close_on_bad_qsid(&g_sl_cfg, c);
  CHECK(srvrun_test_send_count() == 1);
  CHECK(c->closing == 1);
  CHECK(g_sl_closes == 1);
  CHECK(c->wt_active == 0);
  CHECK(src_kept_close(c).is_app == 1);
  CHECK(src_kept_close(c).error_code == H3_DATAGRAM_ERROR);
}

/* T-E14 / RFC 9000 10.2.1: later client packets reach no app callback and
 * draw only the same CONNECTION_CLOSE, on the 1st, 2nd and 4th packet. */
static void test_srvrun_close_closing_answers_only_close(void) {
  srvrun_conn* c = src_closing_fixture();
  u64          pn;
  src_wt_stream_packet(c, 4); /* control: delivered while open */
  CHECK(g_srsd_calls == 1);
  g_srsd_calls = 0;
  srvrun_close_on_bad_qsid(&g_sl_cfg, c);
  srvrun_test_reset_send_count();
  pn = c->l.tx_pn;
  src_wt_stream_packet(c, 8);
  CHECK(srvrun_test_send_count() == 1);
  CHECK(c->l.tx_pn == pn + 1); /* the resend, nothing else */
  src_wt_stream_packet(c, 8);
  src_wt_stream_packet(c, 8);
  CHECK(srvrun_test_send_count() == 2); /* 3rd packet: rate-limited */
  src_wt_stream_packet(c, 8);
  CHECK(srvrun_test_send_count() == 3);
  CHECK(g_srsd_calls == 0);
  CHECK(g_sl_closes == 1);
  CHECK(src_kept_close(c).error_code == H3_DATAGRAM_ERROR);
}

/* T-E14 SingleCloseFrame: a second close attempt while closing sends
 * nothing and keeps the first code. */
static void test_srvrun_close_second_close_is_noop(void) {
  static const u8 why[] = "x";
  srvrun_conn*    c     = src_closing_fixture();
  srvrun_close_on_bad_qsid(&g_sl_cfg, c);
  srvrun_test_reset_send_count();
  srvrun_send_transport_close(
      &g_sl_cfg, c, ERR_PROTOCOL_VIOLATION, wired_span_of(why, 1));
  srvrun_send_app_close(&g_sl_cfg, c, H3_NO_ERROR, wired_span_of(why, 1));
  CHECK(srvrun_test_send_count() == 0);
  CHECK(src_kept_close(c).is_app == 1);
  CHECK(src_kept_close(c).error_code == H3_DATAGRAM_ERROR);
}

/* T-E14: no stream data leaves a closing connection -- the app's send API
 * refuses (no open session), and a pending send round is never pumped. */
static void test_srvrun_close_closing_sends_no_stream(void) {
  static const u8   pay[] = {'z'};
  srvrun_conn*      c     = src_closing_fixture();
  wired_wt_session* s     = &c->wt;
  srvrun_close_on_bad_qsid(&g_sl_cfg, c);
  srvrun_test_reset_send_count();
  CHECK(wired_server_wt_open_uni_stream(s, wired_span_of(pay, 1)) == -1);
  srvrun_sess_on_step(&g_sl_ctx, 0);
  srvrun_tick_slot(&g_sl_ctx, 0);
  CHECK(srvrun_test_send_count() == 0);
}

/* RFC 9000 10.2: the closing slot is reaped three PTOs after the close
 * (tick path), not at the 30 s idle timeout -- one ms earlier it stays;
 * on_session_close is not repeated by the reap. */
static void test_srvrun_close_reaped_after_three_pto(void) {
  srvrun_conn* c = src_closing_fixture();
  u64          until;
  srvrun_close_on_bad_qsid(&g_sl_cfg, c);
  until = c->closing_until_ms;
  CHECK(until == c->l.now_ms + 3 * srvrun_pto_deadline_ms(c, 0));
  CHECK(until < WIRED_SRVRUN_IDLE_MS);
  g_sl_ctx.now_ms = until - 1;
  srvrun_tick_slot(&g_sl_ctx, 0);
  CHECK(c->up == 1);
  g_sl_ctx.now_ms = until;
  srvrun_tick_slot(&g_sl_ctx, 0);
  CHECK(c->up == 0);
  CHECK(c->closing == 0);
  CHECK(g_sl_closes == 1);
  g_sl_ctx.now_ms = 0;
}

/* The same reap through the arrival-time idle sweep. */
static void test_srvrun_close_sweep_reaps_closing(void) {
  srvrun_conn* c = src_closing_fixture();
  srvrun_close_on_bad_qsid(&g_sl_cfg, c);
  c->last_ms = c->closing_until_ms; /* fresh: not idle */
  srvrun_sweep_idle(&g_sl_cfg, &g_sl_st, c->closing_until_ms);
  CHECK(c->up == 0);
  CHECK(g_sl_closes == 1);
}

/* 12-31 / RFC 9000 19.4, 3.5: a client bidi stream the hub already reset
 * (no server send slot ever existed) is in Reset Sent; the session-close
 * sweep (WT_SESSION_GONE) builds no second RESET_STREAM for it, and a
 * repeated app reset latches nothing -- the first code stays the only one. */
static void test_srvrun_close_no_second_reset_after_app_reset(void) {
  struct lp_fix f;
  wired_obuf    ob = {0};
  u8            obuf[1024];
  u8            pl[48];
  wired_obuf    plb = obuf_of(pl, sizeof pl);
  srvrun_conn*  c;
  ob = (wired_obuf){obuf, sizeof obuf, 0};
  c  = sr_wtsend_fixture(&f, &ob);
  CHECK(wired_server_wt_stream_reset(&c->wt, 4, 0x42) == 1);
  CHECK(c->wt_stream_reset_n == 1);
  CHECK(wired_server_wt_stream_reset(&c->wt, 4, 0x43) == 1);
  CHECK(c->wt_stream_reset_n == 1);
  CHECK(c->wt_stream_reset_app_code[0] == 0x42);
  CHECK(srvrun_wt_abort_reset(c, 4, WTERR_SESSION_GONE, &plb, 0) == 0);
}

void test_srvrun_close(void) {
  test_srvrun_close_no_second_reset_after_app_reset();
  test_srvrun_close_peer_capsule_fins_connect();
  test_srvrun_close_peer_fin_fins_connect();
  test_srvrun_close_peer_capsule_and_fin_one_fin();
  test_srvrun_close_bad_capsule_resets_no_fin();
  test_srvrun_close_stream_stays_with_owner();
  test_srvrun_close_stream_offered_later();
  test_srvrun_close_violation_closes_sessions_now();
  test_srvrun_close_closing_answers_only_close();
  test_srvrun_close_second_close_is_noop();
  test_srvrun_close_closing_sends_no_stream();
  test_srvrun_close_reaped_after_three_pto();
  test_srvrun_close_sweep_reaps_closing();
}
