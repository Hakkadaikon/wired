#include "test.h"

/* RFC 9221 rows pinned on the server's shipping path: client DATAGRAMs
 * served through srvrun_serve_slot, server DATAGRAMs sent by
 * srvrun_send_datagram_now and recovered by srvrun_feed_acks. Reuses the
 * srvrec_* (srvrun_rec_test.c) and sr_* (srvrun_test.c) fixtures. */

/* Serve conns[0] (c) one client 1-RTT packet carrying pl at pn, at now. */
static void rfc9221_serve(
    struct lp_fix* f, srvrun_conn* c, u64 pn, wired_span pl, u64 now) {
  conntable    table[WIRED_CONNTABLE_CAP];
  srvrun_state st   = {table, c};
  sockaddr     peer = c->peer;
  sr_arrival   a    = {&peer, -1, 0, 0, now};
  conntable_init(table, WIRED_CONNTABLE_CAP);
  c->l.now_ms = now;
  sr_serve_at(f, &st, &a, pn, pl);
}

/* RFC 9221 5.2 (9221-020, 9221-022): a packet carrying only a DATAGRAM is
 * ack-eliciting -- served through the production receive path it leaves an
 * ACK owed -- and that ACK is delayed, not sent at once, then flushed by the
 * poll tick once max_ack_delay's window passes; the window plus the tick
 * stays within the max_ack_delay the server advertises (RFC 9000 18.2). */
static void test_srvrun_rfc9221_dg_only_packet_acked_within_delay(void) {
  static const u8 ping[1] = {0x01};
  struct lp_fix   f;
  srvrun_conn     c;
  u8              obuf[1024], dg[16];
  wired_obuf      ob  = {obuf, sizeof obuf, 0};
  datagram_frame  df  = {.length = 3, .data = (const u8*)"\x01hi"};
  usz             dn  = datagram_encode(wired_mspan_of(dg, sizeof dg), &df, 1);
  srvrun_cfg      cfg = srvrec_cfg();
  srvrun_state    st  = {0, &c};
  srvrun_step_ctx ctx = {&cfg, 0, &st, 0, 0};
  u64             tx;
  CHECK(
      WIRED_SRVLOOP_MAX_ACK_DELAY_MS + SRVRUN_PTO_MS <=
      STP_DEFAULT_MAX_ACK_DELAY_MS);
  srvrec_bare(&c, &f, &ob);
  c.l.we_advertised_max_datagram = 100; /* RFC 9221 3: server opted in */
  /* RFC 9297 2.1: the DATAGRAM names a live session (Quarter Stream ID 1,
   * CONNECT stream 4); an unknown one would get its request aborted. */
  c.wt_slot_active[0]             = 1;
  c.wt_slots[0].state             = WIRED_WT_ESTABLISHED;
  c.wt_slots[0].connect_stream_id = 4;
  rfc9221_serve(&f, &c, 20, wired_span_of(ping, 1), 0);
  ackpolicy_on_ack_sent(&c.l.app_ack_policy); /* start from nothing owed */
  tx = c.l.tx_pn;
  rfc9221_serve(&f, &c, 21, wired_span_of(dg, dn), 0);
  CHECK(c.closing == 0 && c.l.datagram_violation == 0); /* accepted */
  CHECK(c.l.app_ack_policy.pending == 1);
  CHECK(c.l.tx_pn == tx); /* delayed: nothing sent yet */
  c.l.now_ms = ctx.now_ms = WIRED_SRVLOOP_MAX_ACK_DELAY_MS - 1;
  srvrun_ack_tick_slot(&ctx, 0);
  CHECK(c.l.tx_pn == tx);
  c.l.now_ms = ctx.now_ms = WIRED_SRVLOOP_MAX_ACK_DELAY_MS;
  srvrun_ack_tick_slot(&ctx, 0);
  CHECK(c.l.tx_pn == tx + 1);
  CHECK(c.l.app_ack_policy.pending == 0);
}

/* RFC 9221 5.2 (9221-021): a DATAGRAM declared lost is not sent again.
 * Three DATAGRAM packets, then three MAX_DATA packets acknowledged: the
 * DATAGRAMs are three or more below the largest acknowledged (RFC 9002
 * 6.1.1), leave the sent-packet record and flight, and neither the pump,
 * the loss timer nor the PTO tick sends anything for them. */
static void test_srvrun_rfc9221_lost_dg_not_resent(void) {
  struct lp_fix   f;
  srvrun_conn     c;
  u8              obuf[1024], dg[1500] = {0};
  wired_obuf      ob  = {obuf, sizeof obuf, 0};
  srvrun_cfg      cfg = srvrec_cfg();
  srvrun_state    st  = {0, &c};
  srvrun_step_ctx ctx = {&cfg, 0, &st, 1, 0};
  u64             d0, tx, r[1][2];
  srvrec_bare(&c, &f, &ob);
  c.l.now_ms = 0;
  d0         = c.l.tx_pn;
  for (int i = 0; i < 3; i++) {
    wired_obuf dob = obuf_of(dg, sizeof dg);
    CHECK(srvrun_send_datagram_now(&cfg, &c, wired_span_of(dg, 10), &dob));
  }
  r[0][0] = srvrec_ctrl(&c, 0);
  (void)srvrec_ctrl(&c, 0);
  r[0][1] = srvrec_ctrl(&c, 0);
  CHECK(r[0][0] == d0 + 3);
  srvrec_ack_n(&c, r, 1, 0, 1);
  for (u64 pn = d0; pn < d0 + 3; pn++) {
    CHECK(sentmeta_find(&c.l.ackst.sent, pn) == SENTMETA_CAP);
  }
  CHECK(srvrun_bytes_in_flight(&c) == 0);
  tx = c.l.tx_pn;
  srvrun_test_reset_send_count();
  srvrec_pump(&c, 1);
  srvrun_loss_timer_slot(&ctx, 0);
  srvrec_pto_tick(&c, 1000000);
  CHECK(c.l.tx_pn == tx);
  CHECK(srvrun_test_send_count() == 0);
  CHECK(c.dg_pending == 0);
}

/* RFC 9221 5.3 (9221-024): DATAGRAMs are not flow controlled -- one goes
 * out with the connection's MAX_DATA credit fully used (conn_credit equal
 * to the stream bytes consumed), and sending several leaves the credit and
 * the consumed count unchanged. */
static void test_srvrun_rfc9221_dg_ignores_max_data(void) {
  static u8     body[2 * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024], dg[1500] = {0};
  wired_obuf    ob  = {obuf, sizeof obuf, 0};
  srvrun_cfg    cfg = srvrec_cfg();
  usz           used;
  srvrec_conn(&c, &f, body, sizeof body, &ob);
  srvrec_pump(&c, 0);
  used = srvrun_conn_consumed_bytes(&c);
  CHECK(used == sizeof body);
  c.conn_credit = used; /* MAX_DATA reached */
  for (int i = 0; i < 3; i++) {
    wired_obuf dob = obuf_of(dg, sizeof dg);
    u64        tx  = c.l.tx_pn;
    CHECK(srvrun_send_datagram_now(&cfg, &c, wired_span_of(dg, 100), &dob));
    CHECK(c.l.tx_pn == tx + 1);
  }
  CHECK(c.conn_credit == used);
  CHECK(srvrun_conn_consumed_bytes(&c) == used);
}

void test_srvrun_rfc9221(void) {
  test_srvrun_rfc9221_dg_only_packet_acked_within_delay();
  test_srvrun_rfc9221_lost_dg_not_resent();
  test_srvrun_rfc9221_dg_ignores_max_data();
}
