#include "test.h"

/* RFC 9002 5/6 on the server's shipping path (srvrun_feed_acks and the
 * loss-detection/ACK pieces it drives). Expected values are worked by hand
 * from the RFC 9002 Appendix A pseudocode (A.7 UpdateRtt, A.10
 * DetectAndRemoveLostPackets). */

static srvrun_cfg srvrec_cfg(void) {
  srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &g_srvrun_env,
                    0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0,  0};
  return cfg;
}

/* A confirmed connection with resp[0] armed over body (n bytes). */
static void srvrec_conn(
    srvrun_conn* c, struct lp_fix* f, u8* body, usz n, wired_obuf* ob) {
  sr_make_confirmed_conn(c, f, ob);
  c->cc.cwnd           = 1u << 20;
  c->resp[0].in_use    = 1;
  c->resp[0].stream_id = 0;
  wired_sendsess_arm(&c->resp[0].sess, body, n, SRVRUN_CHUNK);
}

/* Log resp[0]'s next slice as sent under pn at t (bookkeeping only). */
static void srvrec_log(srvrun_conn* c, u64 pn, u64 t) {
  wired_sendq_slice sl;
  CHECK(wired_sendsess_take(&c->resp[0].sess, &sl) == 1);
  CHECK(wired_sendsess_sent(&c->resp[0].sess, &sl, pn, t) == 1);
}

/* pn acknowledged by an earlier step, so later steps re-acking it are
 * duplicates: they raise nothing and take no RTT sample, leaving the loss
 * pass alone under test. */
static void srvrec_preacked(srvrun_conn* c, u64 pn) {
  wired_sendsess_ack(&c->resp[0].sess, pn, pn);
  c->largest_acked = pn;
}

/* One step whose ACK frame acknowledges [lo, hi], fed at now_ms. */
static void srvrec_ack(srvrun_conn* c, u64 lo, u64 hi, u64 now_ms) {
  srvrun_cfg      cfg  = srvrec_cfg();
  srvrun_state    st   = {0, c};
  srvrun_step_ctx ctx  = {&cfg, 0, &st, now_ms, 0};
  c->l.ack_lo[0]       = lo;
  c->l.ack_hi[0]       = hi;
  c->l.ack_n           = 1;
  c->l.ackst.largest   = hi;
  c->l.ackst.delay_raw = 0;
  srvrun_feed_acks(&ctx, &cfg, c);
}

/* A confirmed connection with nothing armed. */
static void srvrec_bare(srvrun_conn* c, struct lp_fix* f, wired_obuf* ob) {
  sr_make_confirmed_conn(c, f, ob);
  c->cc.cwnd = 1u << 20;
}

/* One MAX_DATA packet (ack-eliciting control frame) sealed through the
 * production send path at t; its pn. */
static u64 srvrec_ctrl(srvrun_conn* c, u64 t) {
  u8         out[256];
  wired_obuf ob = obuf_of(out, sizeof out);
  u64        pn = c->l.tx_pn;
  c->l.now_ms   = t;
  CHECK(srvrun_seal_max_data(c, 1000000 + pn, &ob) == 1);
  return pn;
}

/* One step whose ACK frames carry the given ranges (largest first) and
 * ACK Delay field, fed at now_ms. */
static void srvrec_ack_n(
    srvrun_conn* c, const u64 (*r)[2], usz n, u64 delay_raw, u64 now_ms) {
  srvrun_cfg      cfg = srvrec_cfg();
  srvrun_state    st  = {0, c};
  srvrun_step_ctx ctx = {&cfg, 0, &st, now_ms, 0};
  for (usz i = 0; i < n; i++) {
    c->l.ack_lo[i] = r[i][0];
    c->l.ack_hi[i] = r[i][1];
  }
  c->l.ack_n           = n;
  c->l.ackst.largest   = r[0][1];
  c->l.ackst.delay_raw = delay_raw;
  srvrun_feed_acks(&ctx, &cfg, c);
}

/* RFC 9002 6.1.2: loss_delay = 9/8 * max(smoothed_rtt, latest_rtt).
 * Samples 8ms then 40ms: smoothed = 7/8*8 + 40/8 = 12ms, latest = 40ms,
 * so loss_delay = 45ms (13.5ms if latest_rtt were ignored). With pn 101
 * acked, pn 100 (1 below, under kPacketThreshold) stays in flight at 29ms
 * and 44ms elapsed and is lost once 45ms have passed. */
static void test_srvrun_rec_time_threshold_latest_rtt(void) {
  static u8     body[2 * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob = {obuf, sizeof obuf, 0};
  srvrec_conn(&c, &f, body, sizeof body, &ob);
  srvrun_rtt_note(&c, 8);
  srvrun_rtt_note(&c, 40);
  CHECK(c.rtt.smoothed_rtt == 12000);
  srvrec_log(&c, 100, 1);
  srvrec_log(&c, 101, 1);
  srvrec_preacked(&c, 101);
  srvrec_ack(&c, 101, 101, 30);
  CHECK(c.resp[0].sess.requeue_n == 0);
  srvrec_ack(&c, 101, 101, 45);
  CHECK(c.resp[0].sess.requeue_n == 0); /* 44ms elapsed < 45ms */
  srvrec_ack(&c, 101, 101, 46);
  CHECK(c.resp[0].sess.requeue_n == 1);
}

/* RFC 9002 6.1.2: the time threshold is at least kGranularity (1ms). A 0ms
 * RTT sample (loopback at ms resolution) gives 9/8 * 0 = 0; without the
 * floor pn0 would be lost the instant pn0+1 is acked. */
static void test_srvrun_rec_granularity_floor(void) {
  static u8     body[2 * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob = {obuf, sizeof obuf, 0};
  srvrec_conn(&c, &f, body, sizeof body, &ob);
  srvrun_rtt_note(&c, 0);
  CHECK(srvrun_loss_delay_us(&c) == RTT_GRANULARITY);
  srvrec_log(&c, 100, 5);
  srvrec_log(&c, 101, 5);
  srvrec_preacked(&c, 101);
  srvrec_ack(&c, 101, 101, 5);
  CHECK(c.resp[0].sess.requeue_n == 0);
  srvrec_ack(&c, 101, 101, 6);
  CHECK(c.resp[0].sess.requeue_n == 1);
}

/* RFC 9000 13.3 on the server path: pn 100 is declared lost by the
 * packet threshold when pn 103 is acked, then a late ACK of pn 100 arrives
 * before the retransmit went out -- the pump must send new data, never
 * pn 100's already-delivered slice. */
static void test_srvrun_rec_spurious_loss_not_resent(void) {
  static u8         body[5 * SRVRUN_CHUNK];
  struct lp_fix     f;
  srvrun_conn       c;
  u8                obuf[1024];
  wired_obuf        ob = {obuf, sizeof obuf, 0};
  wired_sendq_slice sl;
  srvrec_conn(&c, &f, body, sizeof body, &ob);
  for (u64 pn = 100; pn < 104; pn++) {
    srvrec_log(&c, pn, 1);
  }
  srvrec_ack(&c, 101, 103, 2);
  CHECK(c.resp[0].sess.requeue_n == 1);
  srvrec_ack(&c, 100, 100, 3);
  CHECK(c.resp[0].sess.requeue_n == 0);
  CHECK(wired_sendsess_take(&c.resp[0].sess, &sl) == 1);
  CHECK(sl.offset == 4 * SRVRUN_CHUNK); /* new data, not offset 0 */
}

/* RFC 9002 2 / 9002-002: a packet carrying only control frames is in
 * flight from its seal until acknowledged; an ACK-only packet never is; a
 * STREAM packet is counted by its send session's slice bytes, not twice. */
static void test_srvrun_rec_control_packet_counts_inflight(void) {
  static u8     body[SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob = {obuf, sizeof obuf, 0};
  u8            out[256];
  wired_obuf    sob = obuf_of(out, sizeof out);
  u8            ack[16];
  ack_frame     af = {0, 1, {{0, 0}}, 0, 0, 0, 0};
  u64           pn;
  srvrec_conn(&c, &f, body, sizeof body, &ob);
  CHECK(srvrun_bytes_in_flight(&c) == 0);
  pn = srvrec_ctrl(&c, 10);
  CHECK(c.l.ackst.sent.total_in_flight > 0);
  CHECK(srvrun_bytes_in_flight(&c) == c.l.ackst.sent.total_in_flight);
  {
    wired_srvloop_send_in sin = {
        wired_span_of(c.l.cli_scid, c.l.cli_scid_len),
        c.l.tx_pn++,
        -1,
        wired_span_of(ack, ack_encode(ack, sizeof ack, &af)),
        0,
        0,
        0,
        0};
    usz before = c.l.ackst.sent.total_in_flight;
    CHECK(srvloop_send_onertt_rec(&c.l, &c.s, &sin, &sob) == 1);
    CHECK(
        c.l.ackst.sent.total_in_flight == before); /* ACK-only: not in flight */
  }
  {
    srvrun_cfg      cfg    = srvrec_cfg();
    srvrun_state    st     = {0, &c};
    srvrun_step_ctx ctx    = {&cfg, 0, &st, 10, 0};
    usz             before = c.l.ackst.sent.total_in_flight;
    usz             i;
    srvrun_pump_sess(&ctx, 0);
    CHECK(wired_sendsess_inflight(&c.resp[0].sess) == 1);
    /* RFC 9002 2: the whole STREAM packet is in flight -- the session
     * counts the slice, the record the rest: short header (1 + DCID + 4)
     * and AEAD tag (16) at least. */
    i = sentmeta_find(&c.l.ackst.sent, c.l.tx_pn - 1);
    CHECK(i < SENTMETA_CAP);
    CHECK(c.l.ackst.sent.pkts[i].sent_bytes >= 21u + c.l.cli_scid_len);
    CHECK(
        c.l.ackst.sent.total_in_flight ==
        before + c.l.ackst.sent.pkts[i].sent_bytes);
    CHECK(
        srvrun_bytes_in_flight(&c) ==
        SRVRUN_CHUNK + c.l.ackst.sent.total_in_flight);
  }
  srvrec_ack(&c, pn, c.l.tx_pn - 1, 20);
  CHECK(c.l.ackst.sent.total_in_flight == 0);
}

/* RFC 9002 2 (9002-002): the boot flight counts in bytes in flight -- the
 * Initial (100) and the Handshake datagrams sent so far (300 of 300+200)
 * -- until each half's keys are discarded (RFC 9002 6.2.2). */
static void test_srvrun_rec_boot_flight_counts_inflight(void) {
  srvrun_conn c;
  sr_make_boot_conn(&c, 0);
  c.boot_dgram_count  = 2;
  c.boot_dgram_len[0] = 300;
  c.boot_dgram_len[1] = 200;
  c.boot_dgram_sent   = 1;
  CHECK(srvrun_bytes_in_flight(&c) == 400);
  c.l.hs_rx_seen = 1; /* Initial keys discarded */
  CHECK(srvrun_bytes_in_flight(&c) == 300);
  c.s.phase = WIRED_SERVER_HS_CONFIRMED; /* Handshake keys discarded */
  CHECK(srvrun_bytes_in_flight(&c) == 0);
}

/* RFC 9002 5.1: one RTT sample per ACK frame, from its largest
 * acknowledged packet. Packets at t=0/100/200, one frame acking
 * {pn2} and {pn0} at t=215: the sample is 215-200 = 15ms, taken once
 * (srtt_ms == 15, not blended with a 215ms sample). */
static void test_srvrun_rec_one_sample_per_frame(void) {
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob = {obuf, sizeof obuf, 0};
  u64           pn0, pn2;
  srvrec_bare(&c, &f, &ob);
  pn0 = srvrec_ctrl(&c, 0);
  srvrec_ctrl(&c, 100);
  pn2 = srvrec_ctrl(&c, 200);
  {
    const u64 r[2][2] = {{pn2, pn2}, {pn0, pn0}};
    srvrec_ack_n(&c, r, 2, 0, 215);
  }
  CHECK(c.rtt.have_sample == 1);
  CHECK(c.latest_rtt_ms == 15);
  CHECK(c.srtt_ms == 15);
  CHECK(c.rtt.smoothed_rtt == 15000);
}

/* RFC 9002 5.1 / 9002-006: an ACK whose largest acknowledged was already
 * acknowledged takes no sample, even when it newly acks a lower packet. */
static void test_srvrun_rec_no_sample_when_largest_old(void) {
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob = {obuf, sizeof obuf, 0};
  u64           pn0, pn1;
  srvrec_bare(&c, &f, &ob);
  pn0 = srvrec_ctrl(&c, 0);
  pn1 = srvrec_ctrl(&c, 10);
  srvrec_ack(&c, pn1, pn1, 20);
  CHECK(c.latest_rtt_ms == 10);
  {
    const u64 r[1][2] = {{pn0, pn1}};
    srvrec_ack_n(&c, r, 1, 0, 300);
  }
  CHECK(c.latest_rtt_ms == 10);
  CHECK(c.rtt.smoothed_rtt == 10000);
  CHECK(c.l.ackst.sent.total_in_flight == 0); /* pn0 still left flight */
}

/* RFC 9002 5.1 / A.7 / 9002-007: newly acking only non-ack-eliciting
 * packets (an ACK-only packet) takes no sample. */
static void test_srvrun_rec_no_sample_ack_only(void) {
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob = {obuf, sizeof obuf, 0};
  u8            out[256];
  wired_obuf    sob = obuf_of(out, sizeof out);
  u8            ack[16];
  ack_frame     af = {0, 1, {{0, 0}}, 0, 0, 0, 0};
  u64           pn;
  srvrec_bare(&c, &f, &ob);
  pn         = c.l.tx_pn;
  c.l.now_ms = 0;
  {
    wired_srvloop_send_in sin = {
        wired_span_of(c.l.cli_scid, c.l.cli_scid_len),
        c.l.tx_pn++,
        -1,
        wired_span_of(ack, ack_encode(ack, sizeof ack, &af)),
        0,
        0,
        0,
        0};
    CHECK(srvloop_send_onertt_rec(&c.l, &c.s, &sin, &sob) == 1);
  }
  srvrec_ack(&c, pn, pn, 30);
  CHECK(c.rtt.have_sample == 0);
  CHECK(sentmeta_find(&c.l.ackst.sent, pn) == SENTMETA_CAP); /* still dropped */
}

/* Two samples on a confirmed connection: 50ms, then latest_ms with the
 * given raw ACK Delay; the resulting smoothed_rtt (us). */
static u64 srvrec_two_samples(u64 latest_ms, u64 delay_raw, u64 exp_p1) {
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob = {obuf, sizeof obuf, 0};
  u64           pn;
  srvrec_bare(&c, &f, &ob);
  c.s.sdrv.peer_ack_delay_exponent_p1 = exp_p1;
  pn                                  = srvrec_ctrl(&c, 0);
  srvrec_ack(&c, pn, pn, 50);
  pn = srvrec_ctrl(&c, 100);
  {
    const u64 r[1][2] = {{pn, pn}};
    srvrec_ack_n(&c, r, 1, delay_raw, 100 + latest_ms);
  }
  CHECK(c.rtt.min_rtt == 50000);
  return c.rtt.smoothed_rtt;
}

/* RFC 9002 5.3 / A.7 UpdateRtt after confirmation, first sample 50ms
 * (smoothed 50000us):
 * - ACK Delay 2500 << default exponent 3 = 20ms <= max_ack_delay 25ms:
 *   adjusted = 100 - 20 = 80ms, smoothed = (7*50000 + 80000)/8 = 53750
 * - 5000 << 3 = 40ms, clamped to 25ms: adjusted 75ms -> 53125
 * - 60ms with 20ms delay: 60 < min_rtt 50 + 20, so not subtracted (5.3
 *   9002-017): adjusted 60ms -> 51250
 * - exponent 0 from the peer's transport parameter: 20000 raw = 20ms. */
static void test_srvrun_rec_ack_delay_applied(void) {
  CHECK(srvrec_two_samples(100, 2500, 0) == 53750);
  CHECK(srvrec_two_samples(100, 5000, 0) == 53125);
  CHECK(srvrec_two_samples(60, 2500, 0) == 51250);
  CHECK(srvrec_two_samples(100, 20000, 1) == 53750);
}

/* RFC 9000 18.2: the peer's max_ack_delay (1 + value in sdrv, 0 = absent)
 * defaults to 25ms and otherwise is taken as advertised. */
static void test_srvrun_rec_peer_max_ack_delay(void) {
  srvrun_conn c = {0};
  CHECK(srvrun_peer_max_ack_delay_us(&c) == 25000);
  c.s.sdrv.peer_max_ack_delay_p1 = 1;
  CHECK(srvrun_peer_max_ack_delay_us(&c) == 0);
  c.s.sdrv.peer_max_ack_delay_p1 = 11;
  CHECK(srvrun_peer_max_ack_delay_us(&c) == 10000);
}

/* Two slices of resp[0] sent through the pump at t=0; pn of the first. */
static u64 srvrec_pump_two(srvrun_conn* c) {
  srvrun_cfg      cfg = srvrec_cfg();
  srvrun_state    st  = {0, c};
  srvrun_step_ctx ctx = {&cfg, 0, &st, 0, 0};
  u64             pn0 = c->l.tx_pn;
  c->l.now_ms         = 0;
  srvrun_pump_sess(&ctx, 0);
  CHECK(wired_sendsess_inflight(&c->resp[0].sess) == 2);
  return pn0;
}

/* RFC 9002 6.1.2 / A.10 / 9002-023: pn0+1 acked at t=8 gives the first
 * sample, 8ms: loss_delay = 9/8 * 8 = 9ms, so pn0 (sent t=0) cannot be
 * declared lost yet and the loss timer is armed for t=9ms. The tick does
 * nothing at t=8; at t=9 it declares pn0 lost, shrinks the window and the
 * pump resends it -- no further ACK needed. */
static void test_srvrun_rec_loss_timer_fires(void) {
  static u8       body[2 * SRVRUN_CHUNK];
  struct lp_fix   f;
  srvrun_conn     c;
  u8              obuf[1024];
  wired_obuf      ob  = {obuf, sizeof obuf, 0};
  srvrun_cfg      cfg = srvrec_cfg();
  srvrun_state    st  = {0, &c};
  srvrun_step_ctx ctx = {&cfg, 0, &st, 8, 0};
  u64             pn0, cwnd, tx;
  srvrec_conn(&c, &f, body, sizeof body, &ob);
  pn0 = srvrec_pump_two(&c);
  srvrec_ack(&c, pn0 + 1, pn0 + 1, 8);
  CHECK(c.rtt.smoothed_rtt == 8000);
  CHECK(c.resp[0].sess.requeue_n == 0);
  CHECK(c.loss_time_us == 9000);
  CHECK(srvrun_slot_waiting(&c)); /* the poll loop keeps ticking for it */
  cwnd = c.cc.cwnd;
  tx   = c.l.tx_pn;
  srvrun_loss_timer_slot(&ctx, 0);
  CHECK(c.l.tx_pn == tx && c.loss_time_us == 9000);
  ctx.now_ms = 9;
  srvrun_loss_timer_slot(&ctx, 0);
  CHECK(c.cc.cwnd < cwnd);
  CHECK(c.l.tx_pn == tx + 1); /* the lost slice went out again */
  CHECK(c.resp[0].sess.requeue_n == 0);
  CHECK(c.loss_time_us == 0);
}

/* RFC 9002 6.2.1 / A.8 (9002-030, 9002-034): the 1-RTT PTO is set only
 * once the handshake is confirmed and never while the loss timer is.
 * Exhaustive over {confirmed, loss timer armed, PTO deadline passed} with
 * an ack-eliciting packet in flight: a probe (pto_count 1) only on the row
 * confirmed, unarmed, due. */
static void test_srvrun_rec_loss_timer_suppresses_pto(void) {
  static const struct {
    int confirmed, armed, pto_due, probed;
  } rows[] = {{0, 0, 0, 0}, {0, 0, 1, 0}, {0, 1, 0, 0}, {0, 1, 1, 0},
              {1, 0, 0, 0}, {1, 0, 1, 1}, {1, 1, 0, 0}, {1, 1, 1, 0}};
  for (usz i = 0; i < sizeof rows / sizeof rows[0]; i++) {
    static u8       body[2 * SRVRUN_CHUNK];
    struct lp_fix   f;
    srvrun_conn     c;
    u8              obuf[1024];
    wired_obuf      ob  = {obuf, sizeof obuf, 0};
    srvrun_cfg      cfg = srvrec_cfg();
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0, 0};
    u64             pn0;
    srvrec_conn(&c, &f, body, sizeof body, &ob);
    pn0 = srvrec_pump_two(&c);
    srvrec_ack(&c, pn0 + 1, pn0 + 1, 8);
    c.loss_time_us = rows[i].armed ? 9000 : 0;
    if (!rows[i].confirmed) {
      c.s.phase = WIRED_SERVER_HS_INITIAL;
    }
    ctx.now_ms = rows[i].pto_due ? 10000 : 1;
    srvrun_pto_slot(&ctx, 0);
    CHECK(c.l.ackst.pto_count == rows[i].probed);
  }
}

/* One client 1-RTT PING packet pn stepped through the loop (datagram ECN
 * codepoint ecn); 1 if the step answered it with a packet right away. */
static int srvrec_ping(struct lp_fix* f, u64 pn, u8 ecn) {
  u8         ping[1] = {0x01}, spkt[256], out[1024];
  wired_obuf ob      = {out, sizeof out, 0};
  usz        n       = client_seal_onertt_pn(f, pn, ping, 1, spkt, sizeof spkt);
  f->l.rx_ecn        = ecn; /* counted inside the step once the packet opens */
  wired_srvloop_step(
      &(wired_srvloop_conn){&f->l, &f->s}, wired_mspan_of(spkt, n), &ob);
  return ob.len != 0;
}

/* RFC 9000 13.2.1: a lone in-order ack-eliciting packet waits out the
 * delay window (the clock never moves here); one after a gap, one below
 * the largest received (reordered) and one in an ECN-CE datagram are each
 * acknowledged at once. */
static void test_srvrun_rec_ack_immediate_on_gap_reorder_ce(void) {
  struct lp_fix f;
  u8            out[1024];
  wired_obuf    ob = {out, sizeof out, 0};
  u8            buf[288];
  lp_confirm(&f, &ob);
  srvrec_ping(&f, 20, 0);
  srvloop_app_ack_append(&f.l, buf, sizeof buf); /* start from nothing owed */
  CHECK(srvrec_ping(&f, 21, 0) == 0);            /* in order: delayed */
  CHECK(f.l.app_ack_policy.pending == 1);
  srvloop_app_ack_append(&f.l, buf, sizeof buf);
  CHECK(srvrec_ping(&f, 23, 0) == 1); /* pn 22 missing */
  CHECK(f.l.app_ack_policy.pending == 0);
  CHECK(srvrec_ping(&f, 22, 0) == 1); /* below 23: reordered */
  CHECK(srvrec_ping(&f, 24, 3) == 1); /* ECN-CE */
  CHECK(srvrec_ping(&f, 25, 2) == 0); /* ECT(0), in order: delayed */
}

/* Decode the ACK the loop would send now (marking one owed first: the
 * gapped pings below were each already acknowledged on arrival). */
static void srvrec_peek_ack(wired_srvloop* l, ack_frame* f) {
  u8  buf[300];
  usz n;
  ackpolicy_on_eliciting(&l->app_ack_policy, 0);
  n = wired_srvloop_ack_peek(l, buf, sizeof buf);
  CHECK(n != 0 && ack_decode(buf, n, f) == n);
}

/* RFC 9000 13.2.3: once the peer acknowledges a packet of ours that carried
 * an ACK with Largest Acknowledged 25, later ACKs stop reporting packets at
 * or below 25: after pn 27 arrives only [27, 27] is left. */
static void test_srvrun_rec_ack_prunes_acked_ranges(void) {
  struct lp_fix f;
  u8            out[1024];
  wired_obuf    ob = {out, sizeof out, 0};
  ack_frame     a;
  u64           ours;
  lp_confirm(&f, &ob);
  srvrec_ping(&f, 21, 0);
  srvrec_ping(&f, 23, 0);
  srvrec_ping(&f, 25, 0);
  {
    u8         pl[300];
    u8         sealed[1500];
    wired_obuf sob = obuf_of(sealed, sizeof sealed);
    usz        al;
    ackpolicy_on_eliciting(&f.l.app_ack_policy, 0);
    al                        = wired_srvloop_ack_peek(&f.l, pl, sizeof pl);
    wired_srvloop_send_in sin = {
        wired_span_of(f.l.cli_scid, f.l.cli_scid_len),
        f.l.tx_pn++,
        -1,
        wired_span_of(pl, al),
        0,
        0,
        0,
        0};
    ours = sin.pn;
    CHECK(al != 0);
    CHECK(srvloop_send_onertt_rec(&f.l, &f.s, &sin, &sob) == 1);
  }
  {
    u8        pa[32];
    ack_frame peer = {0, 1, {{ours, ours}}, 0, 0, 0, 0};
    usz       n    = ack_encode(pa, sizeof pa, &peer);
    srvloop_collect_acks(&f.l, wired_span_of(pa, n));
  }
  CHECK(f.l.ackst.floor1 == 26);
  srvrec_ping(&f, 27, 0);
  srvrec_peek_ack(&f.l, &a);
  CHECK(a.n_ranges == 1);
  CHECK(a.ranges[0].hi == 27 && a.ranges[0].lo == 27);
}

/* Seal one 1-RTT packet carrying pl through the recorded send path. */
static void srvrec_send_rec(struct lp_fix* f, const u8* pl, usz n) {
  u8                    sealed[1500];
  wired_obuf            sob = obuf_of(sealed, sizeof sealed);
  wired_srvloop_send_in sin = {
      wired_span_of(f->l.cli_scid, f->l.cli_scid_len),
      f->l.tx_pn++,
      -1,
      wired_span_of(pl, n),
      0,
      0,
      0,
      0};
  CHECK(srvloop_send_onertt_rec(&f->l, &f->s, &sin, &sob) == 1);
}

/* RFC 9000 10.1: the idle timer restarts at the first ack-eliciting send
 * since the last receive, whatever the packet carries (here a PING, no
 * STREAM frame); a bare ACK does not, and a later send does not move it. */
static void test_srvrun_rec_idle_restarts_on_any_eliciting(void) {
  struct lp_fix f;
  u8            out[1500];
  wired_obuf    ob   = {out, sizeof out, 0};
  u8            ping = 0x01;
  u8            ack[16];
  ack_frame     a  = {0, 1, {{0, 0}}, 0, 0, 0, 0};
  usz           an = ack_encode(ack, sizeof ack, &a);
  lp_confirm(&f, &ob);
  f.l.ackst.idle_tx_ms = 0;
  f.l.now_ms           = 4000;
  srvrec_send_rec(&f, ack, an);
  CHECK(f.l.ackst.idle_tx_ms == 0);
  f.l.now_ms = 5000;
  srvrec_send_rec(&f, &ping, 1);
  CHECK(f.l.ackst.idle_tx_ms == 5000);
  f.l.now_ms = 6000;
  srvrec_send_rec(&f, &ping, 1);
  CHECK(f.l.ackst.idle_tx_ms == 5000);
}

/* RFC 9000 13.2.4: 33 separate ranges in the receive window (every other
 * pn, 100..164) exceed ACK_MAX_RANGES; the ACK still goes out with the 32
 * newest instead of not at all. */
static void test_srvrun_rec_ack_truncates_ranges(void) {
  struct lp_fix f;
  u8            out[1024];
  wired_obuf    ob = {out, sizeof out, 0};
  ack_frame     a;
  lp_confirm(&f, &ob);
  for (u64 pn = 100; pn <= 164; pn += 2) {
    srvrec_ping(&f, pn, 0);
  }
  srvrec_peek_ack(&f.l, &a);
  CHECK(a.n_ranges == ACK_MAX_RANGES);
  CHECK(a.ranges[0].hi == 164 && a.ranges[31].lo == 102);
}

/* RFC 9000 13.2.1 / 18.2: an ACK owed with no further packet arriving is
 * sent from the poll tick once the delay window passes, and the advertised
 * max_ack_delay covers that window plus the tick. */
static void test_srvrun_rec_tick_flushes_ack(void) {
  struct lp_fix   f;
  srvrun_conn     c;
  u8              obuf[1024];
  wired_obuf      ob  = {obuf, sizeof obuf, 0};
  srvrun_cfg      cfg = srvrec_cfg();
  srvrun_state    st  = {0, &c};
  srvrun_step_ctx ctx = {&cfg, 0, &st, 10, 0};
  u64             tx;
  CHECK(
      STP_DEFAULT_MAX_ACK_DELAY_MS >=
      WIRED_SRVLOOP_MAX_ACK_DELAY_MS + SRVRUN_PTO_MS);
  srvrec_bare(&c, &f, &ob);
  ackpolicy_on_ack_sent(&c.l.app_ack_policy);
  pnspaces_on_recv(&c.l.ack_recv, PNS_APP, 40);
  ackpolicy_on_eliciting(&c.l.app_ack_policy, 0);
  CHECK(srvrun_slot_waiting(&c));
  tx         = c.l.tx_pn;
  c.l.now_ms = 10;
  srvrun_ack_tick_slot(&ctx, 0);
  CHECK(c.l.tx_pn == tx && c.l.app_ack_policy.pending == 1);
  c.l.now_ms = ctx.now_ms = WIRED_SRVLOOP_MAX_ACK_DELAY_MS;
  srvrun_ack_tick_slot(&ctx, 0);
  CHECK(c.l.tx_pn == tx + 1 && c.l.app_ack_policy.pending == 0);
}

/* RFC 9002 6.2.1: the Initial/Handshake PTO leaves max_ack_delay out.
 * srtt 10ms, rttvar 5ms: PTO = 10 + max(4*5, 1) = 30ms, not 30 + 25. */
static void test_srvrun_boot_pto_no_max_ack_delay(void) {
  conntable       table[WIRED_CONNTABLE_CAP];
  srvrun_state    st  = {table, sr_test_conns()};
  srvrun_cfg      cfg = srvrec_cfg();
  srvrun_step_ctx ctx = {&cfg, 0, &st, 1000 + 29, 0};
  conntable_init(table, WIRED_CONNTABLE_CAP);
  sr_make_boot_conn(&st.conns[0], 1000);
  st.conns[0].rtt.smoothed_rtt = 10000;
  st.conns[0].rtt.rttvar       = 5000;
  srvrun_test_reset_send_count();
  srvrun_boot_pto_slot(&ctx, 0);
  CHECK(st.conns[0].boot_pto_count == 0);
  ctx.now_ms = 1000 + 30;
  srvrun_boot_pto_slot(&ctx, 0);
  CHECK(srvrun_test_send_count() > 0);
  CHECK(st.conns[0].boot_pto_count == 1);
}

/* RFC 9002 6.2.2 / A.11: discarding the Initial keys resets the boot PTO
 * backoff (pto_count = 0); a step that leaves them alone does not. */
static void test_srvrun_boot_pto_resets_on_initial_discard(void) {
  srvrun_conn   c;
  srvrun_rxmark m;
  sr_make_boot_conn(&c, 0);
  c.boot_pto_count = 3;
  m                = srvrun_rx_mark(&c.l);
  srvrun_boot_on_rx(&c, &m);
  CHECK(c.boot_pto_count == 3); /* hs_rx_seen still 0 */
  c.l.hs_rx_seen = 1;
  m              = srvrun_rx_mark(&c.l);
  srvrun_boot_on_rx(&c, &m);
  CHECK(c.boot_pto_count == 3); /* already discarded before this step */
  m.hs_seen = 0;
  srvrun_boot_on_rx(&c, &m);
  CHECK(c.boot_pto_count == 0);
}

/* RFC 9002 6.2.1: "The PTO backoff factor is reset when an acknowledgment
 * is received" -- a step that newly acknowledged a Handshake packet resets
 * the boot backoff; one that acknowledged nothing new does not, and
 * neither does an ACK of a number never sent (RFC 9002 A.7: only a sent
 * packet is newly acknowledged). */
static void test_srvrun_boot_pto_resets_on_hs_ack(void) {
  srvrun_conn   c;
  srvrun_rxmark m;
  sr_make_boot_conn(&c, 0);
  c.boot_dgram_sent = 2; /* pn 0 and 1 sent */
  c.l.hs_rx_seen    = 1;
  c.l.hs_acked      = 1;
  c.boot_pto_count  = 3;
  m                 = srvrun_rx_mark(&c.l);
  srvrun_boot_on_rx(&c, &m);
  CHECK(c.boot_pto_count == 3);
  c.l.hs_acked |= 1u << 5; /* never sent */
  srvrun_boot_on_rx(&c, &m);
  CHECK(c.boot_pto_count == 3);
  c.l.hs_acked |= 2;
  srvrun_boot_on_rx(&c, &m);
  CHECK(c.boot_pto_count == 0);
}

/* RFC 9000 19.3: srvloop_acked_bits folds every ACK frame of a payload
 * into a bitmask of acknowledged packet numbers below 32. Worked by hand:
 * ranges [3,3] and [0,1] -> bits 0,1,3 = 0xb; [30,40] -> bits 30,31 =
 * 0xc0000000; [40,50] -> 0 (nothing below 32). A PING (0x01) ahead of
 * the ACK is walked past. */
static void test_srvloop_acked_bits(void) {
  ack_frame f = {0};
  u8        pl[64];
  usz       n;
  pl[0]       = 0x01; /* PING, RFC 9000 19.2 */
  f.n_ranges  = 2;
  f.ranges[0] = (ack_range){.hi = 3, .lo = 3};
  f.ranges[1] = (ack_range){.hi = 1, .lo = 0};
  n           = ack_encode(pl + 1, sizeof pl - 1, &f);
  CHECK(n != 0);
  CHECK(srvloop_acked_bits(wired_span_of(pl, 1 + n)) == 0xbu);
  f.n_ranges  = 1;
  f.ranges[0] = (ack_range){.hi = 40, .lo = 30};
  n           = ack_encode(pl, sizeof pl, &f);
  CHECK(srvloop_acked_bits(wired_span_of(pl, n)) == 0xc0000000u);
  f.ranges[0] = (ack_range){.hi = 50, .lo = 40};
  n           = ack_encode(pl, sizeof pl, &f);
  CHECK(srvloop_acked_bits(wired_span_of(pl, n)) == 0);
}

/* A real boot (sr_boot_with_budget: one client Initial served at now 0)
 * that the boot-PTO-per-space tests below drive. */
typedef struct {
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32], dg[PMTU_MAX];
  conntable        table[WIRED_CONNTABLE_CAP];
  sockaddr         peer;
  srvrun_state     st;
  srvrun_cfg       cfg;
  srvrun_step_ctx  ctx;
  srvrun_conn*     c;
} srvrec_bootfix;

/* Boot f with `budget` antiamp bytes left; each space last sent at ini_ms /
 * hs_ms (RFC 9002 A.8 time_of_last_ack_eliciting_packet). */
static void srvrec_boot(srvrec_bootfix* f, u64 budget, u64 ini_ms, u64 hs_ms) {
  bytes_memset(&f->peer, 0, sizeof f->peer);
  sr_make_id(&f->id, f->priv, f->pub, f->seed, f->rnd);
  f->st  = (srvrun_state){f->table, g_srvrun_state.conns};
  f->cfg = sr_antiamp_cfg(&f->id);
  f->ctx = (srvrun_step_ctx){&f->cfg, &f->peer, &f->st, 0, 0};
  f->c   = sr_boot_with_budget(&f->ctx, f->dg, sizeof f->dg, budget);
  CHECK(f->c->up == 1);
  CHECK(wired_server_is_confirmed(&f->c->s) == 0);
  f->c->boot_sent_ms[SRVRUN_BOOT_SP_INI] = ini_ms;
  f->c->boot_sent_ms[SRVRUN_BOOT_SP_HS]  = hs_ms;
}

/* Bytes of the first `max` cached Handshake datagrams whose packet number
 * (= datagram index, srvboot_seal_next) is not in `skip`. */
static u64 srvrec_hs_bytes(const srvrun_conn* c, u32 skip, usz max) {
  u64 sum = 0;
  usz got = 0;
  for (usz i = 0; i < c->boot_dgram_count && got < max; i++) {
    if (!(skip >> i & 1)) {
      sum += c->boot_dgram_len[i];
      got++;
    }
  }
  return sum;
}

/* Client role: one ACK-only packet acknowledging server pn `acked`, sealed
 * toward c's SCID under keys k -- an Initial (byte0 0xc0, padded to the
 * RFC 9000 14.1 1200-byte floor) or a Handshake packet (byte0 0xe0). */
static usz srvrec_client_pkt(
    const srvrun_conn*  c,
    const initial_keys* k,
    u8                  byte0,
    wired_span          pl,
    u8*                 out) {
  aes128 hp;
  aes128_init(&hp, k->hp);
  {
    protect_keys pk = {k, &hp, 0};
    tx_desc      t  = {
        byte0,
        wired_span_of(c->s.sdrv.iscid, c->s.sdrv.iscid_len),
        wired_span_of(g_cli_scid, 6),
        byte0 == 0xc0,
        wired_span_of((const u8*)0, 0),
        1,
        pl,
        0};
    return tx_packet(&pk, &t, wired_mspan_of(out, PMTU_MAX));
  }
}

static usz srvrec_client_ack(
    const srvrun_conn* c, const initial_keys* k, u8 byte0, u64 acked, u8* out) {
  ack_frame f        = {0};
  u8        pl[1170] = {0};
  f.n_ranges         = 1;
  f.ranges[0]        = (ack_range){.hi = acked, .lo = acked};
  CHECK(ack_encode(pl, sizeof pl, &f) != 0);
  return srvrec_client_pkt(
      c, k, byte0, wired_span_of(pl, byte0 == 0xc0 ? sizeof pl : 24), out);
}

/* The client's Initial keys (RFC 9001 5.2: from the original DCID). */
static initial_keys srvrec_client_ini_keys(void) {
  initial_keys ck, sk;
  initpkt_derive_ver(wired_span_of(g_sr_odcid, 8), VERSION_1, &ck, &sk);
  return ck;
}

/* The client's Initial ACK of the server's ServerHello Initial. */
static usz srvrec_client_ini_ack(const srvrun_conn* c, u8* out) {
  initial_keys ck = srvrec_client_ini_keys();
  return srvrec_client_ack(c, &ck, 0xc0, c->ini_next_pn - 1, out);
}

/* A padded client Initial whose one CRYPTO frame carries 8 bytes at Initial
 * stream offset `off`. */
static usz srvrec_client_ini_crypto(const srvrun_conn* c, u64 off, u8* out) {
  static const u8       data[8]  = {1, 0, 0, 4, 3, 3, 0, 0};
  u8                    pl[1170] = {0};
  wired_obuf            ob       = obuf_of(pl, sizeof pl);
  crypto_stream_emit_in ein      = {off, 1024};
  initial_keys          ck       = srvrec_client_ini_keys();
  CHECK(crypto_stream_emit(wired_span_of(data, sizeof data), &ein, &ob));
  return srvrec_client_pkt(c, &ck, 0xc0, wired_span_of(pl, sizeof pl), out);
}

/* The client's Handshake ACK of server Handshake pn `acked`. */
static usz srvrec_client_hs_ack(const srvrun_conn* c, u64 acked, u8* out) {
  const initial_keys* k;
  CHECK(keysched_get(&c->s.sched, KS_CLIENT_HS, &k) == 1);
  return srvrec_client_ack(c, k, 0xe0, acked, out);
}

/* RFC 9002 6.2.1 / A.8: one PTO timer, armed from the EARLIEST of the
 * spaces with ack-eliciting data in flight; on expiry only that space is
 * probed (6.2.4), its own send time restarts and the shared pto_count
 * doubles. Initial sent at 0, Handshake at 50, the boot wait capped at
 * SRVRUN_BOOT_RESEND_CAP_MS: at the cap the Initial alone goes, 50ms later
 * the Handshake alone (at most two datagrams, 6.2.4). */
static void test_srvrun_boot_pto_earliest_space(void) {
  srvrec_bootfix f;
  u64            tx;
  srvrec_boot(&f, 3 * 1220, 0, 50);
  f.c->boot_rx_bytes = 100000; /* the antiamp budget is not under test */
  f.ctx.now_ms       = SRVRUN_BOOT_RESEND_CAP_MS;
  tx                 = f.c->boot_tx_bytes;
  srvrun_boot_pto_slot(&f.ctx, 0);
  CHECK(f.c->boot_tx_bytes - tx == f.c->boot_ini_len);
  CHECK(f.c->boot_sent_ms[SRVRUN_BOOT_SP_INI] == SRVRUN_BOOT_RESEND_CAP_MS);
  CHECK(f.c->boot_sent_ms[SRVRUN_BOOT_SP_HS] == 50);
  CHECK(f.c->boot_pto_count == 1);
  f.ctx.now_ms = 50 + SRVRUN_BOOT_RESEND_CAP_MS;
  tx           = f.c->boot_tx_bytes;
  srvrun_boot_pto_slot(&f.ctx, 0);
  CHECK(f.c->boot_tx_bytes - tx == srvrec_hs_bytes(f.c, 0, 2));
  CHECK(f.c->boot_sent_ms[SRVRUN_BOOT_SP_HS] == 50 + SRVRUN_BOOT_RESEND_CAP_MS);
  CHECK(f.c->boot_pto_count == 2);
}

/* RFC 9002 6.2.4 / RFC 9000 8.1: an Initial-space probe carries the
 * ServerHello Initial and nothing else -- with budget left for the Initial
 * plus one Handshake datagram, no Handshake byte (undecryptable to a client
 * still lacking the ServerHello) rides along. */
static void test_srvrun_boot_pto_initial_probe_no_handshake(void) {
  srvrec_bootfix f;
  u64            tx;
  srvrec_boot(&f, 3 * 1220, 0, 0);
  f.c->boot_tx_bytes =
      3 * f.c->boot_rx_bytes - f.c->boot_ini_len - f.c->boot_dgram_len[0];
  f.ctx.now_ms = SRVRUN_BOOT_RESEND_CAP_MS;
  tx           = f.c->boot_tx_bytes;
  srvrun_boot_pto_slot(&f.ctx, 0); /* a tie goes to Initial (A.8 order) */
  CHECK(f.c->boot_tx_bytes - tx == f.c->boot_ini_len);
}

/* RFC 9002 6.2.1 / A.8: once the client acknowledged the ServerHello
 * Initial, that space has nothing in flight and only the Handshake space
 * arms the timer. A client Initial carrying only that ACK is no
 * retransmission request (RFC 9002 6.2: retransmission is driven by loss
 * detection and the PTO), so it sends nothing by itself. */
static void test_srvrun_boot_pto_handshake_only_after_initial_acked(void) {
  srvrec_bootfix f;
  u8             ack[PMTU_MAX];
  usz            n;
  u64            tx;
  srvrec_boot(&f, 3 * 1220, 0, 0);
  f.c->boot_rx_bytes  = 100000;
  f.c->boot_pto_count = 1;
  n                   = srvrec_client_ini_ack(f.c, ack);
  srvrun_test_reset_send_count();
  srvrun_serve(&f.ctx, wired_mspan_of(ack, n));
  CHECK(f.c->boot_ini_acked == 1);
  CHECK(f.c->boot_pto_count == 0); /* RFC 9002 6.2.1: reset on an ACK */
  CHECK(srvrun_test_send_count() == 0);
  /* RFC 9002 A.7: an ACK of the already acknowledged ServerHello newly
   * acknowledges nothing, so the backoff stays */
  f.c->boot_pto_count = 2;
  srvrun_serve(&f.ctx, wired_mspan_of(ack, srvrec_client_ini_ack(f.c, ack)));
  CHECK(f.c->boot_pto_count == 2);
  f.c->boot_pto_count                  = 0;
  f.c->boot_sent_ms[SRVRUN_BOOT_SP_HS] = 50;
  f.ctx.now_ms                         = SRVRUN_BOOT_RESEND_CAP_MS;
  tx                                   = f.c->boot_tx_bytes;
  srvrun_boot_pto_slot(&f.ctx, 0); /* the Initial would be due: not armed */
  CHECK(f.c->boot_tx_bytes == tx);
  CHECK(f.c->boot_pto_count == 0);
  f.ctx.now_ms = 50 + SRVRUN_BOOT_RESEND_CAP_MS;
  srvrun_boot_pto_slot(&f.ctx, 0);
  CHECK(f.c->boot_tx_bytes - tx == srvrec_hs_bytes(f.c, 0, 2));
  CHECK(f.c->boot_pto_count == 1);
}

/* RFC 9002 6.2.4: a probe may "retransmit unacknowledged data" -- a
 * Handshake packet the client acknowledged is never sent again, neither by
 * the replay its Handshake datagram triggers (srvrun_hs_probe_pending) nor
 * by a later Handshake PTO. This fixture's flight is one Handshake datagram
 * (pn 0); once it is acknowledged (and the Initial keys are gone with the
 * client's Handshake packet) nothing is in flight and nothing is sent -- an
 * interop server re-sent such an acknowledged pn 0 54 times. */
static void test_srvrun_boot_pto_skips_acked_handshake(void) {
  srvrec_bootfix f;
  u8             ack[PMTU_MAX];
  usz            n;
  u64            tx;
  srvrec_boot(&f, 3 * 1220, 0, 0);
  CHECK(f.c->boot_dgram_count >= 1);
  f.c->boot_pto_count = 3;
  n                   = srvrec_client_hs_ack(f.c, 0, ack);
  tx                  = f.c->boot_tx_bytes;
  srvrun_serve(&f.ctx, wired_mspan_of(ack, n));
  CHECK(f.c->l.hs_acked == 1);
  CHECK(f.c->boot_pto_count == 0); /* RFC 9002 6.2.1: reset on an ACK */
  CHECK(f.c->boot_tx_bytes - tx == srvrec_hs_bytes(f.c, 1, 32));
  f.c->boot_sent_ms[SRVRUN_BOOT_SP_HS] = 0;
  f.ctx.now_ms                         = SRVRUN_BOOT_RESEND_CAP_MS;
  tx                                   = f.c->boot_tx_bytes;
  srvrun_boot_pto_slot(&f.ctx, 0);
  CHECK(f.c->boot_tx_bytes - tx == srvrec_hs_bytes(f.c, 1, 2));
  CHECK(f.c->boot_pto_count == (f.c->boot_dgram_count > 1));
}

/* RFC 9000 8.1 / 12.3: once a client Handshake packet validated the
 * address no 3x limit bounds a replay, so a datagram that only LOOKS like a
 * Handshake probe (long header, nothing opens) replays nothing; with the
 * boot PTO not yet due nothing at all goes out. */
static void test_srvrun_boot_unopened_hs_header_no_replay(void) {
  srvrec_bootfix f;
  u8             junk[64];
  usz            n;
  u64            tx;
  srvrec_boot(&f, 3 * 1220, 0, 0);
  f.c->l.hs_rx_seen  = 1;
  f.c->boot_rx_bytes = 100000;
  CHECK(srvrun_boot_hs_armed(f.c) == 1);
  n  = sr_append_handshake_pkt(junk, 0, f.c->scid, f.id.scid_len);
  tx = f.c->boot_tx_bytes;
  for (int i = 0; i < 5; i++) {
    srvrun_serve(&f.ctx, wired_mspan_of(junk, n));
  }
  CHECK(f.c->boot_tx_bytes == tx);
  CHECK(f.c->up == 1);
}

/* RFC 9002 6.2.1: a replay triggered by a processed client Handshake probe
 * counts toward SRVRUN_BOOT_PTO_MAX like a PTO probe; with the budget
 * spent a probe replays nothing, and the next boot PTO ends the
 * Handshake-proven boot -- a client that keeps probing without ever
 * acknowledging cannot hold the slot or keep the flight coming. */
static void test_srvrun_boot_probe_budget_ends_exempt_boot(void) {
  srvrec_bootfix f;
  u8             hs[PMTU_MAX];
  usz            n;
  u64            tx;
  srvrec_boot(&f, 3 * 1220, 0, 0);
  f.c->boot_rx_bytes = 100000;
  n                  = sr_client_hs_ping(f.c, 0, hs);
  srvrun_serve(&f.ctx, wired_mspan_of(hs, n));
  CHECK(f.c->l.hs_rx_seen == 1);
  f.c->boot_pto_count = SRVRUN_BOOT_PTO_MAX - 1;
  f.ctx.now_ms        = SRVRUN_BOOT_RESEND_CAP_MS;
  tx                  = f.c->boot_tx_bytes;
  n                   = sr_client_hs_ping(f.c, 1, hs);
  srvrun_serve(&f.ctx, wired_mspan_of(hs, n));
  CHECK(f.c->boot_tx_bytes - tx >= f.c->boot_dgram_len[0]); /* replayed */
  CHECK(f.c->boot_pto_count == SRVRUN_BOOT_PTO_MAX);
  f.ctx.now_ms = 2 * SRVRUN_BOOT_RESEND_CAP_MS;
  tx           = f.c->boot_tx_bytes;
  n            = sr_client_hs_ping(f.c, 2, hs);
  srvrun_serve(&f.ctx, wired_mspan_of(hs, n));
  CHECK(f.c->boot_tx_bytes - tx < f.c->boot_dgram_len[0]); /* ACK at most */
  CHECK(f.c->up == 1);
  f.ctx.now_ms = 3 * SRVRUN_BOOT_RESEND_CAP_MS;
  srvrun_boot_pto_slot(&f.ctx, 0);
  CHECK(srvrun_slot_busy(f.c) == 0);
}

/* RFC 9002 6.2.4: the answer to a client probe is a probe -- at most
 * SRVRUN_BOOT_PROBE_DGRAMS datagrams of the flight, and one answer per
 * SRVRUN_BOOT_RESEND_CAP_MS window however many opened probes arrive. */
static void test_srvrun_boot_probe_burst_one_answer(void) {
  srvrec_bootfix f;
  u8             hs[PMTU_MAX];
  usz            n, sends;
  srvrec_boot(&f, 3 * 1220, 0, 0);
  f.c->boot_rx_bytes = 100000;
  f.ctx.now_ms       = SRVRUN_BOOT_RESEND_CAP_MS;
  srvrun_test_reset_send_count();
  for (u64 pn = 0; pn < 6; pn++) {
    n = sr_client_hs_ping(f.c, pn, hs);
    srvrun_serve(&f.ctx, wired_mspan_of(hs, n));
  }
  sends = srvrun_test_send_count();
  CHECK(sends >= 1); /* the first probe was answered */
  CHECK(sends <= SRVRUN_BOOT_PROBE_DGRAMS);
  CHECK(f.c->boot_pto_count == 1);
}

/* RFC 9000 8.1: a probe never exceeds the anti-amplification budget. With
 * 181 bytes left the ServerHello Initial (>= 1200) cannot go and the
 * Initial PTO sends nothing (no probe spent); a Handshake PTO sends only
 * the small Handshake PING that fits. */
static void test_srvrun_boot_pto_within_antiamp(void) {
  srvrec_bootfix f;
  u64            tx;
  srvrec_boot(&f, 181, 0, 0);
  f.ctx.now_ms = SRVRUN_BOOT_RESEND_CAP_MS;
  tx           = f.c->boot_tx_bytes;
  srvrun_boot_pto_slot(&f.ctx, 0);
  CHECK(f.c->boot_tx_bytes == tx);
  CHECK(f.c->boot_pto_count == 0);
  f.c->boot_sent_ms[SRVRUN_BOOT_SP_INI] = 50;
  srvrun_boot_pto_slot(&f.ctx, 0);
  CHECK(f.c->boot_tx_bytes > tx);
  CHECK(f.c->boot_tx_bytes <= 3 * f.c->boot_rx_bytes);
  CHECK(f.c->boot_pto_count == 1);
}

/* A 4-datagram Handshake flight whose first `sent` went out, the Initial
 * already acknowledged, Handshake last sent at 0, `rx` client bytes
 * received. Distinct lengths 1000..1003 make a boot_tx_bytes delta name the
 * datagrams that went (content is irrelevant: cfg->fd -1 only counts). The
 * real fixture's flight is a single datagram, too few for these cases. */
static void srvrec_hs_flight(srvrun_conn* c, usz sent, u64 rx) {
  sr_antiamp_seed_flight(c);
  for (usz i = 0; i < 4; i++) {
    c->boot_dgram_len[i] = 1000 + i;
    c->boot_tx_bytes += i < sent ? 1000 + i : 0;
  }
  c->up              = 1;
  c->boot_ini_len    = 100;
  c->boot_ini_acked  = 1;
  c->boot_dgram_sent = sent;
  c->boot_rx_bytes   = rx;
  rtt_init(&c->rtt);
}

/* RFC 9002 6.2.4: "An endpoint SHOULD include new data in packets that are
 * sent on PTO expiration" -- with datagram 3 still held by the antiamp gate
 * and budget for it now, the Handshake PTO sends that held tail, not
 * datagrams 0 and 1 the client may already have. */
static void test_srvrun_boot_pto_prefers_held_tail(void) {
  conntable       table[WIRED_CONNTABLE_CAP];
  srvrun_state    st  = {table, sr_test_conns()};
  srvrun_cfg      cfg = sr_boot_pto_cfg();
  srvrun_step_ctx ctx = {&cfg, 0, &st, SRVRUN_BOOT_RESEND_CAP_MS, 0};
  srvrun_conn*    c   = &st.conns[0];
  u64             tx;
  conntable_init(table, WIRED_CONNTABLE_CAP);
  srvrec_hs_flight(c, 3, 2 * 1280); /* budget 7680, 3003 spent */
  tx = c->boot_tx_bytes;
  srvrun_boot_pto_slot(&ctx, 0);
  CHECK(c->boot_tx_bytes - tx == 1003);
  CHECK(c->boot_dgram_sent == 4);
  CHECK(c->boot_pto_count == 1);
}

/* RFC 9002 6.2.4: the probe retransmits unacknowledged data only -- with
 * packets 0 and 2 acknowledged, a Handshake PTO re-sends 1 and 3. */
static void test_srvrun_boot_pto_skips_partially_acked(void) {
  conntable       table[WIRED_CONNTABLE_CAP];
  srvrun_state    st  = {table, sr_test_conns()};
  srvrun_cfg      cfg = sr_boot_pto_cfg();
  srvrun_step_ctx ctx = {&cfg, 0, &st, SRVRUN_BOOT_RESEND_CAP_MS, 0};
  srvrun_conn*    c   = &st.conns[0];
  u64             tx;
  conntable_init(table, WIRED_CONNTABLE_CAP);
  srvrec_hs_flight(c, 4, 100000);
  c->l.hs_acked = 0x5;
  tx            = c->boot_tx_bytes;
  srvrun_boot_pto_slot(&ctx, 0);
  CHECK(c->boot_tx_bytes - tx == 1001 + 1003);
  c->l.hs_acked |= 0x2;
  ctx.now_ms = 2 * SRVRUN_BOOT_RESEND_CAP_MS;
  tx         = c->boot_tx_bytes;
  srvrun_boot_pto_slot(&ctx, 0);
  CHECK(c->boot_tx_bytes - tx == 1003);
}

/* RFC 9000 8.1: the bytes of an ACK-only client Initial raise the budget
 * like any other datagram, so a Handshake datagram the gate held back goes
 * out on that receipt (srvrun_boot_release_pending), not at the next PTO. */
static void test_srvrun_boot_ack_only_initial_releases_tail(void) {
  srvrec_bootfix f;
  u8             ack[PMTU_MAX];
  usz            n;
  srvrec_boot(&f, 3 * 1220, 0, 0);
  f.c->boot_dgram_sent = 0; /* the Handshake datagram is held back */
  f.c->boot_tx_bytes   = 3 * f.c->boot_rx_bytes - 100;
  n                    = srvrec_client_ini_ack(f.c, ack);
  srvrun_test_reset_send_count();
  srvrun_serve(&f.ctx, wired_mspan_of(ack, n));
  CHECK(f.c->boot_ini_acked == 1);
  CHECK(f.c->boot_dgram_sent == 1);
  CHECK(srvrun_test_send_count() == 1);
}

/* RFC 9001 4.1.3: a client Initial reaching a slot whose Handshake keys are
 * installed, with CRYPTO past the ClientHello, closes the connection with
 * PROTOCOL_VIOLATION; RFC 9000 13.3: one inside the ClientHello is a
 * retransmission and is answered with the flight, not closed. */
static void test_srvrun_late_initial_crypto_past_ch_closes(void) {
  srvrec_bootfix f;
  u8             dg[PMTU_MAX];
  int            is_app = -1;
  srvrec_boot(&f, 3 * 1220, 0, 0);
  f.c->boot_rx_bytes = 100000;
  srvrun_test_reset_send_count();
  srvrun_serve(
      &f.ctx, wired_mspan_of(dg, srvrec_client_ini_crypto(f.c, 0, dg)));
  CHECK(f.c->closing == 0);
  CHECK(srvrun_test_send_count() != 0);
  srvrun_serve(
      &f.ctx,
      wired_mspan_of(dg, srvrec_client_ini_crypto(f.c, f.c->s.ini_rx_end, dg)));
  CHECK(sr_close_code(f.c, &is_app) == ERR_PROTOCOL_VIOLATION);
  CHECK(is_app == 0);
  /* RFC 9000 10.2.1: the close was lost and the client sends an Initial
   * again -- it is not processed (its ACK is not taken) and the
   * CONNECTION_CLOSE answers it */
  srvrun_test_reset_send_count();
  srvrun_serve(&f.ctx, wired_mspan_of(dg, srvrec_client_ini_ack(f.c, dg)));
  CHECK(f.c->boot_ini_acked == 0);
  CHECK(srvrun_test_send_count() != 0);
}

/* One srvrun_pto_slot tick of c at now_ms. */
static void srvrec_pto_tick(srvrun_conn* c, u64 now_ms) {
  srvrun_cfg      cfg = srvrec_cfg();
  srvrun_state    st  = {0, c};
  srvrun_step_ctx ctx = {&cfg, 0, &st, now_ms, 0};
  srvrun_pto_slot(&ctx, 0);
}

/* RFC 9002 6.2.1 / A.8 (9002-031): the 1-RTT PTO runs from the LAST
 * ack-eliciting send. Two MAX_DATA packets at t=0 and t=D-1 (D the PTO):
 * not due at D, due at 2D-1. */
static void test_srvrun_pto_restarts_on_send(void) {
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob = {obuf, sizeof obuf, 0};
  u64           d;
  srvrec_bare(&c, &f, &ob);
  d = srvrun_pto_deadline_ms(&c, 0);
  (void)srvrec_ctrl(&c, 0);
  (void)srvrec_ctrl(&c, d - 1);
  srvrec_pto_tick(&c, d);
  CHECK(c.l.ackst.pto_count == 0);
  srvrec_pto_tick(&c, 2 * d - 2);
  CHECK(c.l.ackst.pto_count == 0);
  srvrec_pto_tick(&c, 2 * d - 1);
  CHECK(c.l.ackst.pto_count == 1);
}

/* RFC 9002 A.7: a newly acknowledged packet resets pto_count (a server
 * always completed address validation); a duplicate ACK does not. */
static void test_srvrun_pto_count_resets_on_ack(void) {
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob = {obuf, sizeof obuf, 0};
  u64           pn;
  srvrec_bare(&c, &f, &ob);
  pn = srvrec_ctrl(&c, 0);
  srvrec_pto_tick(&c, srvrun_pto_deadline_ms(&c, 0));
  CHECK(c.l.ackst.pto_count == 1);
  srvrec_ack(&c, pn + 1, pn + 1, 2000); /* the PING probe */
  CHECK(c.l.ackst.pto_count == 0);
  c.l.ackst.pto_count = 2;
  srvrec_ack(&c, pn + 1, pn + 1, 2001); /* duplicate: nothing new */
  CHECK(c.l.ackst.pto_count == 2);
}

/* RFC 9002 6.2.4 (9002-069) / 7.5: with the window full, a PTO probe
 * carries NEW data past cwnd (two packets), and the slice already in flight
 * is neither requeued nor taken out of flight (6.2, 9002-024). */
static void test_srvrun_pto_probe_sends_new_data(void) {
  static u8     body[4 * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob  = {obuf, sizeof obuf, 0};
  srvrun_cfg    cfg = srvrec_cfg();
  srvrun_state  st  = {0, &c};
  srvrec_conn(&c, &f, body, sizeof body, &ob);
  c.resp[0].stream_credit = sizeof body;
  c.cc.cwnd               = SRVRUN_CHUNK; /* room for one slice */
  {
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0, 0};
    c.l.now_ms          = 0;
    srvrun_pump_sess(&ctx, 0);
  }
  CHECK(c.resp[0].sess.q.cur == SRVRUN_CHUNK);
  srvrec_pto_tick(&c, srvrun_pto_deadline_ms(&c, 0));
  CHECK(c.l.ackst.pto_count == 1);
  CHECK(c.resp[0].sess.q.cur == 3 * SRVRUN_CHUNK); /* two new slices */
  CHECK(c.resp[0].sess.requeue_n == 0);
  CHECK(wired_sendsess_inflight(&c.resp[0].sess) == 3);
  CHECK(c.l.ackst.probe_n == 0); /* the cwnd waiver ends with the probe */
}

/* RFC 9002 6.2.4 with no new data: copies of the oldest slices go, the
 * originals stay in flight (9002-024). */
static void test_srvrun_pto_probe_retransmits_when_no_new_data(void) {
  static u8     body[2 * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob = {obuf, sizeof obuf, 0};
  srvrec_conn(&c, &f, body, sizeof body, &ob);
  (void)srvrec_pump_two(&c);
  c.cc.cwnd = 1;
  srvrec_pto_tick(&c, srvrun_pto_deadline_ms(&c, 0));
  CHECK(c.l.ackst.pto_count == 1);
  CHECK(c.resp[0].sess.requeue_n == 0);                 /* both resent */
  CHECK(wired_sendsess_inflight(&c.resp[0].sess) == 4); /* + originals */
}

/* RFC 9000 13.2.1: an ACK still pending for the connection rides the
 * DATAGRAM's packet (the packet is longer by the ACK frame and the pending
 * count is consumed); with nothing pending the DATAGRAM goes out bare, and
 * an ACK that would not fit beside a full-size DATAGRAM stays pending. */
static void test_srvrun_datagram_carries_pending_ack(void) {
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024], dg[1500] = {0};
  wired_obuf    ob  = {obuf, sizeof obuf, 0};
  wired_obuf    dob = obuf_of(dg, sizeof dg);
  srvrun_cfg    cfg = srvrec_cfg();
  usz           bare, room;
  srvrec_bare(&c, &f, &ob);
  c.l.now_ms = 0;
  CHECK(srvrun_send_datagram_now(&cfg, &c, wired_span_of(dg, 10), &dob));
  bare = dob.len;
  pnspaces_on_recv(&c.l.ack_recv, PNS_APP, 0);
  c.l.app_ack_policy.pending = 1; /* not yet due on its own */
  dob                        = obuf_of(dg, sizeof dg);
  srvrun_test_reset_send_count();
  CHECK(srvrun_send_datagram_now(&cfg, &c, wired_span_of(dg, 10), &dob));
  CHECK(srvrun_test_send_count() == 1); /* one packet for both */
  CHECK(dob.len > bare);
  CHECK(c.l.app_ack_policy.pending == 0);
  /* a DATAGRAM that fills the packet leaves no room: the ACK stays */
  room                       = srvrun_dg_room(&c, 1400);
  c.l.app_ack_policy.pending = 1;
  dob                        = obuf_of(dg, sizeof dg);
  srvrun_send_datagram_now(&cfg, &c, wired_span_of(dg, room - 9), &dob);
  CHECK(c.l.app_ack_policy.pending == 1);
}

/* RFC 9221 5.2 (9221-028) / RFC 9002 6.2.4: an unacknowledged DATAGRAM-only
 * packet arms the PTO (the poll tick stays on for it), and with no stream
 * data to send the probe is a single PING. */
static void test_srvrun_pto_pings_datagram_only(void) {
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024], dg[1500] = {0};
  wired_obuf    ob  = {obuf, sizeof obuf, 0};
  wired_obuf    dob = obuf_of(dg, sizeof dg);
  srvrun_cfg    cfg = srvrec_cfg();
  u64           tx;
  srvrec_bare(&c, &f, &ob);
  c.l.now_ms = 0;
  CHECK(srvrun_send_datagram_now(&cfg, &c, wired_span_of(dg, 10), &dob));
  CHECK(srvrun_slot_waiting(&c));
  tx = c.l.tx_pn;
  srvrun_test_reset_send_count();
  srvrec_pto_tick(&c, srvrun_pto_deadline_ms(&c, 0) - 1);
  CHECK(c.l.ackst.pto_count == 0 && c.l.tx_pn == tx);
  srvrec_pto_tick(&c, srvrun_pto_deadline_ms(&c, 0));
  CHECK(c.l.ackst.pto_count == 1);
  CHECK(c.l.tx_pn == tx + 1); /* one PING packet */
  CHECK(srvrun_test_send_count() == 1);
  CHECK(c.l.ackst.last_elicit_ms == srvrun_pto_deadline_ms(&c, 0));
}

/* RFC 9221 5.4 (9221-026/027): a DATAGRAM is congestion controlled -- with
 * the window full nothing is sent (the caller delays or drops it); with
 * room it goes and its packet counts in bytes in flight. */
static void test_srvrun_dg_blocked_by_cwnd(void) {
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024], dg[1500] = {0};
  wired_obuf    ob  = {obuf, sizeof obuf, 0};
  wired_obuf    dob = obuf_of(dg, sizeof dg);
  srvrun_cfg    cfg = srvrec_cfg();
  u64           tx;
  srvrec_bare(&c, &f, &ob);
  tx        = c.l.tx_pn;
  c.cc.cwnd = 10; /* below the 13-byte frame (type, length, 10 bytes) */
  CHECK(srvrun_send_datagram_now(&cfg, &c, wired_span_of(dg, 10), &dob) == 0);
  CHECK(c.l.tx_pn == tx);
  CHECK(srvrun_bytes_in_flight(&c) == 0);
  c.cc.cwnd = 1u << 20;
  CHECK(srvrun_send_datagram_now(&cfg, &c, wired_span_of(dg, 10), &dob) == 1);
  CHECK(c.l.tx_pn == tx + 1);
  CHECK(srvrun_bytes_in_flight(&c) == dob.len); /* the whole packet */
}

/* One pump pass of c at now_ms. */
static void srvrec_pump(srvrun_conn* c, u64 now_ms) {
  srvrun_cfg      cfg = srvrec_cfg();
  srvrun_state    st  = {0, c};
  srvrun_step_ctx ctx = {&cfg, 0, &st, now_ms, 0};
  c->l.now_ms         = now_ms;
  srvrun_pump_sess(&ctx, 0);
}

/* RFC 9002 7.8 (9002-067): a pass that sent everything with the window
 * still open leaves it underutilized, and the ACK does not grow cwnd; a
 * pass the window cut short is not, and the ACK does. */
static void test_srvrun_cc_no_growth_app_limited(void) {
  static u8     body[4 * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob = {obuf, sizeof obuf, 0};
  u64           w, pn;
  srvrec_conn(&c, &f, body, SRVRUN_CHUNK, &ob);
  pn = c.l.tx_pn;
  srvrec_pump(&c, 0);
  CHECK(c.cc.app_limited == 1);
  w = c.cc.cwnd;
  srvrec_ack(&c, pn, pn, 10);
  CHECK(c.cc.cwnd == w);
  srvrec_conn(&c, &f, body, sizeof body, &ob);
  c.resp[0].stream_credit = sizeof body;
  c.cc.cwnd               = 2 * SRVRUN_CHUNK + 100; /* two packets */
  pn                      = c.l.tx_pn;
  srvrec_pump(&c, 0);
  CHECK(wired_sendsess_inflight(&c.resp[0].sess) == 2);
  CHECK(c.cc.app_limited == 0);
  w = c.cc.cwnd;
  srvrec_ack(&c, pn, pn, 10);
  CHECK(c.cc.cwnd == w + SRVRUN_CHUNK); /* slow start: + acked bytes */
}

/* RFC 9002 7.8 (9002-071): a pass ended by pacing, with data left and the
 * window open, is not application limited. */
static void test_srvrun_cc_paced_not_app_limited(void) {
  static u8     body[4 * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob = {obuf, sizeof obuf, 0};
  srvrec_conn(&c, &f, body, sizeof body, &ob);
  c.resp[0].stream_credit = sizeof body;
  c.cc.app_limited        = 1;
  c.srtt_ms               = 30;
  c.pace_tokens           = 0;
  c.pace_refill_ms        = 5; /* refilled at now: no tokens accrue */
  srvrec_pump(&c, 5);
  CHECK(wired_sendsess_inflight(&c.resp[0].sess) == 0); /* paced */
  CHECK(c.cc.app_limited == 0);
}

/* One live send pass of c (srvrun_sess_on_step) with resp[0] holding four
 * slices and one broadcast DATAGRAM queued for its WT session, under a
 * window with room for one slice; datagram_first picks the order. */
static void srvrec_dg_vs_stream(srvrun_conn* c, int datagram_first) {
  static u8       body[4 * SRVRUN_CHUNK];
  static const u8 dg[10] = {0};
  struct lp_fix   f;
  u8              obuf[1024];
  wired_obuf      ob  = {obuf, sizeof obuf, 0};
  srvrun_cfg      cfg = srvrec_cfg();
  srvrun_state    st  = {0, c};
  srvrun_step_ctx ctx = {&cfg, 0, &st, 0, 0};
  srvrec_conn(c, &f, body, sizeof body, &ob);
  c->resp[0].stream_credit               = sizeof body;
  c->s.sdrv.peer_max_datagram_frame_size = 65535;
  c->wt_active                           = 1;
  c->wt.state                            = WIRED_WT_ESTABLISHED;
  c->wt.connect_stream_id                = 4;
  CHECK(srvrun_queue_datagram(c, wired_span_of(dg, sizeof dg)) == 1);
  c->cc.cwnd                  = SRVRUN_CHUNK;
  c->l.now_ms                 = 0;
  g_srvrun_env.datagram_first = datagram_first;
  srvrun_sess_on_step(&ctx, 0);
  g_srvrun_env.datagram_first = 0;
}

/* RFC 9221 5.1 (9221-019): wired_srvrun_opt.datagram_first orders the send
 * pass when the window cannot hold both -- by default the stream slice
 * goes and the DATAGRAM waits; with it set the DATAGRAM goes first. */
static void test_srvrun_dg_priority_vs_stream(void) {
  srvrun_conn c;
  srvrec_dg_vs_stream(&c, 0);
  CHECK(c.resp[0].sess.q.cur == SRVRUN_CHUNK);
  CHECK(c.dg_pending == 1);
  srvrec_dg_vs_stream(&c, 1);
  CHECK(c.dg_pending == 0);
  CHECK(c.resp[0].sess.q.cur == 0);
}

/* RFC 9221 5.1 (9221-019): the pending queue sends its most urgent DATAGRAM
 * first, arrival order within one urgency. A send pass with window room for
 * one DATAGRAM sends the urgent one; the other two wait in arrival order. */
static void test_srvrun_dg_pending_by_urgency(void) {
  static u8       a[100] = {'a'}, b[100] = {'b'}, d[100] = {'d'};
  struct lp_fix   f;
  srvrun_conn     c;
  u8              obuf[1024];
  wired_obuf      ob  = {obuf, sizeof obuf, 0};
  srvrun_cfg      cfg = srvrec_cfg();
  srvrun_state    st  = {0, &c};
  srvrun_step_ctx ctx = {&cfg, 0, &st, 0, 0};
  srvrec_bare(&c, &f, &ob);
  c.s.sdrv.peer_max_datagram_frame_size = 65535;
  c.wt_active                           = 1;
  c.wt.state                            = WIRED_WT_ESTABLISHED;
  c.wt.connect_stream_id                = 4;
  CHECK(srvrun_queue_datagram_prio(&c, wired_span_of(a, sizeof a), 3) == 1);
  CHECK(srvrun_queue_datagram_prio(&c, wired_span_of(b, sizeof b), 0) == 1);
  CHECK(srvrun_queue_datagram_prio(&c, wired_span_of(d, sizeof d), 3) == 1);
  c.cc.cwnd  = 1 + 2 + 1 + sizeof a; /* one frame: type, length, qsid, a */
  c.l.now_ms = 0;
  srvrun_sess_on_step(&ctx, 0);
  CHECK(c.dg_pending == 2);
  CHECK(c.dg_pending_buf[c.dg_pending_head][0] == 'a');
  CHECK(
      c.dg_pending_buf[(c.dg_pending_head + 1) % SRVRUN_DG_PENDING_Q][0] ==
      'd');
}

/* RFC 9000 21.4 / RFC 9002 6.1.1: a purposely skipped packet number has no
 * sent record, so recovery across the gap stays correct -- the packet
 * threshold still counts from the largest acked number, the hole itself is
 * never declared lost, and acking the real packets on both sides of it
 * reclaims them all. */
static void test_srvrun_rec_skip_gap_recovery(void) {
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob = {obuf, sizeof obuf, 0};
  u64           pn0, pn1, pn2, r[1][2];
  srvrec_bare(&c, &f, &ob);
  pn0            = srvrec_ctrl(&c, 10);
  c.l.pn_skip_at = 1; /* force the skip right after this send */
  pn1            = srvrec_ctrl(&c, 10);
  pn2            = srvrec_ctrl(&c, 10);
  CHECK(pn2 == pn1 + 2); /* pn1 + 1 was skipped */
  CHECK(sentmeta_find(&c.l.ackst.sent, pn1 + 1) == SENTMETA_CAP);
  r[0][0] = pn2;
  r[0][1] = pn2;
  srvrec_ack_n(&c, r, 1, 0, 10); /* 0ms RTT: only the packet threshold */
  /* kPacketThreshold 3: pn2 - pn0 = 3 declares pn0 lost (the skipped hole
   * counts as number distance, RFC 9002 6.1.1); pn2 - pn1 = 2 does not. */
  CHECK(sentmeta_find(&c.l.ackst.sent, pn0) == SENTMETA_CAP);
  CHECK(sentmeta_find(&c.l.ackst.sent, pn1) < SENTMETA_CAP);
  r[0][0] = pn0;
  r[0][1] = pn1;
  srvrec_ack_n(&c, r, 1, 0, 11);
  CHECK(sentmeta_find(&c.l.ackst.sent, pn1) == SENTMETA_CAP);
  CHECK(c.l.ackst.sent.total_in_flight == 0);
}

/* RFC 9000 21.4: a long transfer crosses many real skips (one forced per
 * pump round, at an explicit position -- no RNG) and still completes:
 * every slice is acknowledged around the holes, nothing is declared lost
 * from a hole, and the connection never errors. */
static void test_srvrun_rec_skip_long_transfer_completes(void) {
  static u8     body[20 * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob  = {obuf, sizeof obuf, 0};
  srvrun_cfg    cfg = srvrec_cfg();
  srvrun_state  st  = {0, &c};
  u64           r[2][2];
  int           rounds, slots = 0;
  srvrec_conn(&c, &f, body, sizeof body, &ob);
  c.cc.cwnd = 2 * SRVRUN_CHUNK; /* a few slices per round, many rounds */
  for (rounds = 0; rounds < 60; rounds++) {
    u64             start = c.l.tx_pn, end;
    srvrun_step_ctx ctx   = {&cfg, 0, &st, 10 + (u64)rounds, 0};
    c.l.pn_skip_at        = 1; /* skip right after the round's first send */
    srvrun_pump_sess(&ctx, 0);
    end = c.l.tx_pn;
    if (end == start) {
      break; /* everything sent and acknowledged */
    }
    CHECK(end > start + 1); /* >= one send, then the skip of start + 1 */
    if (end > start + 2) {
      r[0][0] = start + 2; /* the honest ACK: everything but the hole */
      r[0][1] = end - 1;
      r[1][0] = start;
      r[1][1] = start;
      srvrec_ack_n(&c, r, 2, 0, 10 + (u64)rounds);
    } else {
      r[0][0] = start;
      r[0][1] = start;
      srvrec_ack_n(&c, r, 1, 0, 10 + (u64)rounds);
    }
  }
  CHECK(rounds < 60);
  CHECK(c.l.transport_error == 0);
  CHECK(c.l.ackst.sent.total_in_flight == 0);
  CHECK(wired_sendsess_inflight(&c.resp[0].sess) == 0);
  CHECK(wired_sendsess_done(&c.resp[0].sess) == 1);
  for (usz i = 0; i < WIRED_SRVLOOP_PN_SKIPS; i++) {
    slots += c.l.pn_skipped1[i] != 0;
  }
  CHECK(slots >= 3); /* the transfer really crossed several skips */
}

void test_srvrun_rec(void) {
  test_srvrun_rec_time_threshold_latest_rtt();
  test_srvrun_rec_granularity_floor();
  test_srvrun_rec_spurious_loss_not_resent();
  test_srvrun_rec_control_packet_counts_inflight();
  test_srvrun_rec_boot_flight_counts_inflight();
  test_srvrun_rec_one_sample_per_frame();
  test_srvrun_rec_no_sample_when_largest_old();
  test_srvrun_rec_no_sample_ack_only();
  test_srvrun_rec_ack_delay_applied();
  test_srvrun_rec_peer_max_ack_delay();
  test_srvrun_rec_loss_timer_fires();
  test_srvrun_rec_loss_timer_suppresses_pto();
  test_srvrun_rec_ack_immediate_on_gap_reorder_ce();
  test_srvrun_rec_ack_prunes_acked_ranges();
  test_srvrun_rec_ack_truncates_ranges();
  test_srvrun_rec_tick_flushes_ack();
  test_srvrun_boot_pto_no_max_ack_delay();
  test_srvrun_boot_pto_resets_on_initial_discard();
  test_srvrun_boot_pto_resets_on_hs_ack();
  test_srvloop_acked_bits();
  test_srvrun_boot_pto_earliest_space();
  test_srvrun_boot_pto_initial_probe_no_handshake();
  test_srvrun_boot_pto_handshake_only_after_initial_acked();
  test_srvrun_boot_pto_skips_acked_handshake();
  test_srvrun_boot_unopened_hs_header_no_replay();
  test_srvrun_boot_probe_budget_ends_exempt_boot();
  test_srvrun_boot_probe_burst_one_answer();
  test_srvrun_boot_pto_within_antiamp();
  test_srvrun_boot_pto_prefers_held_tail();
  test_srvrun_boot_pto_skips_partially_acked();
  test_srvrun_boot_ack_only_initial_releases_tail();
  test_srvrun_late_initial_crypto_past_ch_closes();
  test_srvrun_pto_restarts_on_send();
  test_srvrun_pto_count_resets_on_ack();
  test_srvrun_pto_probe_sends_new_data();
  test_srvrun_pto_probe_retransmits_when_no_new_data();
  test_srvrun_pto_pings_datagram_only();
  test_srvrun_datagram_carries_pending_ack();
  test_srvrun_dg_blocked_by_cwnd();
  test_srvrun_cc_no_growth_app_limited();
  test_srvrun_cc_paced_not_app_limited();
  test_srvrun_dg_priority_vs_stream();
  test_srvrun_dg_pending_by_urgency();
  test_srvrun_rec_idle_restarts_on_any_eliciting();
  test_srvrun_rec_skip_gap_recovery();
  test_srvrun_rec_skip_long_transfer_completes();
}
