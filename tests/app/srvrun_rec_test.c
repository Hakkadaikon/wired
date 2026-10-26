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
  srvrun_cfg      cfg = srvrec_cfg();
  srvrun_state    st  = {0, c};
  srvrun_step_ctx ctx = {&cfg, 0, &st, now_ms, 0};
  c->l.ack_lo[0]      = lo;
  c->l.ack_hi[0]      = hi;
  c->l.ack_n          = 1;
  c->l.ack_largest    = hi;
  c->l.ack_delay_raw  = 0;
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
  c->l.ack_n         = n;
  c->l.ack_largest   = r[0][1];
  c->l.ack_delay_raw = delay_raw;
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
  CHECK(c.l.sent.total_in_flight > 0);
  CHECK(srvrun_bytes_in_flight(&c) == c.l.sent.total_in_flight);
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
    usz before = c.l.sent.total_in_flight;
    CHECK(srvloop_send_onertt_rec(&c.l, &c.s, &sin, &sob) == 1);
    CHECK(c.l.sent.total_in_flight == before); /* ACK-only: not in flight */
  }
  {
    srvrun_cfg      cfg    = srvrec_cfg();
    srvrun_state    st     = {0, &c};
    srvrun_step_ctx ctx    = {&cfg, 0, &st, 10, 0};
    usz             before = c.l.sent.total_in_flight;
    srvrun_pump_sess(&ctx, 0);
    CHECK(wired_sendsess_inflight(&c.resp[0].sess) == 1);
    CHECK(c.l.sent.total_in_flight == before); /* the session counts it */
  }
  srvrec_ack(&c, pn, pn, 20);
  CHECK(c.l.sent.total_in_flight == 0);
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
  CHECK(c.l.sent.total_in_flight == 0); /* pn0 still left flight */
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
  CHECK(sentmeta_find(&c.l.sent, pn) == SENTMETA_CAP); /* still dropped */
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

/* RFC 9002 6.2.1 / A.8 / 9002-034: the PTO is not set while the loss
 * timer is. Exhaustive over {loss timer armed, PTO deadline passed}: a
 * probe (pto_count 1) only when the timer is unarmed and the PTO due. */
static void test_srvrun_rec_loss_timer_suppresses_pto(void) {
  static const struct {
    int armed, pto_due, probed;
  } rows[] = {{0, 0, 0}, {0, 1, 1}, {1, 0, 0}, {1, 1, 0}};
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
    ctx.now_ms     = rows[i].pto_due ? 10000 : 1;
    srvrun_pto_slot(&ctx, 0);
    CHECK(c.resp[0].sess.pto_count == rows[i].probed);
  }
}

/* One client 1-RTT PING packet pn stepped through the loop (datagram ECN
 * codepoint ecn); 1 if the step answered it with a packet right away. */
static int srvrec_ping(struct lp_fix* f, u64 pn, u8 ecn) {
  u8         ping[1] = {0x01}, spkt[256], out[1024];
  wired_obuf ob      = {out, sizeof out, 0};
  usz        n       = client_seal_onertt_pn(f, pn, ping, 1, spkt, sizeof spkt);
  wired_srvloop_ecn_note(&f->l, ecn);
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
  CHECK(f.l.ack_floor1 == 26);
  srvrec_ping(&f, 27, 0);
  srvrec_peek_ack(&f.l, &a);
  CHECK(a.n_ranges == 1);
  CHECK(a.ranges[0].hi == 27 && a.ranges[0].lo == 27);
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

void test_srvrun_rec(void) {
  test_srvrun_rec_time_threshold_latest_rtt();
  test_srvrun_rec_granularity_floor();
  test_srvrun_rec_spurious_loss_not_resent();
  test_srvrun_rec_control_packet_counts_inflight();
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
}
