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

void test_srvrun_rec(void) {
  test_srvrun_rec_time_threshold_latest_rtt();
  test_srvrun_rec_granularity_floor();
  test_srvrun_rec_spurious_loss_not_resent();
}
