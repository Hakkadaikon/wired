#include "test.h"

static void test_cc_slow_start(void) {
  quic_cc c;
  quic_cc_init(&c);
  u64 start = c.cwnd;
  quic_cc_on_ack(&c, 1200, 10, 10); /* slow start: +acked */
  CHECK(c.cwnd == start + 1200);
}

/* Loss halves cwnd but never below the minimum window (most important). */
static void test_cc_loss_halves_floor(void) {
  quic_cc c;
  quic_cc_init(&c);
  quic_cc_on_loss(&c, 5, 100);
  CHECK(c.cwnd == QUIC_CC_INIT_WINDOW / 2);
  CHECK(c.cwnd >= QUIC_CC_MIN_WINDOW);
  /* drive it down repeatedly: must clamp at the floor */
  for (usz i = 0; i < 20; i++) {
    quic_cc_on_ack(&c, 999999, 1000 + i, 1000 + i); /* exit recovery */
    quic_cc_on_loss(&c, 2000 + i, 2000 + i);
  }
  CHECK(c.cwnd >= QUIC_CC_MIN_WINDOW);
}

/* No window growth while in recovery. */
static void test_cc_no_grow_in_recovery(void) {
  quic_cc c;
  quic_cc_init(&c);
  quic_cc_on_loss(&c, 5, 100); /* enter recovery at t=100 */
  u64 w = c.cwnd;
  quic_cc_on_ack(&c, 1200, 50, 50); /* ack of pre-recovery packet */
  CHECK(c.in_recovery == 1 && c.cwnd == w);
}

/* An ack of a packet sent after recovery began exits recovery. */
static void test_cc_recovery_exit(void) {
  quic_cc c;
  quic_cc_init(&c);
  quic_cc_on_loss(&c, 5, 100);
  quic_cc_on_ack(&c, 1200, 200, 200); /* sent after recovery_start=100 */
  CHECK(c.in_recovery == 0);
}

static void test_cc_persistent_collapse(void) {
  quic_cc c;
  quic_cc_init(&c);
  quic_cc_on_persistent(&c);
  CHECK(c.cwnd == QUIC_CC_MIN_WINDOW);
}

/* CUBIC mode (RFC 9438): loss shrinks by beta_cubic 0.7 and re-anchors the
 * cubic epoch; acks lift cwnd onto the curve — back at W_max when K elapses
 * (W_max 10 segments -> K = cbrt(7.5e9) ms = 1957), convex past it. Slow
 * start before the first loss grows as usual. */
static void test_cc_cubic_mode(void) {
  quic_cc c;
  quic_cc_init_algo(&c, QUIC_CC_ALGO_CUBIC);
  CHECK(c.cwnd == QUIC_CC_INIT_WINDOW);
  quic_cc_on_ack(&c, 1200, 10, 10); /* pre-loss slow start still grows */
  CHECK(c.cwnd == QUIC_CC_INIT_WINDOW + 1200);
  quic_cc_init_algo(&c, QUIC_CC_ALGO_CUBIC);
  quic_cc_on_loss(&c, 1000, 1000);
  CHECK(c.cwnd == 8400); /* 12000 * 0.7 */
  quic_cc_on_ack(&c, 1200, 1500, 1000 + 1957);
  CHECK(c.cwnd == 12000); /* the curve reaches W_max at t = K */
  quic_cc_on_ack(&c, 1200, 1500, 1000 + 1957 + 5000);
  CHECK(c.cwnd == 72000); /* K+5s: 10 + 50 segments, convex growth */
}

/* BBR mode: acks feed the delivery-rate sampler; once a round closes, cwnd
 * becomes cwnd_gain x BDP (btl_bw x rtprop) and pacing follows
 * pacing_gain x btl_bw. The drain handoff needs the caller's inflight. */
static void test_cc_bbr_mode(void) {
  quic_cc c;
  quic_cc_init_algo(&c, QUIC_CC_ALGO_BBR);
  CHECK(c.cwnd == QUIC_CC_INIT_WINDOW);
  /* one round: 60000 bytes acked over 50ms -> bw 1200 B/ms, rtprop 50 */
  quic_cc_on_ack(&c, 60000, 0, 50);
  quic_cc_bbr_tick(&c, 0, 51); /* round (>= rtprop) elapsed: sample taken */
  CHECK(c.bbr.btl_bw == 1176); /* 60000 / 51ms */
  CHECK(c.bbr.rtprop_ms == 50);
  /* STARTUP cwnd = 289% x BDP = 2.89 x 1176 x 50 = 169932 */
  CHECK(c.cwnd == 169932);
  /* BBR pacing: mtu x 100 / (gain x btl_bw) = 1200x100/(289x1176) = 0ms
   * floor -> at least 1ms interval when bw known */
  CHECK(quic_cc_pacing_ms(&c, 999, 1200) == 1);
  /* NewReno/CUBIC path unchanged: srtt-based interval */
  {
    quic_cc n;
    quic_cc_init(&n);
    CHECK(quic_cc_pacing_ms(&n, 100, 1200) == 12);
  }
}

/* A large cwnd (post-slow-start) with a real RTT sample makes
 * 5*mtu*srtt/(4*cwnd) truncate below 1ms -- srvrun_pump_sess's per-step
 * drain loop then never re-checks pacing within the step, bursting an
 * entire log's worth of packets at once (observed: 17 packets in ~2.7ms
 * against a real quic-go client, overflowing the network simulator's queue
 * and losing 7 of them). Once an RTT sample exists, the interval must floor
 * at 1ms so the step boundary itself paces sends. */
static void test_cc_pacing_floors_at_1ms_once_rtt_known(void) {
  quic_cc c;
  quic_cc_init(&c);
  c.cwnd = 71055; /* real value observed mid-transfer: 5*1200*40/(4*71055)
                     truncates to 0 unfloored */
  CHECK(quic_pacing_interval(40, c.cwnd, 1200) == 0);
  CHECK(quic_cc_pacing_ms(&c, 40, 1200) == 1);
}

/* No RTT sample yet (srtt_ms == 0): srvrun_pace_ok's own !c->srtt_ms check
 * already bypasses pacing entirely, so the interval must stay 0, not be
 * floored -- flooring here would just be dead weight the caller ignores. */
static void test_cc_pacing_zero_srtt_stays_unfloored(void) {
  quic_cc c;
  quic_cc_init(&c);
  c.cwnd = 71055;
  CHECK(quic_cc_pacing_ms(&c, 0, 1200) == 0);
}

void test_cc(void) {
  test_cc_bbr_mode();
  test_cc_cubic_mode();
  test_cc_slow_start();
  test_cc_loss_halves_floor();
  test_cc_no_grow_in_recovery();
  test_cc_recovery_exit();
  test_cc_persistent_collapse();
  test_cc_pacing_floors_at_1ms_once_rtt_known();
  test_cc_pacing_zero_srtt_stays_unfloored();
}
