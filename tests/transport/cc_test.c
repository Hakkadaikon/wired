#include "test.h"

static void test_cc_slow_start(void) {
  cc c;
  cc_init(&c);
  u64 start = c.cwnd;
  cc_on_ack(&c, 1200, 10, 10); /* slow start: +acked */
  CHECK(c.cwnd == start + 1200);
}

/* Loss halves cwnd but never below the minimum window (most important). */
static void test_cc_loss_halves_floor(void) {
  cc c;
  cc_init(&c);
  cc_on_loss(&c, 5, 100);
  CHECK(c.cwnd == CC_INIT_WINDOW / 2);
  CHECK(c.cwnd >= CC_MIN_WINDOW);
  /* drive it down repeatedly: must clamp at the floor */
  for (usz i = 0; i < 20; i++) {
    cc_on_ack(&c, 999999, 1000 + i, 1000 + i); /* exit recovery */
    cc_on_loss(&c, 2000 + i, 2000 + i);
  }
  CHECK(c.cwnd >= CC_MIN_WINDOW);
}

/* No window growth while in recovery. */
static void test_cc_no_grow_in_recovery(void) {
  cc c;
  cc_init(&c);
  cc_on_loss(&c, 5, 100); /* enter recovery at t=100 */
  u64 w = c.cwnd;
  cc_on_ack(&c, 1200, 50, 50); /* ack of pre-recovery packet */
  CHECK(c.in_recovery == 1 && c.cwnd == w);
}

/* An ack of a packet sent after recovery began exits recovery. */
static void test_cc_recovery_exit(void) {
  cc c;
  cc_init(&c);
  cc_on_loss(&c, 5, 100);
  cc_on_ack(&c, 1200, 200, 200); /* sent after recovery_start=100 */
  CHECK(c.in_recovery == 0);
}

static void test_cc_persistent_collapse(void) {
  cc c;
  cc_init(&c);
  cc_on_persistent(&c);
  CHECK(c.cwnd == CC_MIN_WINDOW);
}

/* CUBIC mode (RFC 9438): loss shrinks by beta_cubic 0.7 and re-anchors the
 * cubic epoch; acks lift cwnd onto the curve — back at W_max when K elapses
 * (W_max 10 segments -> K = cbrt(7.5e9) ms = 1957), convex past it. Slow
 * start before the first loss grows as usual. */
static void test_cc_cubic_mode(void) {
  cc c;
  cc_init_algo(&c, CC_ALGO_CUBIC);
  CHECK(c.cwnd == CC_INIT_WINDOW);
  cc_on_ack(&c, 1200, 10, 10); /* pre-loss slow start still grows */
  CHECK(c.cwnd == CC_INIT_WINDOW + 1200);
  cc_init_algo(&c, CC_ALGO_CUBIC);
  cc_on_loss(&c, 1000, 1000);
  CHECK(c.cwnd == 8400); /* 12000 * 0.7 */
  cc_on_ack(&c, 1200, 1500, 1000 + 1957);
  CHECK(c.cwnd == 12000); /* the curve reaches W_max at t = K */
  cc_on_ack(&c, 1200, 1500, 1000 + 1957 + 5000);
  CHECK(c.cwnd == 72000); /* K+5s: 10 + 50 segments, convex growth */
}

/* BBR mode: acks feed the delivery-rate sampler; once a round closes, cwnd
 * becomes cwnd_gain x BDP (btl_bw x rtprop) and pacing follows
 * pacing_gain x btl_bw. The drain handoff needs the caller's inflight. */
static void test_cc_bbr_mode(void) {
  cc c;
  cc_init_algo(&c, CC_ALGO_BBR);
  CHECK(c.cwnd == CC_INIT_WINDOW);
  /* one round: 60000 bytes acked over 50ms -> bw 1200 B/ms, rtprop 50 */
  cc_on_ack(&c, 60000, 0, 50);
  cc_bbr_tick(&c, 0, 51);      /* round (>= rtprop) elapsed: sample taken */
  CHECK(c.bbr.btl_bw == 1176); /* 60000 / 51ms */
  CHECK(c.bbr.rtprop_ms == 50);
  /* STARTUP cwnd = 289% x BDP = 2.89 x 1176 x 50 = 169932 */
  CHECK(c.cwnd == 169932);
  /* BBR pacing: mtu x 100 / (gain x btl_bw) = 1200x100/(289x1176) = 0ms
   * floor -> at least 1ms interval when bw known */
  CHECK(cc_pacing_ms(&c, 999, 1200) == 1);
  /* NewReno/CUBIC path unchanged: srtt-based interval */
  {
    cc n;
    cc_init(&n);
    CHECK(cc_pacing_ms(&n, 100, 1200) == 12);
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
  cc c;
  cc_init(&c);
  c.cwnd = 71055; /* real value observed mid-transfer: 5*1200*40/(4*71055)
                     truncates to 0 unfloored */
  CHECK(pacing_interval(40, c.cwnd, 1200) == 0);
  CHECK(cc_pacing_ms(&c, 40, 1200) == 1);
}

/* No RTT sample yet (srtt_ms == 0): srvrun_pace_ok's own !c->srtt_ms check
 * already bypasses pacing entirely, so the interval must stay 0, not be
 * floored -- flooring here would just be dead weight the caller ignores. */
static void test_cc_pacing_zero_srtt_stays_unfloored(void) {
  cc c;
  cc_init(&c);
  c.cwnd = 71055;
  CHECK(cc_pacing_ms(&c, 0, 1200) == 0);
}

/* A starved round -- far fewer bytes delivered than the window would carry
 * (loss-stalled, idle, or app-limited) -- proves nothing about the
 * bottleneck: it may only RAISE the estimate, never enter the max filter
 * where it would age the real peak out within BBR_BW_WIN rounds and
 * spiral cwnd to the floor (the observed BBR transfer death spiral). */
static void test_cc_bbr_starved_round_cannot_lower_btl_bw(void) {
  cc  c;
  u64 t = 51;
  cc_init_algo(&c, CC_ALGO_BBR);
  cc_on_ack(&c, 60000, 0, 50); /* healthy round: 1176 B/ms */
  cc_bbr_tick(&c, 0, t);
  CHECK(c.bbr.btl_bw == 1176);
  for (int i = 0; i < BBR_BW_WIN + 1; i++) { /* enough to age it out */
    cc_on_ack(&c, 1200, t, t + 51);          /* one packet per round: starved */
    t += 51;
    cc_bbr_tick(&c, 0, t);
  }
  CHECK(c.bbr.btl_bw == 1176); /* the peak survives the starved stretch */
}

/* draft-cardwell-iccrg-bbr BBRMinPipeCwnd: the cwnd floor is 4 packets --
 * at 2 packets a delayed-ACK peer measures rtt ~2x rtprop and the tiny
 * bandwidth estimate becomes self-consistent (the observed 2400-byte
 * fixed point that never recovered). */
static void test_cc_bbr_cwnd_floor_four_packets(void) {
  cc c;
  cc_init_algo(&c, CC_ALGO_BBR);
  cc_on_ack(&c, 1200, 0, 50); /* tiny first sample: 23 B/ms */
  cc_bbr_tick(&c, 0, 51);
  /* BDP = 23 x 50 = 1150; 289% = 3323 -> floored at 4 packets */
  CHECK(c.cwnd == 4 * MAX_DATAGRAM);
}

/* The PROBE_BW gain cycle advances once per CLOSED ROUND (~rtprop), never
 * per tick -- srvrun ticks every received datagram (~ms), which spun the
 * 8-phase cycle in ~8ms and reduced the probe/drain pattern to noise. */
static void test_cc_bbr_cycle_advances_per_round_not_per_tick(void) {
  cc c;
  cc_init_algo(&c, CC_ALGO_BBR);
  c.bbr.phase       = BBR_PROBE_BW;
  c.bbr.have_rtprop = 1;
  c.bbr.rtprop_ms   = 50;
  c.bbr.btl_bw      = 1000;
  cc_bbr_tick(&c, 0, 1); /* no bytes: no round closes */
  cc_bbr_tick(&c, 0, 2);
  CHECK(c.bbr.cycle_idx == 0);
  c.round_bytes = 60000; /* a real round's worth */
  cc_bbr_tick(&c, 0, 60);
  CHECK(c.bbr.cycle_idx == 1); /* exactly one advance per closed round */
}

void test_cc(void) {
  test_cc_bbr_mode();
  test_cc_bbr_starved_round_cannot_lower_btl_bw();
  test_cc_bbr_cwnd_floor_four_packets();
  test_cc_bbr_cycle_advances_per_round_not_per_tick();
  test_cc_cubic_mode();
  test_cc_slow_start();
  test_cc_loss_halves_floor();
  test_cc_no_grow_in_recovery();
  test_cc_recovery_exit();
  test_cc_persistent_collapse();
  test_cc_pacing_floors_at_1ms_once_rtt_known();
  test_cc_pacing_zero_srtt_stays_unfloored();
}
