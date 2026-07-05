#include "transport/recovery/congestion/cc/bbr.h"

#include "test.h"

/* STARTUP: a >=1.25x bandwidth-growth round resets the flat count; three
 * flat rounds in a row latch the pipe full and move to DRAIN. */
static void test_bbr_startup_growth_and_fill(void) {
  quic_bbr b;
  quic_bbr_init(&b);
  CHECK(b.phase == QUIC_BBR_STARTUP);
  quic_bbr_on_round(&b, 100); /* growth: baseline 100 */
  quic_bbr_on_round(&b, 130); /* 130 >= 125: growth, count resets */
  CHECK(b.full_bw_cnt == 0);
  quic_bbr_on_round(&b, 140); /* flat 1 (140 < 130*1.25) */
  quic_bbr_on_round(&b, 141); /* flat 2 */
  CHECK(b.phase == QUIC_BBR_STARTUP);
  quic_bbr_on_round(&b, 142); /* flat 3: pipe full -> DRAIN */
  CHECK(b.filled == 1);
  CHECK(b.phase == QUIC_BBR_DRAIN);
}

/* DRAIN leaves for PROBE_BW only once inflight has drained to the BDP; the
 * full-pipe latch never clears. */
static void test_bbr_drain_exit_and_latch(void) {
  quic_bbr b;
  quic_bbr_init(&b);
  quic_bbr_on_round(&b, 100);
  quic_bbr_on_round(&b, 101);
  quic_bbr_on_round(&b, 102);
  quic_bbr_on_round(&b, 103); /* 3 flat rounds -> DRAIN */
  CHECK(b.phase == QUIC_BBR_DRAIN);
  quic_bbr_drained(&b, 0); /* still above BDP: stays */
  CHECK(b.phase == QUIC_BBR_DRAIN);
  quic_bbr_drained(&b, 1);
  CHECK(b.phase == QUIC_BBR_PROBE_BW);
  CHECK(b.filled == 1); /* latch holds through every later phase */
}

/* PROBE_BW: the gain cycle advances modulo 8 and only there; the cycle is
 * frozen in every other phase. */
static void test_bbr_cycle_advances_only_in_probe_bw(void) {
  quic_bbr b;
  quic_bbr_init(&b);
  int start;
  quic_bbr_cycle_tick(&b); /* STARTUP: frozen */
  CHECK(b.cycle_idx == 0);
  quic_bbr_on_round(&b, 100);
  quic_bbr_on_round(&b, 101);
  quic_bbr_on_round(&b, 102);
  quic_bbr_on_round(&b, 103);
  quic_bbr_drained(&b, 1); /* -> PROBE_BW */
  start = b.cycle_idx;
  quic_bbr_cycle_tick(&b);
  CHECK(b.cycle_idx == (start + 1) % 8);
  for (int i = 0; i < 8; i++) quic_bbr_cycle_tick(&b);
  CHECK(b.cycle_idx == (start + 1) % 8); /* wrapped mod 8 */
}

/* min_rtt expiry forces PROBE_RTT from any phase; after the dwell it returns
 * to PROBE_BW when the pipe filled, else back to STARTUP. */
static void test_bbr_probe_rtt_round_trip(void) {
  quic_bbr b;
  quic_bbr_init(&b);
  /* rtprop learned at t=0; nothing due within the 10s window */
  quic_bbr_on_rtt(&b, 50, 0);
  CHECK(quic_bbr_check_probe_rtt(&b, 5000) == 0);
  CHECK(b.phase == QUIC_BBR_STARTUP);
  /* expiry: due from STARTUP too */
  CHECK(quic_bbr_check_probe_rtt(&b, 10001) == 1);
  CHECK(b.phase == QUIC_BBR_PROBE_RTT);
  /* dwell 200ms: no exit before, exit after; unfilled -> STARTUP */
  quic_bbr_probe_rtt_exit(&b, 10100);
  CHECK(b.phase == QUIC_BBR_PROBE_RTT);
  quic_bbr_probe_rtt_exit(&b, 10250);
  CHECK(b.phase == QUIC_BBR_STARTUP);
  /* refill the pipe, expire again: exit goes to PROBE_BW this time */
  quic_bbr_on_rtt(&b, 50, 10300);
  quic_bbr_on_round(&b, 100);
  quic_bbr_on_round(&b, 101);
  quic_bbr_on_round(&b, 102);
  quic_bbr_on_round(&b, 103);
  quic_bbr_drained(&b, 1);
  CHECK(quic_bbr_check_probe_rtt(&b, 20400) == 1);
  quic_bbr_probe_rtt_exit(&b, 20700);
  CHECK(b.phase == QUIC_BBR_PROBE_BW);
}

/* The pacing-gain schedule: startup 289%, drain 35%, probe_bw cycles
 * 125,75,100x6, probe_rtt 100%. */
static void test_bbr_gain_table(void) {
  quic_bbr b;
  quic_bbr_init(&b);
  CHECK(quic_bbr_pacing_gain_pct(&b) == 289);
  quic_bbr_on_round(&b, 100);
  quic_bbr_on_round(&b, 101);
  quic_bbr_on_round(&b, 102);
  quic_bbr_on_round(&b, 103);
  CHECK(quic_bbr_pacing_gain_pct(&b) == 35); /* DRAIN */
  quic_bbr_drained(&b, 1);
  b.cycle_idx = 0;
  CHECK(quic_bbr_pacing_gain_pct(&b) == 125);
  b.cycle_idx = 1;
  CHECK(quic_bbr_pacing_gain_pct(&b) == 75);
  b.cycle_idx = 5;
  CHECK(quic_bbr_pacing_gain_pct(&b) == 100);
}

/* Bandwidth and RTT estimators: btl_bw is the max over the last rounds,
 * rtprop the min that a fresher-but-larger sample cannot raise early. */
static void test_bbr_estimators(void) {
  quic_bbr b;
  quic_bbr_init(&b);
  quic_bbr_on_round(&b, 300);
  quic_bbr_on_round(&b, 200);
  CHECK(b.btl_bw == 300); /* windowed max keeps the peak */
  quic_bbr_on_rtt(&b, 80, 0);
  quic_bbr_on_rtt(&b, 120, 100); /* larger: ignored inside the window */
  CHECK(b.rtprop_ms == 80);
  quic_bbr_on_rtt(&b, 60, 200); /* smaller: taken immediately */
  CHECK(b.rtprop_ms == 60);
}

/* The cwnd-gain schedule: aggressive 289% through STARTUP/DRAIN (the pipe
 * estimate is still forming), 200% headroom cruising PROBE_BW, neutral in
 * PROBE_RTT. */
static void test_bbr_cwnd_gain_table(void) {
  quic_bbr b;
  quic_bbr_init(&b);
  CHECK(quic_bbr_cwnd_gain_pct(&b) == 289);
  quic_bbr_on_round(&b, 100);
  quic_bbr_on_round(&b, 101);
  quic_bbr_on_round(&b, 102);
  quic_bbr_on_round(&b, 103);
  CHECK(quic_bbr_cwnd_gain_pct(&b) == 289); /* DRAIN keeps the headroom */
  quic_bbr_drained(&b, 1);
  CHECK(quic_bbr_cwnd_gain_pct(&b) == 200); /* PROBE_BW */
  quic_bbr_on_rtt(&b, 50, 0);
  quic_bbr_check_probe_rtt(&b, 20000);
  CHECK(quic_bbr_cwnd_gain_pct(&b) == 100); /* PROBE_RTT */
}

void test_bbr(void) {
  test_bbr_cwnd_gain_table();
  test_bbr_startup_growth_and_fill();
  test_bbr_drain_exit_and_latch();
  test_bbr_cycle_advances_only_in_probe_bw();
  test_bbr_probe_rtt_round_trip();
  test_bbr_gain_table();
  test_bbr_estimators();
}
