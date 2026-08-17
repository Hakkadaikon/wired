#include "transport/recovery/congestion/cc/bbr.h"

void bbr_init(bbr* b) {
  b->phase         = BBR_STARTUP;
  b->bw_idx        = 0;
  b->btl_bw        = 0;
  b->full_bw       = 0;
  b->full_bw_cnt   = 0;
  b->filled        = 0;
  b->cycle_idx     = 0;
  b->rtprop_ms     = 0;
  b->rtprop_at     = 0;
  b->have_rtprop   = 0;
  b->probe_rtt_end = 0;
  for (usz i = 0; i < BBR_BW_WIN; i++) b->bw_win[i] = 0;
}

/* Windowed max over the last BBR_BW_WIN round samples. */
static u64 bbr_win_max(const bbr* b) {
  u64 m = 0;
  for (usz i = 0; i < BBR_BW_WIN; i++)
    if (b->bw_win[i] > m) m = b->bw_win[i];
  return m;
}

/* 1.25x growth takes a new baseline and resets the flat count. */
static int bbr_grew(bbr* b, u64 bw) {
  if (bw * 4 < b->full_bw * 5) return 0;
  b->full_bw     = bw;
  b->full_bw_cnt = 0;
  return 1;
}

/* Three flat rounds latch the pipe full. */
static void bbr_count_flat(bbr* b) {
  if (++b->full_bw_cnt >= 3) b->filled = 1;
}

/* BBRCheckFullPipe. */
static void bbr_full_pipe_check(bbr* b, u64 bw) {
  if (b->filled || bbr_grew(b, bw)) return;
  bbr_count_flat(b);
}

/* BBRCheckDrain (entry half): a full pipe ends STARTUP. */
static void bbr_maybe_drain(bbr* b) {
  if (b->phase == BBR_STARTUP && b->filled) b->phase = BBR_DRAIN;
}

void bbr_on_round(bbr* b, u64 bw_sample) {
  b->bw_win[b->bw_idx] = bw_sample;
  b->bw_idx            = (b->bw_idx + 1) % BBR_BW_WIN;
  b->btl_bw            = bbr_win_max(b);
  bbr_full_pipe_check(b, b->btl_bw);
  bbr_maybe_drain(b);
}

/* A fresh minimum (or an aged-out window) takes the sample. */
static int bbr_rtprop_take(const bbr* b, u64 rtt_ms, u64 now_ms) {
  return !b->have_rtprop || rtt_ms <= b->rtprop_ms ||
         now_ms - b->rtprop_at > BBR_RTPROP_WIN_MS;
}

void bbr_on_rtt(bbr* b, u64 rtt_ms, u64 now_ms) {
  if (!bbr_rtprop_take(b, rtt_ms, now_ms)) return;
  b->rtprop_ms   = rtt_ms;
  b->rtprop_at   = now_ms;
  b->have_rtprop = 1;
}

void bbr_drained(bbr* b, int inflight_at_bdp) {
  if (b->phase == BBR_DRAIN && inflight_at_bdp) b->phase = BBR_PROBE_BW;
}

void bbr_cycle_tick(bbr* b) {
  if (b->phase != BBR_PROBE_BW) return;
  b->cycle_idx = (b->cycle_idx + 1) % 8;
}

/* Due when the rtprop window expired and we are not already probing. */
static int bbr_probe_rtt_due(const bbr* b, u64 now_ms) {
  return b->phase != BBR_PROBE_RTT && b->have_rtprop &&
         now_ms - b->rtprop_at > BBR_RTPROP_WIN_MS;
}

int bbr_check_probe_rtt(bbr* b, u64 now_ms) {
  if (!bbr_probe_rtt_due(b, now_ms)) return 0;
  b->phase         = BBR_PROBE_RTT;
  b->probe_rtt_end = now_ms + BBR_PROBE_RTT_MS;
  return 1;
}

/* Where PROBE_RTT hands off: a filled pipe cruises, an unfilled one grows. */
static int bbr_exit_phase(const bbr* b) {
  return b->filled ? BBR_PROBE_BW : BBR_STARTUP;
}

void bbr_probe_rtt_exit(bbr* b, u64 now_ms) {
  if (b->phase != BBR_PROBE_RTT || now_ms < b->probe_rtt_end) return;
  b->phase = bbr_exit_phase(b);
  /* leaving PROBE_RTT refreshes the window baseline (dwell measured it) */
  b->rtprop_at = now_ms;
}

/* PROBE_BW gain cycle (BBRGainCycle): probe up, drain, then cruise x6. */
static const u64 bbr_cycle_pct[8] = {125, 75, 100, 100, 100, 100, 100, 100};

u64 bbr_pacing_gain_pct(const bbr* b) {
  /* STARTUP 2/ln2, DRAIN its inverse, PROBE_RTT neutral. */
  static const u64 by_phase[4] = {289, 35, 0, 100};
  if (b->phase == BBR_PROBE_BW) return bbr_cycle_pct[b->cycle_idx];
  return by_phase[b->phase];
}

u64 bbr_cwnd_gain_pct(const bbr* b) {
  static const u64 by_phase[4] = {289, 289, 200, 100};
  return by_phase[b->phase];
}
