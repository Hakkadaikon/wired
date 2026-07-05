#ifndef QUIC_CC_BBR_H
#define QUIC_CC_BBR_H

#include "common/platform/sys/syscall.h"

/** @file
 * BBR v1 phase machine and estimators
 * (draft-cardwell-iccrg-bbr-congestion-control): model-based congestion
 * control driven by a windowed-max bottleneck-bandwidth estimate and a
 * windowed-min round-trip propagation delay. Integer-only; gains are
 * percentages. This is the pure state core — BDP/cwnd arithmetic and the
 * delivery-rate sampler live with the caller. */

#define QUIC_BBR_STARTUP 0
#define QUIC_BBR_DRAIN 1
#define QUIC_BBR_PROBE_BW 2
#define QUIC_BBR_PROBE_RTT 3

/** Rounds the bottleneck-bandwidth max filter spans (BBRBtlBwFilterLen). */
#define QUIC_BBR_BW_WIN 10
/** RTprop validity window in ms (RTpropFilterLen, 10s). */
#define QUIC_BBR_RTPROP_WIN_MS 10000
/** PROBE_RTT dwell in ms (ProbeRTTDuration, 200ms). */
#define QUIC_BBR_PROBE_RTT_MS 200

typedef struct {
  int phase;                   /**< QUIC_BBR_* */
  u64 bw_win[QUIC_BBR_BW_WIN]; /**< per-round delivery-rate samples */
  usz bw_idx;                  /**< next slot in bw_win (ring) */
  u64 btl_bw;        /**< max of bw_win: bottleneck bandwidth estimate */
  u64 full_bw;       /**< growth baseline for the full-pipe check */
  int full_bw_cnt;   /**< rounds without 1.25x growth (3 fills the pipe) */
  int filled;        /**< full-pipe latch; never clears (BBRCheckFullPipe) */
  int cycle_idx;     /**< PROBE_BW gain-cycle position, 0..7 */
  u64 rtprop_ms;     /**< windowed-min round-trip propagation delay */
  u64 rtprop_at;     /**< when rtprop_ms was last lowered/refreshed */
  int have_rtprop;   /**< 1 once any RTT sample arrived */
  u64 probe_rtt_end; /**< PROBE_RTT dwell deadline */
} quic_bbr;

void quic_bbr_init(quic_bbr* b);

/** Feed one round's delivery-rate sample (bytes/ms or any consistent unit):
 * refreshes the windowed-max estimate and runs the full-pipe check —
 * STARTUP moves to DRAIN once three rounds pass without 1.25x growth. */
void quic_bbr_on_round(quic_bbr* b, u64 bw_sample);

/** Feed one RTT sample at now: keeps the windowed minimum (a lower sample
 * or an expired window takes it). */
void quic_bbr_on_rtt(quic_bbr* b, u64 rtt_ms, u64 now_ms);

/** DRAIN exit check: once inflight has drained to the BDP
 * (inflight_at_bdp = 1, judged by the caller) DRAIN moves to PROBE_BW. */
void quic_bbr_drained(quic_bbr* b, int inflight_at_bdp);

/** Advance the PROBE_BW gain cycle one step (modulo 8); frozen elsewhere. */
void quic_bbr_cycle_tick(quic_bbr* b);

/** RTprop-expiry check (BBRCheckProbeRTT): with the window expired, any
 * phase yields to PROBE_RTT and the dwell deadline is armed.
 * @return 1 when PROBE_RTT was entered. */
int quic_bbr_check_probe_rtt(quic_bbr* b, u64 now_ms);

/** PROBE_RTT exit (BBRExitProbeRTT): after the dwell, return to PROBE_BW
 * when the pipe filled, else back to STARTUP. */
void quic_bbr_probe_rtt_exit(quic_bbr* b, u64 now_ms);

/** The phase's pacing gain in percent (STARTUP 289 = 2/ln2, DRAIN 35 its
 * inverse, PROBE_BW cycles 125,75,100x6, PROBE_RTT 100). */
u64 quic_bbr_pacing_gain_pct(const quic_bbr* b);

#endif
