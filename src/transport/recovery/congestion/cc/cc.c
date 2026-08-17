#include "transport/recovery/congestion/cc/cc.h"

#include "common/bytes/util/num.h"
#include "transport/recovery/congestion/cc/cubic.h"
#include "transport/recovery/congestion/cc/pacing.h"

void cc_init(cc* c) { cc_init_algo(c, QUIC_CC_ALGO_NEWRENO); }

void cc_init_algo(cc* c, int algo) {
  c->cwnd           = QUIC_CC_INIT_WINDOW;
  c->ssthresh       = ~(u64)0; /* "infinite" until the first loss */
  c->in_recovery    = 0;
  c->recovery_start = 0;
  c->algo           = algo;
  c->w_max_seg      = 0;
  c->k_ms           = 0;
  c->epoch_ms       = 0;
  c->round_bytes    = 0;
  c->round_start_ms = 0;
  bbr_init(&c->bbr);
}

/* Grow the window: exponential in slow start, linear in avoidance. */
static void grow(cc* c, u64 acked) {
  u64 inc = (c->cwnd < c->ssthresh)
                ? acked                                     /* slow start */
                : (u64)QUIC_MAX_DATAGRAM * acked / c->cwnd; /* avoidance */
  c->cwnd += inc;
}

/* Leave recovery once an ack arrives for a packet sent after it began. */
static void maybe_exit_recovery(cc* c, u64 sent_time) {
  if (c->in_recovery && sent_time > c->recovery_start) c->in_recovery = 0;
}

/* RFC 9438 4.1: lift cwnd onto the cubic curve at `now`; before the first
 * loss (no epoch) CUBIC slow-starts like NewReno. */
static void grow_cubic(cc* c, u64 acked, u64 now) {
  u64 target;
  if (!c->w_max_seg) {
    grow(c, acked);
    return;
  }
  target =
      cubic_w(now - c->epoch_ms, c->k_ms, c->w_max_seg) * QUIC_MAX_DATAGRAM;
  if (target > c->cwnd) c->cwnd = target;
}

/* BBR: acks only feed the samplers; cwnd moves in cc_bbr_tick. */
static void feed_bbr(cc* c, u64 acked, u64 sent_time, u64 now) {
  bbr_on_rtt(&c->bbr, now - sent_time, now);
  c->round_bytes += acked;
}

static void grow_algo(cc* c, u64 acked, u64 now) {
  if (c->algo == QUIC_CC_ALGO_CUBIC) {
    grow_cubic(c, acked, now);
    return;
  }
  grow(c, acked);
}

void cc_on_ack(cc* c, u64 acked, u64 sent_time, u64 now) {
  if (c->algo == QUIC_CC_ALGO_BBR) {
    feed_bbr(c, acked, sent_time, now);
    return;
  }
  maybe_exit_recovery(c, sent_time);
  if (!c->in_recovery) grow_algo(c, acked, now);
}

/* RFC 9438 4.6/4.7: remember W_max (fast convergence), re-anchor the cubic
 * epoch at this loss, shrink by beta_cubic (0.7). */
static u64 loss_window_cubic(cc* c, u64 now) {
  u64 w_seg    = c->cwnd / QUIC_MAX_DATAGRAM;
  c->w_max_seg = cubic_wmax_fastconv(w_seg, c->w_max_seg);
  c->k_ms      = cubic_k_ms(c->w_max_seg);
  c->epoch_ms  = now;
  return u64_max(c->cwnd * 7 / 10, QUIC_CC_MIN_WINDOW);
}

static u64 loss_window(cc* c, u64 now) {
  if (c->algo == QUIC_CC_ALGO_CUBIC) return loss_window_cubic(c, now);
  return u64_max(c->cwnd / 2, QUIC_CC_MIN_WINDOW);
}

void cc_on_loss(cc* c, u64 sent_time, u64 now) {
  if (c->in_recovery || sent_time < c->recovery_start) return; /* once/window */
  c->ssthresh       = loss_window(c, now);
  c->cwnd           = c->ssthresh;
  c->in_recovery    = 1;
  c->recovery_start = now;
}

void cc_on_persistent(cc* c) { c->cwnd = QUIC_CC_MIN_WINDOW; }

/* The bandwidth-delay product in bytes (btl_bw B/ms x rtprop ms). */
static u64 bbr_bdp(const cc* c) { return c->bbr.btl_bw * c->bbr.rtprop_ms; }

/* A starved round -- far fewer bytes delivered than the window would carry
 * (loss-stalled, idle, or app-limited) -- proves nothing about the
 * bottleneck: its sample may only RAISE the estimate. Feeding it into the
 * max filter would age the real peak out within QUIC_BBR_BW_WIN rounds and
 * spiral cwnd down to the floor (observed live: a startup loss storm
 * starved a few rounds, btl_bw collapsed, and the transfer never
 * recovered). */
static int bbr_round_counts(const cc* c, u64 rate) {
  int starved = c->round_bytes + QUIC_MAX_DATAGRAM < c->cwnd;
  return !starved || rate > c->bbr.btl_bw;
}

/* Feed one closed round: the (guarded) bandwidth sample, one PROBE_BW gain
 * cycle step -- per ROUND, not per tick: srvrun ticks every received
 * datagram (~ms) and would spin the 8-phase cycle into noise -- and the
 * next round's baseline. */
static void bbr_round_feed(cc* c, u64 now_ms, u64 rate) {
  if (bbr_round_counts(c, rate)) bbr_on_round(&c->bbr, rate);
  bbr_cycle_tick(&c->bbr);
  c->round_bytes    = 0;
  c->round_start_ms = now_ms;
}

/* Close the sample round once at least one rtprop (min 1ms) has elapsed. */
static void bbr_round_close(cc* c, u64 now_ms) {
  u64 span = now_ms - c->round_start_ms;
  u64 need = u64_max(c->bbr.rtprop_ms, 1);
  if (span < need || !c->round_bytes) return;
  bbr_round_feed(c, now_ms, c->round_bytes / span);
}

/* draft-cardwell-iccrg-bbr 4.2.3.4 BBRMinPipeCwnd: never below 4 packets,
 * so ACK clocking survives a collapsed estimate -- at 2 packets a
 * delayed-ACK peer measures rtt ~2x rtprop and the tiny bandwidth estimate
 * becomes self-consistent (a 2400-byte cwnd fixed point, observed live). */
#define QUIC_CC_BBR_MIN_CWND (4 * QUIC_MAX_DATAGRAM)

/* cwnd = cwnd_gain x BDP once the estimators have data. */
static void bbr_set_cwnd(cc* c) {
  u64 bdp = bbr_bdp(c);
  if (!bdp) return;
  c->cwnd =
      u64_max(bbr_cwnd_gain_pct(&c->bbr) * bdp / 100, QUIC_CC_BBR_MIN_CWND);
}

void cc_bbr_tick(cc* c, u64 inflight_bytes, u64 now_ms) {
  if (c->algo != QUIC_CC_ALGO_BBR) return;
  bbr_round_close(c, now_ms);
  bbr_drained(&c->bbr, inflight_bytes <= bbr_bdp(c));
  if (!bbr_check_probe_rtt(&c->bbr, now_ms))
    bbr_probe_rtt_exit(&c->bbr, now_ms);
  bbr_set_cwnd(c);
}

/* BBR rate: mtu / (pacing_gain x btl_bw), floored at 1ms once bw is known. */
static u64 bbr_pacing_ms(const cc* c, u64 mtu) {
  u64 rate = bbr_pacing_gain_pct(&c->bbr) * c->bbr.btl_bw / 100;
  if (!rate) return 0;
  return u64_max(mtu / rate, 1);
}

/* NewReno/CUBIC pacing: RFC 9002 7.7 interval, floored at 1ms once an RTT
 * sample exists -- integer ms truncates any interval under 1ms to 0, which
 * left srvrun_pump_sess's per-step drain loop unpaced once cwnd grew large
 * enough (interval = 5*mtu*srtt/(4*cwnd) < 1), bursting a whole log's worth
 * of packets in one step and overflowing the network simulator's queue. */
static u64 newreno_pacing_ms(const cc* c, u64 srtt_ms, u64 mtu) {
  u64 ms = pacing_interval(srtt_ms, c->cwnd, mtu);
  return srtt_ms ? u64_max(ms, 1) : ms;
}

u64 cc_pacing_ms(const cc* c, u64 srtt_ms, u64 mtu) {
  if (c->algo == QUIC_CC_ALGO_BBR) return bbr_pacing_ms(c, mtu);
  return newreno_pacing_ms(c, srtt_ms, mtu);
}
