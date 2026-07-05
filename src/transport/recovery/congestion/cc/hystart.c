#include "transport/recovery/congestion/cc/hystart.h"

#define HYSTART_NONE (~(u64)0)
#define HYSTART_N_SAMPLES 8
#define HYSTART_MIN_ETA 4
#define HYSTART_MAX_ETA 16

void quic_hystart_init(quic_hystart* h) {
  h->last_round_min = HYSTART_NONE;
  h->curr_round_min = HYSTART_NONE;
  h->samples        = 0;
  h->round_end_pn   = 0;
  h->have_boundary  = 0;
}

/* RFC 9406 4.2: eta = clamp(MIN_RTT_THRESH, lastRoundMinRTT/8,
 * MAX_RTT_THRESH). */
static u64 hystart_eta(u64 last_min) {
  u64 eta = last_min / 8;
  if (eta < HYSTART_MIN_ETA) return HYSTART_MIN_ETA;
  return eta > HYSTART_MAX_ETA ? HYSTART_MAX_ETA : eta;
}

/* Roll into a new round: the current mins become last round's. */
static void hystart_roll(quic_hystart* h, u64 next_pn) {
  h->last_round_min = h->curr_round_min;
  h->curr_round_min = HYSTART_NONE;
  h->samples        = 0;
  h->round_end_pn   = next_pn;
}

/* An ack at or past the boundary ends the round (arming it on round 1). */
static void hystart_maybe_roll(quic_hystart* h, u64 acked_pn, u64 next_pn) {
  if (!h->have_boundary) {
    h->round_end_pn  = next_pn;
    h->have_boundary = 1;
    return;
  }
  if (acked_pn >= h->round_end_pn) hystart_roll(h, next_pn);
}

/* Exit verdict: enough samples this round, a previous round to compare, and
 * the round min risen past it by eta. */
static int hystart_due(const quic_hystart* h) {
  return h->samples >= HYSTART_N_SAMPLES && h->last_round_min != HYSTART_NONE &&
         h->curr_round_min >=
             h->last_round_min + hystart_eta(h->last_round_min);
}

int quic_hystart_sample(
    quic_hystart* h, u64 rtt_ms, u64 acked_pn, u64 next_pn) {
  hystart_maybe_roll(h, acked_pn, next_pn);
  if (rtt_ms < h->curr_round_min) h->curr_round_min = rtt_ms;
  h->samples++;
  return hystart_due(h);
}
