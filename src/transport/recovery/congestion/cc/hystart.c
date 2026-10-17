#include "transport/recovery/congestion/cc/hystart.h"

#define HYSTART_NONE (~(u64)0)
#define HYSTART_N_SAMPLES 8
#define HYSTART_MIN_ETA 4
#define HYSTART_MAX_ETA 16
#define HYSTART_CSS_GROWTH_DIVISOR 4
#define HYSTART_CSS_ROUNDS 5

void hystart_init(hystart* h) {
  h->last_round_min = HYSTART_NONE;
  h->curr_round_min = HYSTART_NONE;
  h->samples        = 0;
  h->round_end_pn   = 0;
  h->have_boundary  = 0;
  h->css            = 0;
  h->css_baseline   = HYSTART_NONE;
  h->css_rounds     = 0;
}

/* RFC 9406 4.2: eta = clamp(MIN_RTT_THRESH, lastRoundMinRTT/8,
 * MAX_RTT_THRESH). */
static u64 hystart_eta(u64 last_min) {
  u64 eta = last_min / 8;
  if (eta < HYSTART_MIN_ETA) {
    return HYSTART_MIN_ETA;
  }
  return eta > HYSTART_MAX_ETA ? HYSTART_MAX_ETA : eta;
}

/* Roll into a new round: the current mins become last round's; a round
 * ending in CSS counts toward CSS_ROUNDS. */
static void hystart_roll(hystart* h, u64 next_pn) {
  h->css_rounds += (usz)h->css;
  h->last_round_min = h->curr_round_min;
  h->curr_round_min = HYSTART_NONE;
  h->samples        = 0;
  h->round_end_pn   = next_pn;
}

/* An ack at or past the boundary ends the round (arming it on round 1). */
static void hystart_maybe_roll(hystart* h, u64 acked_pn, u64 next_pn) {
  if (!h->have_boundary) {
    h->round_end_pn  = next_pn;
    h->have_boundary = 1;
    return;
  }
  if (acked_pn >= h->round_end_pn) {
    hystart_roll(h, next_pn);
  }
}

/* Exit verdict: enough samples this round, a previous round to compare, and
 * the round min risen past it by eta. */
static int hystart_due(const hystart* h) {
  return h->samples >= HYSTART_N_SAMPLES && h->last_round_min != HYSTART_NONE &&
         h->curr_round_min >=
             h->last_round_min + hystart_eta(h->last_round_min);
}

/* RFC 9406 4.2: a delay increase enters CSS with this round's min as the
 * baseline; slow start itself goes on. */
static int hystart_ss_step(hystart* h) {
  if (!hystart_due(h)) {
    return 0;
  }
  h->css          = 1;
  h->css_baseline = h->curr_round_min;
  h->css_rounds   = 0;
  return 0;
}

/* RFC 9406 4.2: the RTT fell back below the CSS baseline over a full
 * sample set -- the increase was spurious. */
static int hystart_css_spurious(const hystart* h) {
  return h->samples >= HYSTART_N_SAMPLES && h->curr_round_min < h->css_baseline;
}

/* In CSS: resume slow start on a spurious increase, else end slow start
 * once CSS_ROUNDS rounds have passed. */
static int hystart_css_step(hystart* h) {
  if (hystart_css_spurious(h)) {
    h->css = 0;
    return 0;
  }
  return h->css_rounds >= HYSTART_CSS_ROUNDS;
}

u64 hystart_acked(const hystart* h, u64 acked) {
  return h->css ? acked / HYSTART_CSS_GROWTH_DIVISOR : acked;
}

int hystart_sample(hystart* h, u64 rtt_ms, u64 acked_pn, u64 next_pn) {
  hystart_maybe_roll(h, acked_pn, next_pn);
  if (rtt_ms < h->curr_round_min) {
    h->curr_round_min = rtt_ms;
  }
  h->samples++;
  return h->css ? hystart_css_step(h) : hystart_ss_step(h);
}
