#include "app/datagram/dgpriority/dgpriority.h"

/* RFC 9221 5.1 */
int quic_dgpriority_valid(u8 u) { return u <= QUIC_DGPRIORITY_MAX; }

/* RFC 9221 5.1: matches quic_h3_priority_higher's convention (lower value =
 * more urgent) so a DATAGRAM's urgency and a stream's urgency compare
 * directly. */
int quic_dgpriority_higher(u8 urg_a, u8 urg_b) { return urg_a < urg_b; }

/* 1 if candidate i outranks the current best (strictly more urgent; ties
 * keep the earlier index, so pick_step never overwrites on equal urgency). */
static int outranks_best(
    const quic_dgpriority_candidate* candidates, usz best, usz i) {
  return quic_dgpriority_higher(
      candidates[i].urgency, candidates[best].urgency);
}

/* candidates[0..n) is non-empty: scan for the most urgent index. */
static usz pick_best(const quic_dgpriority_candidate* candidates, usz n) {
  usz best = 0;
  for (usz i = 1; i < n; i++)
    if (outranks_best(candidates, best, i)) best = i;
  return best;
}

i64 quic_dgpriority_pick(const quic_dgpriority_candidate* candidates, usz n) {
  if (n == 0) return -1;
  return (i64)pick_best(candidates, n);
}
