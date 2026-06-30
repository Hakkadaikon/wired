#include "transport/recovery/rtx/sentpkt/ack_process.h"

/* True when pn lies within [lo, hi]. */
static int pn_within(u64 pn, u64 lo, u64 hi) { return pn >= lo && pn <= hi; }

/* True when slot i holds an in-flight packet whose pn is in [lo, hi]. */
static int slot_in_range(const quic_sentpkt *t, usz i, u64 lo, u64 hi) {
  const quic_sentpkt_entry *p = &t->e[i];
  return p->used && p->state == QUIC_SP_INFLIGHT && pn_within(p->pn, lo, hi);
}

/* Remove every in-flight packet in [lo, hi], appending pns to out. */
static void ack_range(quic_sentpkt *t, u64 lo, u64 hi, u64 *out, usz *n) {
  for (usz i = 0; i < QUIC_SENTPKT_CAP; i++) {
    if (!slot_in_range(t, i, lo, hi)) continue;
    t->e[i].state = QUIC_SP_ACKED;
    t->e[i].used  = 0;
    out[(*n)++]   = t->e[i].pn;
  }
}

/* RFC 9000 19.3: ranges are first_len, then (gap, range_len) pairs. The
 * top of each successive range is the previous low minus gap minus 2. */
void quic_ack_process(
    quic_sentpkt *t,
    u64           ack_largest,
    const u64    *ack_ranges,
    usz           n_ranges,
    u64          *newly_acked_pns,
    usz          *n_acked) {
  *n_acked = 0;
  if (n_ranges == 0) return;
  u64 hi = ack_largest;
  u64 lo = hi - ack_ranges[0];
  ack_range(t, lo, hi, newly_acked_pns, n_acked);
  for (usz i = 1; i + 1 < n_ranges; i += 2) {
    hi = lo - ack_ranges[i] - 2;
    lo = hi - ack_ranges[i + 1];
    ack_range(t, lo, hi, newly_acked_pns, n_acked);
  }
}
