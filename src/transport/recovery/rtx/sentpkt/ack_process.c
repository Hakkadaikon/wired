#include "transport/recovery/rtx/sentpkt/ack_process.h"

/* An inclusive packet-number range [lo, hi]. */
typedef struct {
  u64 lo;
  u64 hi;
} ap_pnrange;

/* True when pn lies within r. */
static int pn_within(u64 pn, ap_pnrange r) { return pn >= r.lo && pn <= r.hi; }

/* True when slot i holds an in-flight packet whose pn is in r. */
static int slot_in_range(const quic_sentpkt* t, usz i, ap_pnrange r) {
  const quic_sentpkt_entry* p = &t->e[i];
  return p->used && p->state == QUIC_SP_INFLIGHT && pn_within(p->pn, r);
}

/* Remove every in-flight packet in r, appending pns to out. */
static void ack_range(quic_sentpkt* t, ap_pnrange r, quic_u64out out) {
  for (usz i = 0; i < QUIC_SENTPKT_CAP; i++) {
    if (!slot_in_range(t, i, r)) continue;
    t->e[i].state       = QUIC_SP_ACKED;
    t->e[i].used        = 0;
    out.out[(*out.n)++] = t->e[i].pn;
  }
}

/* RFC 9000 19.3: ranges are first_len, then (gap, range_len) pairs. The
 * top of each successive range is the previous low minus gap minus 2. */
void quic_ack_process(
    quic_sentpkt* t, const quic_ackset* acked, quic_u64out newly_acked) {
  *newly_acked.n = 0;
  if (acked->n_ranges == 0) return;
  u64 hi = acked->ack_largest;
  u64 lo = hi - acked->ack_ranges[0];
  ack_range(t, (ap_pnrange){lo, hi}, newly_acked);
  for (usz i = 1; i + 1 < acked->n_ranges; i += 2) {
    hi = lo - acked->ack_ranges[i] - 2;
    lo = hi - acked->ack_ranges[i + 1];
    ack_range(t, (ap_pnrange){lo, hi}, newly_acked);
  }
}
