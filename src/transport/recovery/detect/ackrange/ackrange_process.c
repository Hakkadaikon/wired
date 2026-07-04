#include "transport/recovery/detect/ackrange/ackrange_process.h"

#include "transport/packet/frame/frame/ack.h"

/* An inclusive packet-number range [lo, hi]. */
typedef struct {
  u64 lo;
  u64 hi;
} akr_pnrange;

/* 1 when pn lies within r. */
static int akr_pn_within(u64 pn, akr_pnrange r) {
  return pn >= r.lo && pn <= r.hi;
}

/* 1 when slot i holds an in-flight packet whose pn is in r. */
static int akr_slot_in_range(const quic_sentpkt* t, usz i, akr_pnrange r) {
  const quic_sentpkt_entry* p = &t->e[i];
  return p->used && p->state == QUIC_SP_INFLIGHT && akr_pn_within(p->pn, r);
}

/* Ack every in-flight packet in r, appending pns to out. */
static void akr_ack_range(quic_sentpkt* t, akr_pnrange r, quic_u64out out) {
  for (usz i = 0; i < QUIC_SENTPKT_CAP; i++) {
    if (!akr_slot_in_range(t, i, r)) continue;
    t->e[i].state       = QUIC_SP_ACKED;
    t->e[i].used        = 0;
    out.out[(*out.n)++] = t->e[i].pn;
  }
}

int quic_ackrange_process(
    quic_sentpkt* t, quic_span ack_frame, quic_u64out newly_acked) {
  quic_ack_frame f;
  *newly_acked.n = 0;
  if (quic_ack_decode(ack_frame.p, ack_frame.n, &f) == 0) return 0;
  for (usz i = 0; i < f.n_ranges; i++)
    akr_ack_range(
        t, (akr_pnrange){f.ranges[i].lo, f.ranges[i].hi}, newly_acked);
  return 1;
}
