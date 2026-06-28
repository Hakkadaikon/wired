#include "ackrange/ackrange_process.h"
#include "frame/ack.h"

/* 1 when pn lies within [lo, hi]. */
static int akr_pn_within(u64 pn, u64 lo, u64 hi) { return pn >= lo && pn <= hi; }

/* 1 when slot i holds an in-flight packet whose pn is in [lo, hi]. */
static int akr_slot_in_range(const quic_sentpkt *t, usz i, u64 lo, u64 hi)
{
    const quic_sentpkt_entry *p = &t->e[i];
    return p->used && p->state == QUIC_SP_INFLIGHT && akr_pn_within(p->pn, lo, hi);
}

/* Ack every in-flight packet in [lo, hi], appending pns to out. */
static void akr_ack_range(quic_sentpkt *t, u64 lo, u64 hi, u64 *out, usz *n)
{
    for (usz i = 0; i < QUIC_SENTPKT_CAP; i++) {
        if (!akr_slot_in_range(t, i, lo, hi)) continue;
        t->e[i].state = QUIC_SP_ACKED;
        t->e[i].used = 0;
        out[(*n)++] = t->e[i].pn;
    }
}

int quic_ackrange_process(quic_sentpkt *t, const u8 *ack_frame, usz len,
                          u64 *newly_acked, usz *n_acked)
{
    quic_ack_frame f;
    *n_acked = 0;
    if (quic_ack_decode(ack_frame, len, &f) == 0) return 0;
    for (usz i = 0; i < f.n_ranges; i++)
        akr_ack_range(t, f.ranges[i].lo, f.ranges[i].hi, newly_acked, n_acked);
    return 1;
}
