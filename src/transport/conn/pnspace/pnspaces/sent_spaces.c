#include "transport/conn/pnspace/pnspaces/sent_spaces.h"
#include "sentpkt/ack_process.h"

void quic_pnspaces_sent_init(quic_pnspaces_sent *s)
{
    for (int i = 0; i < QUIC_PNS_COUNT; i++) quic_sentpkt_init(&s->t[i]);
}

int quic_pnspaces_on_send(quic_pnspaces_sent *s, int space, u64 pn, u64 time,
                          int ack_eliciting, usz size)
{
    return quic_sentpkt_on_send(&s->t[space], pn, time, ack_eliciting, size);
}

void quic_pnspaces_on_ack(quic_pnspaces_sent *s, int space, u64 ack_largest,
                          const u64 *ack_ranges, usz n_ranges,
                          u64 *newly_acked_pns, usz *n_acked)
{
    quic_ack_process(&s->t[space], ack_largest, ack_ranges, n_ranges,
                     newly_acked_pns, n_acked);
}

usz quic_pnspaces_sent_count(const quic_pnspaces_sent *s, int space)
{
    return quic_sentpkt_count(&s->t[space]);
}
