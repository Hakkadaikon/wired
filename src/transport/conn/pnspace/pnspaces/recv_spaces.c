#include "transport/conn/pnspace/pnspaces/recv_spaces.h"
#include "ackgen/ackrange.h"

void quic_pnspaces_recv_init(quic_pnspaces_recv *s)
{
    for (int i = 0; i < QUIC_PNS_COUNT; i++) quic_recvpn_init(&s->r[i]);
}

void quic_pnspaces_on_recv(quic_pnspaces_recv *s, int space, u64 pn)
{
    quic_recvpn_record(&s->r[space], pn);
}

/* Collect received PNs in `r` into out ascending (lowest first), returning the
 * count. At most QUIC_PNSPACES_ACK_CAP entries: the window below largest, then
 * largest itself. */
static usz collect_pns(const quic_recvpn *r, u64 *out)
{
    usz n = 0;
    for (u64 d = QUIC_RECVPN_WINDOW; d >= 1; d--)
        if (quic_recvpn_seen(r, r->largest - d)) out[n++] = r->largest - d;
    out[n++] = r->largest;
    return n;
}

int quic_pnspaces_ack_ranges(const quic_pnspaces_recv *s, int space,
                             u64 *largest, u64 *ranges, usz *n_ranges, usz cap)
{
    u64 pns[QUIC_PNSPACES_ACK_CAP];
    const quic_recvpn *r = &s->r[space];
    if (!r->any) return 0;
    return quic_ackgen_build_ranges(pns, collect_pns(r, pns), largest, ranges,
                                    n_ranges, cap);
}
