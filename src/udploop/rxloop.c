#include "udploop/rxloop.h"
#include "packet/coalesce.h"

usz quic_udploop_split(const u8 *buf, usz dlen, const u8 **pkts,
                       usz *pkt_offsets, usz *pkt_lens, usz max_pkts)
{
    quic_coalesce_iter it;
    quic_coalesced pkt;
    usz n = 0;
    quic_coalesce_begin(&it, buf, dlen);
    while (n < max_pkts && quic_coalesce_next(&it, &pkt)) {
        pkts[n] = pkt.data;
        pkt_offsets[n] = (usz)(pkt.data - buf);
        pkt_lens[n] = pkt.len;
        n += 1;
    }
    return n;
}

usz quic_udploop_rx(i64 fd, u8 *buf, usz cap, const u8 **pkts,
                    usz *pkt_offsets, usz *pkt_lens, usz *n_pkts, usz max_pkts)
{
    i64 r = quic_udp_recv(fd, buf, cap); /* RFC 9000 12.2: one datagram */
    usz n;
    if (r <= 0) { *n_pkts = 0; return 0; } /* EAGAIN/empty/error */
    n = quic_udploop_split(buf, (usz)r, pkts, pkt_offsets, pkt_lens, max_pkts);
    *n_pkts = n;
    return n;
}
