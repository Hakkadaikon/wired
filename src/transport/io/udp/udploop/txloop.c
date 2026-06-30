#include "transport/io/udp/udploop/txloop.h"
#include "common/bytes/util/bytes.h"

usz quic_udploop_pack(const u8 *pkts, const usz *pkt_lens, usz n_pkts,
                      u8 *scratch, usz cap)
{
    usz off = 0;
    const u8 *src = pkts;
    for (usz i = 0; i < n_pkts; i++) {
        if (!quic_put_bytes(scratch, cap, &off, src, pkt_lens[i])) return 0;
        src += pkt_lens[i];
    }
    return off;
}

/* The full datagram was sent iff send returned exactly len bytes. */
static int sent_whole(i64 r, usz len)
{
    return r >= 0 && (usz)r == len;
}

usz quic_udploop_tx(i64 fd, const quic_sockaddr_in *peer, const u8 *pkts,
                    const usz *pkt_lens, usz n_pkts, u8 *scratch, usz cap)
{
    usz len = quic_udploop_pack(pkts, pkt_lens, n_pkts, scratch, cap);
    i64 r;
    if (len == 0) return 0; /* RFC 9000 12.2: overflow or nothing to send */
    r = quic_udp_send(fd, peer, scratch, len);
    return sent_whole(r, len) ? len : 0;
}
