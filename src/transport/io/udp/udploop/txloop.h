#ifndef QUIC_UDPLOOP_TXLOOP_H
#define QUIC_UDPLOOP_TXLOOP_H

#include "common/platform/sys/syscall.h"
#include "transport/io/socket/io/udp.h"

/* RFC 9000 12.2: several QUIC packets may be coalesced into one UDP datagram.
 * Packing concatenates n_pkts packets (taken back-to-back from pkts, with
 * lengths in pkt_lens) into scratch. Returns the datagram length, or 0 if the
 * concatenation would exceed cap. */
usz quic_udploop_pack(
    const u8 *pkts, const usz *pkt_lens, usz n_pkts, u8 *scratch, usz cap);

/* Pack the packets and send them as one datagram to peer. Returns the bytes
 * sent, or 0 if packing overflows cap or the send fails. */
usz quic_udploop_tx(
    i64                     fd,
    const quic_sockaddr_in *peer,
    const u8               *pkts,
    const usz              *pkt_lens,
    usz                     n_pkts,
    u8                     *scratch,
    usz                     cap);

#endif
