#ifndef QUIC_UDPLOOP_RXLOOP_H
#define QUIC_UDPLOOP_RXLOOP_H

#include "common/platform/sys/syscall.h"
#include "transport/io/socket/io/udp.h"

/* RFC 9000 12.2: a received UDP datagram may carry several coalesced QUIC
 * packets. Splitting walks the datagram and records each packet's offset and
 * length. pkts[i] points at pkt_offsets[i] within buf; *n_pkts is the count. */

/* Split an already-received datagram of dlen bytes in buf into its coalesced
 * packets. Returns the number of packets found (also written to *n_pkts). */
usz quic_udploop_split(
    const u8  *buf,
    usz        dlen,
    const u8 **pkts,
    usz       *pkt_offsets,
    usz       *pkt_lens,
    usz        max_pkts);

/* Receive one datagram from fd and split it. Returns the number of QUIC
 * packets; 0 on EAGAIN/empty/error. cap bounds the recv into buf. */
usz quic_udploop_rx(
    i64        fd,
    u8        *buf,
    usz        cap,
    const u8 **pkts,
    usz       *pkt_offsets,
    usz       *pkt_lens,
    usz       *n_pkts,
    usz        max_pkts);

#endif
