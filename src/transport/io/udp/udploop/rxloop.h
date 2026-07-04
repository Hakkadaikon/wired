#ifndef QUIC_UDPLOOP_RXLOOP_H
#define QUIC_UDPLOOP_RXLOOP_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "transport/io/socket/io/udp.h"

/* RFC 9000 12.2: a received UDP datagram may carry several coalesced QUIC
 * packets. Splitting walks the datagram and records each packet's offset and
 * length. pkts[i] points at pkt_offsets[i] within buf; the return value is
 * the count. */

/* Output slots for a split: pkts[i]/pkt_offsets[i]/pkt_lens[i] for i <
 * max_pkts, capacity max_pkts. */
typedef struct {
  const u8** pkts;
  usz*       pkt_offsets;
  usz*       pkt_lens;
  usz        max_pkts;
} quic_pktlist;

/* Split an already-received datagram (dgram.p, dgram.n) into its coalesced
 * packets, writing into out. Returns the number of packets found. */
usz quic_udploop_split(quic_span dgram, const quic_pktlist* out);

/* Receive one datagram from fd into buf and split it into out. Returns the
 * number of QUIC packets; 0 on EAGAIN/empty/error. */
usz quic_udploop_rx(i64 fd, quic_mspan buf, const quic_pktlist* out);

#endif
