#ifndef QUIC_UDPLOOP_TXLOOP_H
#define QUIC_UDPLOOP_TXLOOP_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "transport/io/socket/io/udp.h"

/* n_pkts packets taken back-to-back from pkts, with lengths in pkt_lens. */
typedef struct {
  const u8*  pkts;
  const usz* pkt_lens;
  usz        n_pkts;
} quic_pktsrc;

/* RFC 9000 12.2: several QUIC packets may be coalesced into one UDP datagram.
 * Packing concatenates src's packets into out. Returns the datagram length
 * (also out->len), or 0 if the concatenation would exceed out->cap. */
usz quic_udploop_pack(const quic_pktsrc* src, quic_obuf* out);

/* A destination socket: an open fd and the peer to send to. */
typedef struct {
  i64                     fd;
  const quic_sockaddr_in* peer;
} quic_udpdst;

/* Pack the packets and send them as one datagram to dst. Returns the bytes
 * sent, or 0 if packing overflows out->cap or the send fails. */
usz quic_udploop_tx(
    const quic_udpdst* dst, const quic_pktsrc* src, quic_obuf* out);

#endif
