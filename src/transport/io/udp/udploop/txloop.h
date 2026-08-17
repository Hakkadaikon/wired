#ifndef UDPLOOP_TXLOOP_H
#define UDPLOOP_TXLOOP_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "transport/io/socket/io/udp.h"

/** n_pkts packets taken back-to-back from pkts, with lengths in pkt_lens. */
typedef struct {
  const u8*  pkts;
  const usz* pkt_lens;
  usz        n_pkts;
} pktsrc;

/* RFC 9000 12.2: several QUIC packets may be coalesced into one UDP datagram.
 * Packing concatenates src's packets into out. Returns the datagram length
 * (also out->len), or 0 if the concatenation would exceed out->cap. */
usz udploop_pack(const pktsrc* src, wired_obuf* out);

/** A destination socket: an open fd and the peer to send to. */
typedef struct {
  i64             fd;
  const sockaddr* peer;
} udpdst;

/* Pack the packets and send them as one datagram to dst. Returns the bytes
 * sent, or 0 if packing overflows out->cap or the send fails. */
usz udploop_tx(const udpdst* dst, const pktsrc* src, wired_obuf* out);

#endif
