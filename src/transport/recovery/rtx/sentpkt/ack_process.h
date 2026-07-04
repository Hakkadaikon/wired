#ifndef QUIC_SENTPKT_ACK_PROCESS_H
#define QUIC_SENTPKT_ACK_PROCESS_H

#include "transport/recovery/rtx/sentpkt/sentpkt.h"

/* The acknowledged set from a received ACK: ack_largest plus the ACK ranges
 * below it, encoded as alternating (gap, range_length) pairs (RFC 9000
 * 19.3). */
typedef struct {
  u64        ack_largest;
  const u64* ack_ranges;
  usz        n_ranges;
} quic_ackset;

/* RFC 9002 5.1: process a received ACK (acked). Each sent packet whose pn
 * falls in an acknowledged range is removed and its pn appended to
 * newly_acked.out; *newly_acked.n is set to the count. */
void quic_ack_process(
    quic_sentpkt* t, const quic_ackset* acked, quic_u64out newly_acked);

#endif
