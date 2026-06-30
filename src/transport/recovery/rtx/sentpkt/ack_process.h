#ifndef QUIC_SENTPKT_ACK_PROCESS_H
#define QUIC_SENTPKT_ACK_PROCESS_H

#include "transport/recovery/rtx/sentpkt/sentpkt.h"

/* RFC 9002 5.1: process a received ACK. The acknowledged set is
 * ack_largest plus the ACK ranges below it, encoded as alternating
 * (gap, range_length) pairs per RFC 9000 19.3. Each sent packet whose
 * pn falls in an acknowledged range is removed and its pn appended to
 * newly_acked_pns; *n_acked is set to the count. */
void quic_ack_process(
    quic_sentpkt *t,
    u64           ack_largest,
    const u64    *ack_ranges,
    usz           n_ranges,
    u64          *newly_acked_pns,
    usz          *n_acked);

#endif
