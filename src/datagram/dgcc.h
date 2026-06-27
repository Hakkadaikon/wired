#ifndef QUIC_DATAGRAM_DGCC_H
#define QUIC_DATAGRAM_DGCC_H

#include "sys/syscall.h"

/* RFC 9221 5.3: DATAGRAM frames are not subject to flow control. */
int quic_datagram_flow_controlled(void);

/* RFC 9221 5.4: DATAGRAM frames are subject to congestion control. */
int quic_datagram_congestion_controlled(void);

/* RFC 9221 5.4: their bytes count against the in-flight congestion window. */
u64 quic_datagram_counts_in_flight(u64 size);

/* RFC 9221 5.2: DATAGRAM frames are ack-eliciting but are never retransmitted
 * on loss. Returns 1 (ack-eliciting). */
int quic_datagram_ack_eliciting(void);

/* RFC 9221 5.2: never retransmitted. Returns 0. */
int quic_datagram_retransmittable(void);

#endif
