#ifndef QUIC_DATAGRAM_ZERORTT_DGRAM_H
#define QUIC_DATAGRAM_ZERORTT_DGRAM_H

#include "common/platform/sys/syscall.h"

/* RFC 9221 3: a client may send DATAGRAM frames in 0-RTT only if it remembered
 * the peer's max_datagram_frame_size from a previous connection and the frame
 * it wants to send fits within that remembered limit. A remembered limit of 0
 * means the peer did not support DATAGRAM, so 0-RTT DATAGRAM is forbidden. */

/* Returns 1 when a DATAGRAM frame of `frame_size` may be sent in 0-RTT given
 * the `remembered_max` max_datagram_frame_size from the previous connection. */
int datagram_0rtt_ok(u64 remembered_max, u64 frame_size);

/* RFC 9221 3: "When servers decide to accept 0-RTT data, they MUST send a
 * max_datagram_frame_size transport parameter greater than or equal to the
 * value they sent to the client in the connection where they sent them the
 * NewSessionTicket message." Returns 1 when accepting 0-RTT is safe: the
 * value this connection is about to advertise (accept_max) is >= the value
 * advertised on the ticket-issuing connection (issued_max). */
int datagram_0rtt_accept_ok(u64 issued_max, u64 accept_max);

#endif
