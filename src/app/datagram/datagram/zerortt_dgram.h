#ifndef DATAGRAM_ZERORTT_DGRAM_H
#define DATAGRAM_ZERORTT_DGRAM_H

#include "common/platform/sys/syscall.h"

/* RFC 9221 3: "When servers decide to accept 0-RTT data, they MUST send a
 * max_datagram_frame_size transport parameter greater than or equal to the
 * value they sent to the client in the connection where they sent them the
 * NewSessionTicket message." Returns 1 when accepting 0-RTT is safe: the
 * value this connection is about to advertise (accept_max) is >= the value
 * advertised on the ticket-issuing connection (issued_max). */
int datagram_0rtt_accept_ok(u64 issued_max, u64 accept_max);

#endif
