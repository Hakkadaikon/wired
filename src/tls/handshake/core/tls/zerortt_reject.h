#ifndef TLS_ZERORTT_REJECT_H
#define TLS_ZERORTT_REJECT_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 4.6.1: if the server rejects 0-RTT, the client must discard the
 * 0-RTT keys and treat the 0-RTT data as needing retransmission in 1-RTT. */
void zerortt_on_reject(int* retransmit_needed, int* discard_keys);

/* server_accepted is 1 if the server accepted 0-RTT, 0 if it rejected. */
int zerortt_accepted(int server_accepted);

/* RFC 9001 4.9.3: once a 1-RTT packet has been received, 0-RTT keys are no
 * longer needed and should be discarded within a short time (three times
 * the PTO is recommended) rather than kept for the rest of the connection.
 * first_1rtt_recv is the time the first 1-RTT packet was received; now and
 * pto share that time unit. Returns 1 once that window has elapsed. */
int zerortt_should_discard(u64 first_1rtt_recv, u64 now, u64 pto);

#endif
