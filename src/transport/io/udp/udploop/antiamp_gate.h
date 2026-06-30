#ifndef QUIC_UDPLOOP_ANTIAMP_GATE_H
#define QUIC_UDPLOOP_ANTIAMP_GATE_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 8.1: on an unvalidated path an endpoint may send at most three
 * times the bytes it has received. Once the path is validated the limit no
 * longer applies. Returns 1 if sending next_len more bytes is permitted. */
int quic_udploop_send_allowed(u64 received_bytes, u64 sent_bytes,
                              int address_validated, usz next_len);

#endif
