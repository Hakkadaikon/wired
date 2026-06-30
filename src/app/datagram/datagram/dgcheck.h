#ifndef QUIC_DATAGRAM_DGCHECK_H
#define QUIC_DATAGRAM_DGCHECK_H

#include "common/platform/sys/syscall.h"

/* RFC 9221 3: receiving a DATAGRAM frame without having advertised
 * max_datagram_frame_size, or one exceeding the advertised size, is a
 * PROTOCOL_VIOLATION. Returns 1 when the receive is valid, 0 on violation. */
int quic_datagram_recv_ok(
    u64 advertised_max, int we_advertised, u64 frame_size);

#endif
