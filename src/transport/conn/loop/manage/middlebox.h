#ifndef QUIC_MIDDLEBOX_H
#define QUIC_MIDDLEBOX_H

#include "common/platform/sys/syscall.h"

/* RFC 9308 5 / RFC 9312 4: middlebox traversal. QUIC traffic is expected on
 * UDP port 443, and an Initial-bearing datagram must be at least 1200 bytes
 * to pass middleboxes that key on a minimum size. */

/* Whether an Initial-bearing datagram of `datagram_size` meets the minimum. */
int quic_middlebox_initial_ok(usz datagram_size);

/* Whether `port` is the expected QUIC UDP port. */
int quic_middlebox_port_expected(u16 port);

#endif
