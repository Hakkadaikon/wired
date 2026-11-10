#ifndef MIDDLEBOX_H
#define MIDDLEBOX_H

#include "common/platform/sys/syscall.h"

/* RFC 9308 5 / RFC 9312 4: middlebox traversal. QUIC traffic is expected on
 * UDP port 443, and an Initial-bearing datagram must be at least 1200 bytes
 * to pass middleboxes that key on a minimum size. */

/* Whether an Initial-bearing datagram of `datagram_size` meets the minimum. */
int middlebox_initial_ok(usz datagram_size);

#endif
