#ifndef QUIC_CC_CWNDCHECK_H
#define QUIC_CC_CWNDCHECK_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 7.5/7.8: congestion-window admission and application-limited
 * detection. Sizes in bytes. */

/* True when sending `size` more bytes keeps bytes-in-flight within cwnd. */
int cwnd_can_send(u64 in_flight, u64 cwnd, u64 size);

/* RFC 9002 7.8: application-limited when in-flight does not fill cwnd, so
 * the window must not grow on acks. */
int cwnd_app_limited(u64 in_flight, u64 cwnd);

#endif
