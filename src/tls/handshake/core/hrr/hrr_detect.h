#ifndef QUIC_HRR_DETECT_H
#define QUIC_HRR_DETECT_H

#include "common/platform/sys/syscall.h"

/* RFC 8446 4.1.4: a ServerHello is a HelloRetryRequest iff its random equals
 * the fixed SHA-256("HelloRetryRequest") sentinel. sh_msg is a handshake
 * message (type 0x02 | length(3) | body). Returns 1 on a match, else 0. */
int quic_hrr_is_hello_retry(const u8 *sh_msg, usz len);

#endif
