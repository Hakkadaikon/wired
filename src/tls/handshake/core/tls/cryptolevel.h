#ifndef TLS_CRYPTOLEVEL_H
#define TLS_CRYPTOLEVEL_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 4.1.3: 1 if a level being superseded still has
 * buffered-but-undelivered data: received_to (the contiguous prefix
 * received) is past read_upto (the prefix already handed to TLS). Call when
 * keys for a higher level are about to be installed; a true result is a
 * connection error of type PROTOCOL_VIOLATION. */
int cryptolevel_unconsumed_on_promote(u64 received_to, u64 read_upto);

#endif
