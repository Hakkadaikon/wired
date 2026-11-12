#ifndef CONN_PNSPACE_H
#define CONN_PNSPACE_H

#include "common/platform/sys/syscall.h"

/** RFC 9000 12.3: three independent packet number spaces; numbers never
 * cross spaces. */
typedef enum { PNS_INITIAL = 0, PNS_HANDSHAKE, PNS_APP, PNS_COUNT } pns_space;

/* RFC 9000 12.3: 2^62-1 is the highest packet number a sender may ever use;
 * once it is reached the sender MUST close the connection without sending a
 * CONNECTION_CLOSE frame (srvrun_silent_due). */
#define PN_LIMIT (((u64)1 << 62) - 1)

#endif
