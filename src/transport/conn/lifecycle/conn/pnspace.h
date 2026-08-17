#ifndef CONN_PNSPACE_H
#define CONN_PNSPACE_H

#include "common/platform/sys/syscall.h"

/** RFC 9000 12.3: three independent packet number spaces. Each tracks its own
 * next packet number and is incremented separately; numbers never cross
 * spaces. */
typedef enum { PNS_INITIAL = 0, PNS_HANDSHAKE, PNS_APP, PNS_COUNT } pns_space;

/** Per-space next-packet-number counters (RFC 9000 12.3). */
typedef struct {
  u64 next[PNS_COUNT]; /**< next packet number, indexed by pns_space
                        */
} pnspace;

/* RFC 9000 12.3: 2^62-1 is the highest packet number a sender may ever use;
 * once issued, that space must not send another packet in it (and MUST
 * close the connection without sending a CONNECTION_CLOSE frame). */
#define PN_LIMIT (((u64)1 << 62) - 1)

/* Initialize all spaces to packet number 0. */
void pnspace_init(pnspace* s);

/* Return the next packet number for `space` and advance that space's counter.
 * Each space is strictly monotonic and independent of the others. */
u64 pnspace_next(pnspace* s, pns_space space);

/* RFC 9000 12.3: 1 once `space` has issued PN_LIMIT (its highest legal
 * packet number), meaning the sender must stop sending in it -- silently,
 * without a CONNECTION_CLOSE. 0 while more packet numbers remain. */
int pnspace_exhausted(const pnspace* s, pns_space space);

#endif
