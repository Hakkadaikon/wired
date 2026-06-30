#ifndef QUIC_CONN_PNSPACE_H
#define QUIC_CONN_PNSPACE_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 12.3: three independent packet number spaces. Each tracks its own
 * next packet number and is incremented separately; numbers never cross
 * spaces. */
typedef enum {
    QUIC_PNS_INITIAL = 0,
    QUIC_PNS_HANDSHAKE,
    QUIC_PNS_APP,
    QUIC_PNS_COUNT
} quic_pns_space;

typedef struct {
    u64 next[QUIC_PNS_COUNT];
} quic_pnspace;

/* Initialize all spaces to packet number 0. */
void quic_pnspace_init(quic_pnspace *s);

/* Return the next packet number for `space` and advance that space's counter.
 * Each space is strictly monotonic and independent of the others. */
u64 quic_pnspace_next(quic_pnspace *s, quic_pns_space space);

#endif
