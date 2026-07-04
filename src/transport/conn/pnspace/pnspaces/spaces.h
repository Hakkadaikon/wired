#ifndef QUIC_PNSPACES_SPACES_H
#define QUIC_PNSPACES_SPACES_H

#include "common/platform/sys/syscall.h"
#include "transport/conn/lifecycle/conn/pnspace.h"

/* RFC 9000 12.3: three independent packet number spaces, each numbering from
 * 0 and advancing without affecting the others. Thin wrapper over quic_pnspace
 * giving the pnspaces-facing send-side API. */

typedef struct {
  quic_pnspace pn;
} quic_pnspaces;

void quic_pnspaces_init(quic_pnspaces* s);

/* Next packet number for `space` (0=Initial, 1=Handshake, 2=Application);
 * returns the current value and advances that space only. */
u64 quic_pnspaces_next_pn(quic_pnspaces* s, int space);

#endif
