#ifndef PNSPACES_SPACES_H
#define PNSPACES_SPACES_H

#include "common/platform/sys/syscall.h"
#include "transport/conn/lifecycle/conn/pnspace.h"

/* RFC 9000 12.3: three independent packet number spaces, each numbering from
 * 0 and advancing without affecting the others. Thin wrapper over pnspace
 * giving the pnspaces-facing send-side API. */

/** Send-side wrapper over pnspace: the three independent packet
 * number spaces (RFC 9000 12.3). */
typedef struct {
  pnspace pn;
} pnspaces;

void pnspaces_init(pnspaces* s);

/* Next packet number for `space` (0=Initial, 1=Handshake, 2=Application);
 * returns the current value and advances that space only. */
u64 pnspaces_next_pn(pnspaces* s, int space);

/* RFC 9000 12.3: 1 once `space` has issued its highest legal packet number
 * (2^62-1); the caller must stop sending in it, silently (no
 * CONNECTION_CLOSE). */
int pnspaces_exhausted(const pnspaces* s, int space);

#endif
