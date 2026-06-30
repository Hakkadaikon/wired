#ifndef QUIC_H3RUN_GOAWAY_H
#define QUIC_H3RUN_GOAWAY_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 5.2: successive GOAWAY ids MUST be non-increasing; an increase is
 * H3_ID_ERROR. */

typedef struct {
  u8  seen; /* a prior GOAWAY id was recorded */
  u64 last; /* the most recent (lowest accepted) GOAWAY id */
} quic_h3_goaway_state;

/* Validate a GOAWAY id. Returns 1 if it is the first or not greater than the
 * previous one (recording it), 0 on an increase (H3_ID_ERROR). */
int quic_h3_goaway_ok(quic_h3_goaway_state *state, u64 id);

#endif
