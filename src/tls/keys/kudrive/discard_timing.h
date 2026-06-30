#ifndef QUIC_KUDRIVE_DISCARD_TIMING_H
#define QUIC_KUDRIVE_DISCARD_TIMING_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 6.5: after a key update completes the prior keys are retained for
 * three times the PTO; once that elapses they may be discarded. Returns 1 when
 * now is at or past update_completed_at + 3*PTO. */
int quic_kudrive_can_discard_old(u64 now, u64 update_completed_at, u64 pto);

/* RFC 9001 6.5: an endpoint that has recently updated keys MUST NOT initiate a
 * subsequent update until the prior one is acknowledged and its retention has
 * elapsed; a 3*PTO floor since the last update bounds the rate. Returns 1 when
 * a new update may be initiated, 0 while still within 3*PTO. */
int quic_kudrive_can_initiate_again(u64 now, u64 last_update_at, u64 pto);

#endif
