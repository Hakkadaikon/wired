#ifndef RECOVERY_LARGESTACKED_H
#define RECOVERY_LARGESTACKED_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 A.7: tracking the largest acknowledged packet number. */

/* Largest acked never regresses: max of current and the ACK frame's largest. */
u64 largest_acked_update(u64 current, u64 new_largest);

/* True iff pn is newly acked, i.e. above the previous largest acked. */
int newly_acked(u64 prev_largest, u64 pn);

#endif
