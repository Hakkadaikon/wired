#ifndef RECOVERY_LARGESTACKED_H
#define RECOVERY_LARGESTACKED_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 A.7: tracking the largest acknowledged packet number. */

/* True iff pn is newly acked, i.e. above the previous largest acked. */
int newly_acked(u64 prev_largest, u64 pn);

#endif
