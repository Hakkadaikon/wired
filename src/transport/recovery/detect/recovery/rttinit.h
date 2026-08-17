#ifndef RECOVERY_RTTINIT_H
#define RECOVERY_RTTINIT_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 5.2: seeding the estimator from the first RTT sample. */

int rtt_is_first(int have_sample);
u64 rtt_first_srtt(u64 latest_rtt);
u64 rtt_first_rttvar(u64 latest_rtt);

#endif
