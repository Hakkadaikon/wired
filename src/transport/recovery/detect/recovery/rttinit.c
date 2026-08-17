#include "transport/recovery/detect/recovery/rttinit.h"

/* RFC 9002 5.2: the first sample seeds the estimator directly. */
int rtt_is_first(int have_sample) { return !have_sample; }

u64 rtt_first_srtt(u64 latest_rtt) { return latest_rtt; }

u64 rtt_first_rttvar(u64 latest_rtt) { return latest_rtt / 2; }
