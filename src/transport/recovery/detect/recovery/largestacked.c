#include "transport/recovery/detect/recovery/largestacked.h"

int newly_acked(u64 prev_largest, u64 pn) { return pn > prev_largest ? 1 : 0; }
