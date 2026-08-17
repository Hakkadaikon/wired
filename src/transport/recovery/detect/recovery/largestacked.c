#include "transport/recovery/detect/recovery/largestacked.h"

#include "common/bytes/util/num.h"

u64 largest_acked_update(u64 current, u64 new_largest) {
  return u64_max(current, new_largest);
}

int newly_acked(u64 prev_largest, u64 pn) { return pn > prev_largest ? 1 : 0; }
