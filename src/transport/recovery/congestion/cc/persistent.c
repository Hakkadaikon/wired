#include "transport/recovery/congestion/cc/persistent.h"

int cc_persistent(u64 loss_period, u64 pto) { return loss_period > 3 * pto; }
