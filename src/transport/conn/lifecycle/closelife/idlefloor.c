#include "transport/conn/lifecycle/closelife/idlefloor.h"

#include "common/bytes/util/num.h"

/* RFC 9000 10.1: effective idle timeout is at least 3*PTO. */
u64 idle_floor(u64 idle_timeout, u64 pto) {
  return u64_max(idle_timeout, 3 * pto);
}
