#include "transport/conn/lifecycle/closelife/idlefloor.h"

#include "common/bytes/util/num.h"

/* RFC 9000 10.1: effective idle timeout is at least 3*PTO. */
u64 quic_idle_floor(u64 idle_timeout, u64 pto) {
  return quic_u64_max(idle_timeout, 3 * pto);
}

/* RFC 9000 10.1: close once the effective idle period has elapsed. */
int quic_idle_should_close(u64 elapsed, u64 effective_idle) {
  return elapsed >= effective_idle;
}
