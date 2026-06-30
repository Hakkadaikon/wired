#include "transport/conn/lifecycle/closelife/draining.h"

/* RFC 9000 10.2.2 */
u64 quic_draining_period(u64 pto) { return 3 * pto; }

int quic_draining_done(u64 close_time, u64 now, u64 pto) {
  return now >= close_time + quic_draining_period(pto);
}

int quic_draining_may_send(int in_draining) { return !in_draining; }
