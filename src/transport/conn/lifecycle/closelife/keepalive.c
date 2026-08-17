#include "transport/conn/lifecycle/closelife/keepalive.h"

/* RFC 9000 10.1.2: send before the idle timeout; half the timeout leaves
 * margin for the packet to arrive. */
u64 keepalive_interval(u64 idle_timeout) { return idle_timeout / 2; }

int keepalive_due(u64 last_activity, u64 now, u64 idle_timeout) {
  return now - last_activity >= keepalive_interval(idle_timeout);
}
