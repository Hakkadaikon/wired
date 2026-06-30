#include "app/http3/core/h3/shutdown.h"

/* RFC 9114 5.2 */
int quic_h3_shutdown_processes(u64 request_id, u64 goaway_limit) {
  return request_id < goaway_limit;
}

/* RFC 9114 5.2 */
int quic_h3_shutdown_id_monotone(u64 prev, u64 next) { return next <= prev; }
