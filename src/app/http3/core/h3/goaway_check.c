#include "app/http3/core/h3/goaway_check.h"

int quic_h3_goaway_id_ok(u64 id, int from_server) {
  /* RFC 9114 5.2: server -> client-initiated bidi (id % 4 == 0); client -> any
   * Push ID. */
  return !from_server || id % 4 == 0;
}
