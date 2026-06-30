#include "app/datagram/datagram/dgcheck.h"

int quic_datagram_recv_ok(
    u64 advertised_max, int we_advertised, u64 frame_size) {
  if (!we_advertised) return 0;        /* RFC 9221 3 */
  return frame_size <= advertised_max; /* RFC 9221 3 */
}
