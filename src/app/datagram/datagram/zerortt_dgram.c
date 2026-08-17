#include "app/datagram/datagram/zerortt_dgram.h"

/* RFC 9221 3 */
int datagram_0rtt_ok(u64 remembered_max, u64 frame_size) {
  return remembered_max != 0 && frame_size <= remembered_max;
}

/* RFC 9221 3 */
int datagram_0rtt_accept_ok(u64 issued_max, u64 accept_max) {
  return accept_max >= issued_max;
}
