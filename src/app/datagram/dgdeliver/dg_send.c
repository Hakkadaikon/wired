#include "app/datagram/dgdeliver/dg_send.h"

#include "app/datagram/datagram/datagram.h"

int quic_dgdeliver_frame(
    const u8 *data,
    usz       len,
    int       with_length,
    u64       max_frame_size,
    u8       *out,
    usz       cap,
    usz      *out_len) {
  quic_datagram_frame f = {.length = (u64)len, .data = data};
  usz                 w = quic_datagram_encode(out, cap, &f, with_length);
  if (w == 0) return 0;
  if (!quic_datagram_allowed(max_frame_size, (u64)w)) return 0; /* RFC 9221 5 */
  *out_len = w;
  return 1;
}
