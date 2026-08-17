#include "transport/stream/data/appdata/stream_send.h"

/* RFC 9000 19.8 */
int appdata_stream_frame(const stream_frame* f, wired_obuf* out) {
  usz n = frame_put_stream(out->p, out->cap, f);
  if (n == 0) return 0;
  out->len = n;
  return 1;
}
