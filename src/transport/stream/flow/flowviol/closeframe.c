#include "transport/stream/flow/flowviol/closeframe.h"

#include "transport/packet/frame/frame/frame.h"

/* RFC 9000 19.19 */
int quic_flowviol_close_frame(const quic_flowviol_err* e, quic_obuf* out) {
  quic_conn_close_frame f;
  usz                   n;
  f.is_app     = 0;
  f.error_code = e->error_code;
  f.frame_type = e->frame_type;
  f.reason_len = (u64)e->reason.n;
  f.reason     = e->reason.p;
  n            = quic_frame_put_conn_close(out->p, out->cap, &f);
  if (n == 0) return 0;
  out->len = n;
  return 1;
}
