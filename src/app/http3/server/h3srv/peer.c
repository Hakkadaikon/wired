#include "app/http3/server/h3srv/peer.h"

#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3/stream_type.h"

/* The peer_qpack_* flag st owns for stream_type, or 0 if stream_type is not a
 * QPACK stream type. */
static u8* qpack_flag_for(wired_h3srv_state* st, u64 stream_type) {
  if (stream_type == H3_STREAM_QPACK_ENCODER) {
    return &st->peer_qpack_encoder;
  }
  if (stream_type == H3_STREAM_QPACK_DECODER) {
    return &st->peer_qpack_decoder;
  }
  return 0;
}

int wired_h3srv_on_peer_qpack(
    wired_h3srv_state* st, u64 stream_type, u16* err) {
  u8* flag = qpack_flag_for(st, stream_type);
  *err     = 0;
  if (!flag) {
    return 1;
  }
  if (*flag) {
    *err = H3_STREAM_CREATION_ERROR;
    return 0;
  }
  *flag = 1;
  return 1;
}

/* Accepted uni stream type classifiers, scanned until one matches. */
static int (*const accept_uni_checks[])(u64) = {
    h3_stream_type_is_control,
    h3_stream_type_is_qpack,
    h3_stream_type_is_webtransport,
};

/* RFC 9114 6.2 / RFC 9204 4.2 / draft-ietf-webtrans-http3-15 4.3 */
int wired_h3srv_accept_uni(u64 stream_type) {
  for (usz i = 0; i < sizeof(accept_uni_checks) / sizeof(*accept_uni_checks);
       i++) {
    if (accept_uni_checks[i](stream_type)) {
      return 1;
    }
  }
  return 0;
}
