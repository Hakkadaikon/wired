#include "app/http3/server/srvloop/srvloop_impl.h"

/* An empty receive window at stream offset 0. */
void srvloop_body_reset(wired_srvloop_stream_slot* slot) {
  bytes_memset(&slot->body, 0, sizeof slot->body);
}

/* A re-armed slot starts its window over -- unless its body streamed: base
 * then stays past the delivered bytes, so a late retransmission of them is
 * stale and never reaches the app twice. */
void srvloop_body_rearm(wired_srvloop_stream_slot* slot) {
  if (!slot->body.on) srvloop_body_reset(slot);
}

/* Mark every stream reassembly slot free and its accumulator clean (RFC 9000
 * 2.2) — mirrors the old flat req_len/req_fin/req_done reset in
 * wired_srvloop_init, now done for every slot rather than one fixed field
 * set, so a slot used without going through srvloop_stream_slot_claim (a direct
 * wired_srvloop_dispatch call, as the tests do) still starts from zero. */
void srvloop_streams_reset(wired_srvloop* l) {
  bytes_memset(&l->req_closed, 0, sizeof l->req_closed);
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_STREAMS; i++) {
    l->streams[i].in_use         = 0;
    l->streams[i].stream_id      = 0;
    l->streams[i].req_len        = 0;
    l->streams[i].req_fin        = 0;
    l->streams[i].req_done       = 0;
    l->streams[i].req_incomplete = 0;
    l->streams[i].qpack_settled  = 0;
    srvloop_body_reset(&l->streams[i]);
    h3_priority_init(&l->streams[i].priority);
  }
}
