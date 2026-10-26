#include "app/http3/server/srvloop/srvloop_impl.h"

static int srvloop_id_past_limit(const wired_srvloop* l, u64 id);
static int srvloop_frame_past_limit(
    const wired_srvloop* l, const framewalk_item* fr);
static int srvloop_past_stream_limit(const wired_srvloop* l, wired_span pl);

/* RFC 9000 3.2 / 19: the frame kinds that name a stream (and so open it). */
static const u8 SRVLOOP_NAMES_STREAM[FK_RESET_STREAM_AT + 1] = {
    [FK_RESET_STREAM]        = 1,
    [FK_STOP_SENDING]        = 1,
    [FK_STREAM]              = 1,
    [FK_MAX_STREAM_DATA]     = 1,
    [FK_STREAM_DATA_BLOCKED] = 1,
    [FK_RESET_STREAM_AT]     = 1,
};

/* RFC 9000 4.6: 1 if id is a client stream at or past l's advertised limit
 * for its type (bidi or uni). */
static int srvloop_id_past_limit(const wired_srvloop* l, u64 id) {
  u64 lim = l->peer_stream_limit[(id >> 1) & 1];
  return !(id & 1) && lim && id / 4 >= lim;
}

/* 1 if the walked frame names a stream past its limit; the stream id is the
 * varint right after the frame type in every stream-naming frame. */
static int srvloop_frame_past_limit(
    const wired_srvloop* l, const framewalk_item* fr) {
  u64 id;
  usz t = varint_decode(fr->start, fr->remaining, &id);
  if (!SRVLOOP_NAMES_STREAM[frame_classify(fr->type)]) {
    return 0;
  }
  return varint_decode(fr->start + t, fr->remaining - t, &id) &&
         srvloop_id_past_limit(l, id);
}

/* RFC 9000 4.6: "An endpoint that receives a frame with a stream ID
 * exceeding the limit it has sent MUST treat this as a connection error of
 * type STREAM_LIMIT_ERROR". */
static int srvloop_past_stream_limit(const wired_srvloop* l, wired_span pl) {
  framewalk      it;
  framewalk_item fr;
  framewalk_init(&it, pl.p, pl.n);
  while (framewalk_next(&it, &fr)) {
    if (srvloop_frame_past_limit(l, &fr)) {
      return 1;
    }
  }
  return 0;
}

/* Dispatch this opened payload. Request STREAM frames are routed per frame
 * to their own stream's slot inside wired_srvloop_dispatch (ctx->l != 0
 * selects the routed path); a slot whose request completes is appended to
 * l->done_slots and mirrored into l->req/req_stream_id there. The in
 * scratch/wrap/req fields are unused on the routed path (each completion
 * uses its own slot's buffers), passed empty. */
void srvloop_step_dispatch(const wired_srvloop_conn* conn, wired_span payload) {
  wired_srvloop*            l   = conn->l;
  int                       got = 0;
  wired_srvloop_dispatch_in in  = {
      payload, wired_mspan_of(0, 0), wired_mspan_of(0, 0), &got, &l->req};
  wired_srvloop_dispatch_ctx ctx = {conn->s, &l->h3, 0, l};
  if (srvloop_past_stream_limit(l, payload)) {
    l->wt_refused_overflow = 1;
    return;
  }
  wired_srvloop_dispatch(&ctx, &in);
}

/* This opened slice's level determines which pn space (App/Handshake) owns
 * its ack-eliciting bookkeeping (RFC 9000 12.3); Initial is out of this
 * loop's scope (srvboot's own layer). Split out of srvloop_step_one to keep its
 * own branch count at the CCN gate. */
void srvloop_step_note_ack_owed(
    wired_srvloop* l, wired_span payload, int level) {
  if (level == LEVEL_ONERTT) {
    srvloop_note_ack_owed(
        &l->ack_recv, PNS_APP, &l->app_ack_policy, payload, l->app_rx_pn,
        l->now_ms, srvloop_app_ack_urgent(l));
  }
  if (level == LEVEL_HANDSHAKE) {
    srvloop_note_ack_owed(
        &l->ack_recv, PNS_HANDSHAKE, &l->ackst.hs_ack_policy, payload,
        l->hs_rx_pn, l->now_ms, 0);
  }
}

/* RFC 9000 13.2.1: the 1-RTT packet just numbered is below an ack-eliciting
 * packet already received (recorded before this one). */
static int srvloop_app_reordered(const wired_srvloop* l) {
  const recvpn* r = &l->ack_recv.r[PNS_APP];
  return r->any && l->app_rx_pn < r->largest;
}

/* RFC 9000 13.2.1: acknowledge the 1-RTT packet just numbered without delay
 * -- it arrived out of order or after a gap, or its datagram was ECN-CE. */
int srvloop_app_ack_urgent(const wired_srvloop* l) {
  return l->ackst.rx_gap || l->ackst.rx_ce || srvloop_app_reordered(l);
}

/* RFC 9001 5 / 5.1: open one coalesced packet slice and walk its frames. A
 * STREAM frame sets *got_request; CRYPTO is fed to the handshake. A slice that
 * fails to open (wrong level/key) is silently skipped, as the next slice in the
 * datagram may still be ours (RFC 9000 12.2). */
/* RFC 9000 12.3: the just-recorded pn of this level was already received
 * (an ack-eliciting packet seen before, or one older than the receive
 * window, which is treated as received). */
int srvloop_step_dup(const wired_srvloop* l, int level) {
  if (level == LEVEL_ONERTT) {
    return recvpn_seen(&l->ack_recv.r[PNS_APP], l->app_rx_pn);
  }
  return level == LEVEL_HANDSHAKE &&
         recvpn_seen(&l->ack_recv.r[PNS_HANDSHAKE], l->hs_rx_pn);
}
