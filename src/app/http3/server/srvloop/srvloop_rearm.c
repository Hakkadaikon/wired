#include "app/http3/server/srvloop/srvloop_impl.h"

void srvloop_step_one(const wired_srvloop_conn* conn, wired_mspan pkt) {
  wired_srvloop*         l = conn->l;
  wired_srvloop_recv_out ro;
  wired_srvloop_recv_in  ri = {
      pkt, srvloop_app_largest_pn(l), srvloop_hs_largest_pn(l)};
  if (wired_srvloop_recv(conn->s, &ri, &ro))
    srvloop_step_opened(conn, &ro, pkt);
}

/* RFC 9000 2.2: re-arm every slot that answered a request this step, so the
 * next request on that stream (curl reuses stream 0 across requests)
 * reassembles from a clean buffer rather than re-triggering the finished
 * one. Only a slot that saw FIN: an Extended CONNECT completes at its
 * HEADERS (RFC 9220 3) and its stream keeps carrying capsules -- re-arming
 * it would leave the old HEADERS in req_buf to complete (and dispatch) the
 * same request again, and restart the capsule bytes from zero. */
void srvloop_rearm_reqacc(wired_srvloop* l) {
  for (usz i = 0; i < l->done_n; i++) {
    wired_srvloop_stream_slot* slot = &l->streams[l->done_slots[i]];
    if (!slot->req_fin) continue;
    slot->req_len  = 0;
    slot->req_fin  = 0;
    slot->req_done = 0;
    slot->req_over = 0;
    srvloop_body_rearm(slot);
  }
}

/* Same re-arm as srvloop_rearm_reqacc, for slots that finished incomplete (RFC
 * 9114 4.1) instead of decoding a request -- kept separate so the caller (which
 * must abort the stream before this fires, srvrun's own layer) still finds
 * req_incomplete set through the step that discovers it. */
void srvloop_rearm_incomplete(wired_srvloop* l) {
  for (usz i = 0; i < l->incomplete_n; i++) {
    wired_srvloop_stream_slot* slot = &l->streams[l->incomplete_slots[i]];
    slot->req_len                   = 0;
    slot->req_fin                   = 0;
    slot->req_done                  = 0;
    slot->req_incomplete            = 0;
    srvloop_body_rearm(slot);
  }
}

/* Same re-arm as srvloop_rearm_incomplete, for slots that finished rejected
 * outright (RFC 9114 7.2.5/7.2.8, 9114-067/9114-073) instead of merely
 * incomplete -- also clears req.frame_unexpected (via the same *req = {0} that
 * clearing req_len/req_fin/req_done leaves implicit on this SDK's other rearms
 * is NOT enough here, since frame_unexpected lives in req itself, not the
 * slot). */
void srvloop_rearm_frame_unexpected(wired_srvloop* l) {
  for (usz i = 0; i < l->frame_unexpected_n; i++) {
    wired_srvloop_stream_slot* slot = &l->streams[l->frame_unexpected_slots[i]];
    slot->req_len                   = 0;
    slot->req_fin                   = 0;
    slot->req_done                  = 0;
    slot->req                       = (wired_h3reqdrive_req){0};
    srvloop_body_rearm(slot);
  }
}
