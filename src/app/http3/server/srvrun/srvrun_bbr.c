#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_wtsend_arm_fin_only(const srvrun_conn* c, srvrun_wtsend* w);
static int  srvrun_bbr_has_bw(const srvrun_conn* c);
static u64  srvrun_est_bpms(const srvrun_conn* c);

int wired_server_wt_stream_send(
    wired_wt_session* s, u64 stream_id, wired_span payload, int fin) {
  srvrun_conn*   c    = srvrun_session_conn(s);
  int            sidx = srvrun_wt_session_slot_or_absent(c, s);
  srvrun_wtsend* w;
  if (!srvrun_wt_reply_flow_ok(sidx, s, payload.n))
    return srvrun_wtsend_flow_refuse(c);
  w = srvrun_wtsend_owned(c, sidx, stream_id);
  if (!srvrun_wtsend_accept_round(c, w, payload, fin)) {
    c->stat_wtsend_busy += (u64)srvrun_wtsend_busy_reject(w, payload.n);
    return -1;
  }
  c->stat_wtsend_ok++;
  wired_wt_session_note_data_sent(s, payload.n);
  return 1;
}

/* Arms w's sess for a bare-FIN round: no bytes, but wired_sendsess_arm is
 * still the only place that sets sess.active -- without it,
 * wired_sendsess_done keeps reading active=0 as "not done" forever (its own
 * early return), so the slot would never reap even after the bare-FIN
 * slice is ACKed. Mirrors srvrun_wtsend_append_round's arm+set_base_offset
 * pair, just with a NULL/0 payload. */
static void srvrun_wtsend_arm_fin_only(const srvrun_conn* c, srvrun_wtsend* w) {
  wired_sendsess_arm(&w->sess, 0, 0, srvrun_mps(c));
  wired_sendsess_set_base_offset(&w->sess, w->stream_off);
}

void srvrun_wtsend_start_fin_now(const srvrun_conn* c, srvrun_wtsend* w) {
  srvrun_wtsend_arm_fin_only(c, w);
  w->fin_only_pending = 1;
}

/* Arms the bare-FIN round right away if w's previous round has already
 * finished (wired_sendsess_done), else defers it: fin_requested is
 * promoted to fin_only_pending by srvrun_pump_one_wt the moment that round
 * finishes, so a FIN requested while a data round is still in flight (the
 * common case -- a WebTransport writer's close() often follows its last
 * write() before that write's round has even been ACKed) is deferred, not
 * dropped. */
void srvrun_wtsend_request_fin(const srvrun_conn* c, srvrun_wtsend* w) {
  if (wired_sendsess_done(&w->sess))
    srvrun_wtsend_start_fin_now(c, w);
  else
    w->fin_requested = 1;
}

/* draft-ietf-webtrans-http3-16 SS6: the peer ended session slot sidx (its
 * WT_CLOSE_SESSION, or its FIN on the CONNECT stream, which equals a close
 * with code 0) -- "the recipient MUST either close or reset the stream in
 * response", so this server closes its own side with a FIN at the
 * stream's current end (wt_connect_sent_len, behind any capsule still in
 * flight: srvrun_wtsend_request_fin defers it until that round is done).
 * A client that waits for the stream to end (transport.closed) settles on
 * it. A CONNECT stream this server already FINs (its own WT_CLOSE_SESSION
 * round) gets nothing more. */
void srvrun_wt_connect_fin(srvrun_conn* c, int sidx) {
  srvrun_wtsend* w = srvrun_wt_connect_sender(c, sidx);
  if (srvrun_wt_connect_finable(w)) srvrun_wtsend_request_fin(c, w);
}

int wired_server_wt_stream_fin(wired_wt_session* s, u64 stream_id) {
  srvrun_conn*   c    = srvrun_session_conn(s);
  int            sidx = srvrun_wt_session_slot_or_absent(c, s);
  srvrun_wtsend* w;
  if (sidx < 0) return -1;
  w = srvrun_wtsend_owned(c, sidx, stream_id);
  if (!srvrun_wtsend_open_slot(w)) return -1;
  srvrun_wtsend_request_fin(c, w);
  return 1;
}

/* s's own in-use WT send slot on stream_id, 0 when s resolves to no live
 * connection or s owns no send slot on the id. */
srvrun_wtsend* srvrun_wtsend_of(wired_wt_session* s, u64 stream_id) {
  srvrun_conn* c = srvrun_session_conn(s);
  return c ? srvrun_wtsend_owned(
                 c, srvrun_wt_session_slot_or_absent(c, s), stream_id)
           : 0;
}

static int srvrun_bbr_has_bw(const srvrun_conn* c) {
  return c->cc.algo == CC_ALGO_BBR && c->cc.bbr.btl_bw;
}

/* Delivery rate in B/ms: BBR's btl_bw once sampled, else cwnd / srtt (0
 * before the first RTT sample). */
static u64 srvrun_est_bpms(const srvrun_conn* c) {
  if (srvrun_bbr_has_bw(c)) return c->cc.bbr.btl_bw;
  return c->srtt_ms ? c->cc.cwnd / c->srtt_ms : 0;
}

u64 wired_server_wt_est_kbps(wired_wt_session* s) {
  srvrun_conn* c = srvrun_session_conn(s);
  return c ? srvrun_est_bpms(c) * 8 : 0; /* 1 B/ms = 8 kbps */
}

int wired_server_wt_stream_priority(
    wired_wt_session* s, u64 stream_id, u8 urgency) {
  srvrun_wtsend* w;
  if (urgency > H3_URGENCY_MAX) return -1;
  w = srvrun_wtsend_of(s, stream_id);
  if (!w) return -1;
  w->urgency1 = (u8)(urgency + 1);
  return 1;
}

int wired_server_wt_stream_schedule(
    wired_wt_session* s, u64 stream_id, const wired_wt_sched* k) {
  srvrun_wtsend* w;
  if (wired_server_wt_stream_priority(s, stream_id, k->urgency) < 0) return -1;
  w        = srvrun_wtsend_of(s, stream_id);
  w->fine  = k->fine;
  w->flow  = k->flow;
  w->order = k->order;
  w->tie   = k->tie;
  return 1;
}
