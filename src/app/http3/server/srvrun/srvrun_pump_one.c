#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_pump_one_wt_slice(
    const srvrun_step_ctx* ctx, srvrun_conn* c, srvrun_wtsend* w);
static int srvrun_wtsend_has_work(const srvrun_wtsend* w);
static int srvrun_wtsend_ready(const srvrun_conn* c, const srvrun_wtsend* w);
static u32 srvrun_wtsend_ready_key(
    const srvrun_conn* c, const srvrun_wtsend* w);
static int srvrun_wt_same_flow_class(
    const srvrun_wtsend* v, const srvrun_wtsend* w);
static int srvrun_wt_ranks_before(
    const srvrun_wtsend* v, const srvrun_wtsend* w);
static int srvrun_wt_goes_before(
    const srvrun_conn* c, const srvrun_wtsend* v, const srvrun_wtsend* w);
static int srvrun_wt_flow_beaten(const srvrun_conn* c, const srvrun_wtsend* w);

/* Send one slice from WT send slot w under the same gates -- or, once its
 * own sess has nothing left to give (wired_sendsess_take), a bare-FIN
 * round if one is pending (promoting a deferred request first). */
static int srvrun_pump_one_wt_slice(
    const srvrun_step_ctx* ctx, srvrun_conn* c, srvrun_wtsend* w) {
  wired_sendq_slice sl;
  srvrun_wtsend_promote_fin_if_ready(c, w);
  if (!srvrun_pump_gate_ok(c, &w->sess, w->stream_credit)) {
    srvrun_notify_conn_blocked(ctx, c);
    srvrun_notify_stream_blocked(
        ctx, c, w->stream_id, &w->sess, w->stream_credit, &w->sdb);
    return 0;
  }
  if (wired_sendsess_take(&w->sess, &sl)) {
    return srvrun_send_taken(
        ctx, c, &w->sess, w->stream_id, &sl, srvrun_wt_slice_fin(w, &sl));
  }
  return srvrun_pump_wt_fin_only(ctx, c, w);
}

/* srvrun_pump_one's cached-total delta wrapper, WT-slot flavor. */
int srvrun_pump_one_wt(
    const srvrun_step_ctx* ctx, srvrun_conn* c, srvrun_wtsend* w) {
  /* Same as srvrun_pump_one: a released slot never sends again -- for a
   * view round its bytes are the app's buffer, free once inflight is 0. */
  if (!w->in_use) {
    return 0;
  }
  usz inf0 = wired_sendsess_inflight_bytes(&w->sess);
  usz con0 = srvrun_sess_consumed(&w->sess);
  int sent = srvrun_pump_one_wt_slice(ctx, c, w);
  usz inf1 = wired_sendsess_inflight_bytes(&w->sess);
  c->acct_inflight += inf1 - inf0;
  c->acct_consumed += srvrun_sess_consumed(&w->sess) - con0;
  if (sent) {
    srvrun_pace_charge(c, inf1 - inf0);
  }
  return sent;
}

/* w's RFC 9218 2.1 urgency: the app's wired_server_wt_stream_priority
 * value, or the default when never set. */
u8 srvrun_wtsend_urgency(const srvrun_wtsend* w) {
  return w->urgency1 ? (u8)(w->urgency1 - 1) : H3_URGENCY_DEFAULT;
}

/* w has something to put on the wire: a retransmit, unsent bytes, or a
 * pending bare FIN. */
static int srvrun_wtsend_has_work(const srvrun_wtsend* w) {
  return srvrun_has_requeued(&w->sess) || w->sess.q.cur < w->sess.q.len ||
         w->fin_only_pending;
}

/* w could send a slice right now. */
static int srvrun_wtsend_ready(const srvrun_conn* c, const srvrun_wtsend* w) {
  return w->in_use && srvrun_wtsend_has_work(w) &&
         srvrun_pump_gate_ok(c, &w->sess, w->stream_credit);
}

/* w's class key: (urgency, fine) packed so lexicographic order is plain
 * integer order. */
u32 srvrun_wtsend_key(const srvrun_wtsend* w) {
  return (u32)srvrun_wtsend_urgency(w) << 16 | w->fine;
}

/* w's class key when it could send a slice right now, else the idle
 * sentinel -- a stream blocked by its own flow-control credit must not
 * hold back less urgent ones (RFC 9218 10: unused capacity goes to the
 * next class). */
static u32 srvrun_wtsend_ready_key(
    const srvrun_conn* c, const srvrun_wtsend* w) {
  return srvrun_wtsend_ready(c, w) ? srvrun_wtsend_key(w) : SRVRUN_WT_KEY_IDLE;
}

/* The best class among the slots that can send this pass, the idle
 * sentinel when none can (every slot is then visited, as before classes
 * existed, so the blocked-path signals still fire). One O(slots) pass, no
 * sort. */
u32 srvrun_wt_pass_key(const srvrun_conn* c) {
  u32 m = SRVRUN_WT_KEY_IDLE;
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++) {
    u32 k = srvrun_wtsend_ready_key(c, &c->wtsend[i]);
    if (k < m) {
      m = k;
    }
  }
  return m;
}

/* v and w share a flow and a class. */
static int srvrun_wt_same_flow_class(
    const srvrun_wtsend* v, const srvrun_wtsend* w) {
  return v->flow == w->flow && srvrun_wtsend_key(v) == srvrun_wtsend_key(w);
}

/* v's (order, tie) is lexicographically below w's. */
static int srvrun_wt_ranks_before(
    const srvrun_wtsend* v, const srvrun_wtsend* w) {
  return v->order < w->order || (v->order == w->order && v->tie < w->tie);
}

/* v, ready, goes before w inside their flow and class. */
static int srvrun_wt_goes_before(
    const srvrun_conn* c, const srvrun_wtsend* v, const srvrun_wtsend* w) {
  return srvrun_wt_same_flow_class(v, w) && srvrun_wt_ranks_before(v, w) &&
         srvrun_wtsend_ready(c, v);
}

/* Some ready slot of w's flow and class ranks before w
 * (draft-ietf-moq-transport-22 7.2 rules 3-4: group order, then fill
 * before subscription, then Subgroup ID). */
static int srvrun_wt_flow_beaten(const srvrun_conn* c, const srvrun_wtsend* w) {
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++) {
    if (srvrun_wt_goes_before(c, &c->wtsend[i], w)) {
      return 1;
    }
  }
  return 0;
}

/* w may send this pass as far as its flow goes: flow 0 (control, request
 * and plain streams) is never ordered against anything. */
int srvrun_wt_flow_ok(const srvrun_conn* c, const srvrun_wtsend* w) {
  return !w->flow || !srvrun_wt_flow_beaten(c, w);
}
