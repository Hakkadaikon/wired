#include "app/moqt/run/moqtrun_impl.h"

static int  moqtrun_req_done_ok(u64 kind, u64 type);
static int  moqtrun_req_goaway_ok(const wired_moqtrun_req* q, u64 type);
static int  moqtrun_req_follow_ok(const wired_moqtrun_req* q, u64 type);
static void moqtrun_req_note(wired_moqtrun_req* q, u64 type, wired_span body);
static moqtrun_ctl_fn moqtrun_req_route(
    wired_moqtrun_req* q, u64 type, wired_span body);
static int  moqtrun_peek_known(int peek);
static void moqtrun_dispatch_going_away(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
static int            moqtrun_is_late(const wired_moqtrun_peer* p, u64 type);
static moqtrun_ctl_fn moqtrun_late_route(
    const wired_moqtrun_peer* p, u64 type, moqtrun_ctl_fn fn);
static int moqtrun_rid_counts(int peek, u64 type);
static int moqtrun_rid_of(int peek, u64 type, wired_span body, u64* rid);
static int moqtrun_rid_fresh(
    wired_moqtrun_peer* p, int peek, u64 type, wired_span body);
static void moqtrun_dispatch_bad_rid(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body);
static moqtrun_ctl_fn moqtrun_msg_route_known(
    wired_moqtrun_peer* p, int peek, u64 type, wired_span body);

/* ===================== request streams ===================== */

/* draft-ietf-moq-transport-19 3.3: the seven types a request stream may
 * begin with. */
static const u64 moqtrun_req_first[] = {
    MOQCTL_T_SUBSCRIBE,        MOQCTL_T_PUBLISH,
    MOQFETCH_T_FETCH,          MOQTSTAT_T_TRACK_STATUS,
    MOQNS_T_PUBLISH_NAMESPACE, MOQNS_T_SUBSCRIBE_NAMESPACE,
    MOQCTL_T_SUBSCRIBE_TRACKS,
};

int moqtrun_req_is_first(u64 type) {
  for (usz i = 0; i < MOQTRUN_REQ_FIRST_N; i++) {
    if (moqtrun_req_first[i] == type) {
      return 1;
    }
  }
  return 0;
}

/* draft 10.9: REQUEST_UPDATE follows any request but TRACK_STATUS. */
int moqtrun_req_update_ok(u64 kind, u64 type) {
  return type == MOQTSTAT_T_REQUEST_UPDATE && kind != MOQTSTAT_T_TRACK_STATUS;
}

/* draft 10.11/10.20 and draft-22 9.10: messages only a PUBLISH's sender
 * may follow its request with on its own stream. PUBLISH_STATE_NOTIFY
 * reaches here on a draft-22 session alone -- the other drafts' peek
 * already closed on it as an unknown type. */
int moqtrun_req_pub_follow(u64 type) {
  return type == MOQCTL_T_PUBLISH_DONE || type == MOQCTL_T_PUBLISH_SKIPPED ||
         type == MOQCTL_T_PUBLISH_STATE_NOTIFY;
}

static int moqtrun_req_done_ok(u64 kind, u64 type) {
  return kind == MOQCTL_T_PUBLISH && moqtrun_req_pub_follow(type);
}

/* draft 10.4: GOAWAY may appear on a request stream, but only once. */
static int moqtrun_req_goaway_ok(const wired_moqtrun_req* q, u64 type) {
  return type == MOQCTL_T_GOAWAY && !q->goaway;
}

/* What the requester may send after its request. */
static int moqtrun_req_follow_ok(const wired_moqtrun_req* q, u64 type) {
  return moqtrun_req_goaway_ok(q, type) ||
         moqtrun_req_update_ok(q->kind, type) ||
         moqtrun_req_done_ok(q->kind, type);
}

/* kind 0: nothing read yet, so type must open the stream. */
int moqtrun_req_allowed(const wired_moqtrun_req* q, u64 type) {
  if (!q->kind) {
    return moqtrun_req_is_first(type);
  }
  return moqtrun_req_follow_ok(q, type);
}

/* Records the request q carries: its type and Request ID (the first field
 * of every request message, draft 10.1), and whether GOAWAY was seen. */
static void moqtrun_req_note(wired_moqtrun_req* q, u64 type, wired_span body) {
  usz off = 0;
  q->goaway |= type == MOQCTL_T_GOAWAY;
  if (q->kind) {
    return;
  }
  q->kind = type;
  moqvi_take(body, &off, &q->request_id);
}

/* A request-stream message out of place (draft 3.3: a bidi stream begins
 * with a request; draft 10: a "First" type only first, and every later
 * message must belong to that request) closes the session with
 * PROTOCOL_VIOLATION; the rest goes to the shared handlers. */
static moqtrun_ctl_fn moqtrun_req_route(
    wired_moqtrun_req* q, u64 type, wired_span body) {
  if (!moqtrun_req_allowed(q, type)) {
    return moqtrun_dispatch_close;
  }
  moqtrun_req_note(q, type, body);
  return moqtrun_ctl_lookup(type);
}

static int moqtrun_peek_known(int peek) {
  return peek == MOQCTL_OK || peek == MOQCTL_KNOWN_UNIMPLEMENTED;
}

/* draft-ietf-moq-transport-19 10.4: after the hub sent GOAWAY on this
 * session, a new request is refused GOING_AWAY. */
static void moqtrun_dispatch_going_away(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)hub;
  (void)peer_idx;
  (void)body;
  moqtrun_send_request_error(p, MOQCTL_ERR_GOING_AWAY);
}

static int moqtrun_is_late(const wired_moqtrun_peer* p, u64 type) {
  return p->sess.goaway_sent && moqtrun_req_is_first(type);
}

/* fn, unless the message is a request arriving late (a closing route
 * still wins). */
static moqtrun_ctl_fn moqtrun_late_route(
    const wired_moqtrun_peer* p, u64 type, moqtrun_ctl_fn fn) {
  if (fn != moqtrun_dispatch_close && moqtrun_is_late(p, type)) {
    return moqtrun_dispatch_going_away;
  }
  return fn;
}

/* A request message (a First type or REQUEST_UPDATE, draft 10.1) starts
 * with the Request ID it consumes. */
static int moqtrun_rid_counts(int peek, u64 type) {
  return moqtrun_peek_known(peek) &&
         (moqtrun_req_is_first(type) || type == MOQTSTAT_T_REQUEST_UPDATE);
}

/* 1 when a request message's body yields its Request ID into *rid. */
static int moqtrun_rid_of(int peek, u64 type, wired_span body, u64* rid) {
  usz off = 0;
  return moqtrun_rid_counts(peek, type) && moqvi_take(body, &off, rid);
}

/* Checks a request message's Request ID against the sender's (the client
 * sends even IDs, draft-19 10.1) and the IDs already used; 0 when it is
 * wrong-parity or a repeat (INVALID_REQUEST_ID). Otherwise 1, with
 * p->peer_rid_next kept past every Request ID p has sent (draft-18 SS10.4
 * GOAWAY Request ID). A message whose ID does not decode passes: its
 * handler closes it. */
static int moqtrun_rid_fresh(
    wired_moqtrun_peer* p, int peek, u64 type, wired_span body) {
  u64 rid  = 0;
  u64 next = ~(u64)0; /* rid + 2 saturates: u64_add_ok keeps it on overflow */
  if (!moqtrun_rid_of(peek, type, body, &rid)) {
    return 1;
  }
  if (moqtrun_rid_bad(p, rid)) {
    return 0;
  }
  u64_add_ok(rid, 2, &next);
  p->peer_rid_next = u64_max(p->peer_rid_next, next);
  return 1;
}

/* draft-19 10.1: a wrong-parity or reused Request ID closes the session
 * INVALID_REQUEST_ID (moqsess EV_BAD_REQUEST_ID). */
static void moqtrun_dispatch_bad_rid(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  (void)peer_idx;
  (void)body;
  moqtrun_sess_fault(hub, p, MOQSESS_EV_BAD_REQUEST_ID);
}

/* fn, or the INVALID_REQUEST_ID close when body's Request ID is bad. */
moqtrun_ctl_fn moqtrun_rid_gate(
    wired_moqtrun_peer* p,
    int                 peek,
    u64                 type,
    wired_span          body,
    moqtrun_ctl_fn      fn) {
  return moqtrun_rid_fresh(p, peek, type, body) ? fn : moqtrun_dispatch_bad_rid;
}

static moqtrun_ctl_fn moqtrun_msg_route_known(
    wired_moqtrun_peer* p, int peek, u64 type, wired_span body) {
  if (p->req && moqtrun_peek_known(peek)) {
    return moqtrun_late_route(p, type, moqtrun_req_route(p->req, type, body));
  }
  return moqtrun_late_route(p, type, moqtrun_ctl_route(peek, type));
}

moqtrun_ctl_fn moqtrun_msg_route(
    wired_moqtrun_peer* p, int peek, u64 type, wired_span body) {
  peek = moqctl_type_ver(p->ver, peek, &type);
  if (!moqtrun_rid_fresh(p, peek, type, body)) {
    return moqtrun_dispatch_bad_rid;
  }
  return moqtrun_msg_route_known(p, peek, type, body);
}

/* ===================== control-stream reassembly ===================== */

void moqtrun_span_drop(wired_span* s, usz d) {
  if (d == 0) {
    return; /* s->p may be null: no arithmetic on it (C11 6.5.6) */
  }
  s->p += d;
  s->n -= d;
}
