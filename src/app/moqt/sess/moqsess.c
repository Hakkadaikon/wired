#include "app/moqt/sess/moqsess.h"

/* draft-ietf-moq-transport-19 3.3 / 5.1 -- see moqsess.h for the state/
 * event catalog. Each event has its own tiny handler (CCN<=3 per handler);
 * moqsess_step dispatches by event index through a function table. */

void moqsess_init(moqsess* s) {
  moqsess zero = {0};
  *s           = zero;
}

static int moqsess_closed(moqsess* s, int reason) {
  s->state        = QUIC_MOQSESS_CLOSED;
  s->close_reason = reason;
  return reason;
}

/* Advance the SETUP half-handshake: IDLE -> SETUP_HALF -> ESTABLISHED.
 * Either "own sent" or "peer recv'd" arriving first takes the same path;
 * the second occurrence of either establishes. */
static int moqsess_setup_progress(moqsess* s) {
  if (s->state == QUIC_MOQSESS_IDLE) {
    s->state = QUIC_MOQSESS_SETUP_HALF;
    return QUIC_MOQSESS_CLOSE_NONE;
  }
  if (s->state == QUIC_MOQSESS_SETUP_HALF) s->state = QUIC_MOQSESS_ESTABLISHED;
  return QUIC_MOQSESS_CLOSE_NONE;
}

static int moqsess_on_sent_setup(moqsess* s) {
  return moqsess_setup_progress(s);
}

static int moqsess_on_recv_setup(moqsess* s) {
  return moqsess_setup_progress(s);
}

static int moqsess_on_ctrl_closed(moqsess* s) {
  return moqsess_closed(s, QUIC_MOQSESS_CLOSE_PROTOCOL_VIOLATION);
}

static int moqsess_on_unknown_uni(moqsess* s) {
  return moqsess_closed(s, QUIC_MOQSESS_CLOSE_PROTOCOL_VIOLATION);
}

static int moqsess_on_second_ctrl(moqsess* s) {
  return moqsess_closed(s, QUIC_MOQSESS_CLOSE_PROTOCOL_VIOLATION);
}

static int moqsess_on_malformed_ctrl(moqsess* s) {
  return moqsess_closed(s, QUIC_MOQSESS_CLOSE_PROTOCOL_VIOLATION);
}

static int moqsess_on_send_goaway(moqsess* s) {
  s->goaway_sent = 1;
  return QUIC_MOQSESS_CLOSE_NONE;
}

/* A 2nd GOAWAY on the same control stream is a protocol violation; the
 * first is recorded and leaves the session open. */
static int moqsess_on_recv_goaway(moqsess* s) {
  if (s->goaway_recv)
    return moqsess_closed(s, QUIC_MOQSESS_CLOSE_PROTOCOL_VIOLATION);
  s->goaway_recv = 1;
  return QUIC_MOQSESS_CLOSE_NONE;
}

static int moqsess_on_recv_goaway_bad_uri(moqsess* s) {
  return moqsess_closed(s, QUIC_MOQSESS_CLOSE_PROTOCOL_VIOLATION);
}

static int moqsess_on_goaway_timeout(moqsess* s) {
  return moqsess_closed(s, QUIC_MOQSESS_CLOSE_GOAWAY_TIMEOUT);
}

static int moqsess_on_bad_first(moqsess* s) {
  return moqsess_closed(s, QUIC_MOQSESS_CLOSE_PROTOCOL_VIOLATION);
}

static int moqsess_on_bad_request_id(moqsess* s) {
  return moqsess_closed(s, QUIC_MOQSESS_CLOSE_INVALID_REQUEST_ID);
}

typedef int (*moqsess_handler)(moqsess* s);

static const moqsess_handler MOQSESS_HANDLERS[] = {
    moqsess_on_sent_setup,          /* EV_SENT_SETUP */
    moqsess_on_recv_setup,          /* EV_RECV_SETUP */
    moqsess_on_ctrl_closed,         /* EV_CTRL_CLOSED */
    moqsess_on_unknown_uni,         /* EV_UNKNOWN_UNI */
    moqsess_on_second_ctrl,         /* EV_SECOND_CTRL */
    moqsess_on_malformed_ctrl,      /* EV_MALFORMED_CTRL */
    moqsess_on_send_goaway,         /* EV_SEND_GOAWAY */
    moqsess_on_recv_goaway,         /* EV_RECV_GOAWAY */
    moqsess_on_recv_goaway_bad_uri, /* EV_RECV_GOAWAY_BAD_URI */
    moqsess_on_goaway_timeout,      /* EV_GOAWAY_TIMEOUT */
    moqsess_on_bad_first,           /* EV_BAD_FIRST */
    moqsess_on_bad_request_id,      /* EV_BAD_REQUEST_ID */
};

#define MOQSESS_HANDLERS_N \
  (sizeof(MOQSESS_HANDLERS) / sizeof(MOQSESS_HANDLERS[0]))

int moqsess_step(moqsess* s, moqsess_event ev) {
  usz idx = (usz)ev;
  if (s->state == QUIC_MOQSESS_CLOSED) return s->close_reason;
  if (idx >= MOQSESS_HANDLERS_N) return QUIC_MOQSESS_CLOSE_NONE;
  return MOQSESS_HANDLERS[idx](s);
}

int moqsess_should_buffer(const moqsess* s) {
  return s->state != QUIC_MOQSESS_ESTABLISHED &&
         s->state != QUIC_MOQSESS_CLOSED;
}

int moqsess_established(const moqsess* s) {
  return s->state == QUIC_MOQSESS_ESTABLISHED;
}

int moqsess_may_reject_request(const moqsess* s) {
  return s->goaway_sent || s->goaway_recv;
}

int moqsess_suppress_own_requests(const moqsess* s) { return s->goaway_recv; }

/* ===================== B. Subscribe lifecycle ===================== */

void moqsub_init(moqsub* s, moqsub_role role) {
  moqsub zero = {0};
  zero.role   = role;
  *s          = zero;
}

static int moqsess_sub_terminate(moqsub* s, int reason) {
  s->state       = QUIC_MOQSUB_TERMINATED;
  s->term_reason = reason;
  return 1;
}

/* SUBSCRIBE/PUBLISH opens the request: Idle -> Pending. Anything else is a
 * caller misuse (ignored: no legal re-open of an active subscription). */
static int moqsess_sub_on_open(moqsub* s) {
  if (s->state != QUIC_MOQSUB_IDLE) return 0;
  s->state = QUIC_MOQSUB_PENDING;
  return 1;
}

/* A response (OK or ERROR) answers the request exactly once. A 2nd
 * response is a session-level fault, not a local termination. */
static int moqsess_sub_guard_single_response(moqsub* s) {
  if (s->responded) {
    s->session_fault = 1;
    return 0;
  }
  s->responded = 1;
  return 1;
}

static int moqsess_sub_on_ok(moqsub* s) {
  if (!moqsess_sub_guard_single_response(s)) return 0;
  s->state = QUIC_MOQSUB_ESTABLISHED;
  return 1;
}

static int moqsess_sub_on_error(moqsub* s) {
  if (!moqsess_sub_guard_single_response(s)) return 0;
  return moqsess_sub_terminate(s, QUIC_MOQSUB_TERM_ERROR);
}

/* REQUEST_UPDATE only makes sense once Established, and never changes
 * state. */
static int moqsess_sub_on_update(moqsub* s) {
  return s->state == QUIC_MOQSUB_ESTABLISHED;
}

/* STOP_SENDING cancels: legal from Pending(Subscriber) or Established. */
static int moqsess_sub_stop_sending_legal(const moqsub* s) {
  if (s->state == QUIC_MOQSUB_ESTABLISHED) return 1;
  return s->state == QUIC_MOQSUB_PENDING &&
         s->role == QUIC_MOQSUB_ROLE_SUBSCRIBER;
}

static int moqsess_sub_on_stop_sending(moqsub* s) {
  if (!moqsess_sub_stop_sending_legal(s)) return 0;
  return moqsess_sub_terminate(s, QUIC_MOQSUB_TERM_STOP_SENDING);
}

/* PUBLISH_DONE ends a publisher-initiated (or already established)
 * subscription. From Pending(Publisher) with no response sent yet, the
 * subscriber owes a deferred PUBLISH_OK before it FINs (exactly-one-
 * response is satisfied by that late OK, not skipped). */
static int moqsess_sub_publish_done_legal(const moqsub* s) {
  if (s->state == QUIC_MOQSUB_ESTABLISHED) return 1;
  return s->state == QUIC_MOQSUB_PENDING &&
         s->role == QUIC_MOQSUB_ROLE_PUBLISHER;
}

/* Pending(Publisher) with no response sent yet owes a deferred OK. */
static int moqsess_sub_owes_late_ok(const moqsub* s) {
  return s->state == QUIC_MOQSUB_PENDING && !s->responded;
}

static int moqsess_sub_on_publish_done(moqsub* s) {
  if (!moqsess_sub_publish_done_legal(s)) return 0;
  if (moqsess_sub_owes_late_ok(s)) {
    s->responded  = 1;
    s->pending_ok = 1;
  }
  return moqsess_sub_terminate(s, QUIC_MOQSUB_TERM_PUBLISH_DONE);
}

static int moqsess_sub_on_fin_resp(moqsub* s) {
  s->fin_resp = 1;
  return 1;
}

static int moqsess_sub_on_fin_req(moqsub* s) {
  s->fin_req = 1;
  return 1;
}

typedef int (*moqsess_sub_handler)(moqsub* s);

static const moqsess_sub_handler MOQSESS_SUB_HANDLERS[] = {
    moqsess_sub_on_open,         /* EV_OPEN */
    moqsess_sub_on_ok,           /* EV_OK */
    moqsess_sub_on_error,        /* EV_ERROR */
    moqsess_sub_on_update,       /* EV_UPDATE */
    moqsess_sub_on_stop_sending, /* EV_STOP_SENDING */
    moqsess_sub_on_publish_done, /* EV_PUBLISH_DONE */
    moqsess_sub_on_fin_resp,     /* EV_FIN_RESP */
    moqsess_sub_on_fin_req,      /* EV_FIN_REQ */
};

#define MOQSESS_SUB_HANDLERS_N \
  (sizeof(MOQSESS_SUB_HANDLERS) / sizeof(MOQSESS_SUB_HANDLERS[0]))

int moqsub_step(moqsub* s, moqsub_event ev) {
  usz idx = (usz)ev;
  if (s->state == QUIC_MOQSUB_TERMINATED) return 0;
  if (idx >= MOQSESS_SUB_HANDLERS_N) return 0;
  return MOQSESS_SUB_HANDLERS[idx](s);
}

int moqsub_established(const moqsub* s) {
  return s->state == QUIC_MOQSUB_ESTABLISHED;
}

int moqsub_terminated(const moqsub* s) {
  return s->state == QUIC_MOQSUB_TERMINATED;
}

int moqsub_may_forward(const moqsub* s, int forward) {
  if (!forward) return 0;
  return s->state == QUIC_MOQSUB_PENDING || s->state == QUIC_MOQSUB_ESTABLISHED;
}

int moqsub_may_send_publish_done(usz open_stream_count) {
  return open_stream_count == 0;
}
