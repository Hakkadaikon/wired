#include "app/moqt/sess/moqsess.h"

/* draft-ietf-moq-transport-19 3.3 / 5.1 -- see moqsess.h for the state/
 * event catalog. Each event has its own tiny handler (CCN<=3 per handler);
 * moqsess_step dispatches by event index through a function table. */

void moqsess_init(moqsess* s) {
  moqsess zero = {0};
  *s           = zero;
}

static int moqsess_closed(moqsess* s, int reason) {
  s->state        = MOQSESS_CLOSED;
  s->close_reason = reason;
  return reason;
}

/* Advance the SETUP half-handshake: IDLE -> SETUP_HALF -> ESTABLISHED.
 * Either "own sent" or "peer recv'd" arriving first takes the same path;
 * the second occurrence of either establishes. */
static int moqsess_setup_progress(moqsess* s) {
  if (s->state == MOQSESS_IDLE) {
    s->state = MOQSESS_SETUP_HALF;
    return MOQSESS_CLOSE_NONE;
  }
  if (s->state == MOQSESS_SETUP_HALF) {
    s->state = MOQSESS_ESTABLISHED;
  }
  return MOQSESS_CLOSE_NONE;
}

static int moqsess_on_sent_setup(moqsess* s) {
  return moqsess_setup_progress(s);
}

static int moqsess_on_recv_setup(moqsess* s) {
  return moqsess_setup_progress(s);
}

static int moqsess_on_ctrl_closed(moqsess* s) {
  return moqsess_closed(s, MOQSESS_CLOSE_PROTOCOL_VIOLATION);
}

static int moqsess_on_unknown_uni(moqsess* s) {
  return moqsess_closed(s, MOQSESS_CLOSE_PROTOCOL_VIOLATION);
}

static int moqsess_on_second_ctrl(moqsess* s) {
  return moqsess_closed(s, MOQSESS_CLOSE_PROTOCOL_VIOLATION);
}

static int moqsess_on_malformed_ctrl(moqsess* s) {
  return moqsess_closed(s, MOQSESS_CLOSE_PROTOCOL_VIOLATION);
}

static int moqsess_on_send_goaway(moqsess* s) {
  s->goaway_sent = 1;
  return MOQSESS_CLOSE_NONE;
}

/* A 2nd GOAWAY on the same control stream is a protocol violation; the
 * first is recorded and leaves the session open. */
static int moqsess_on_recv_goaway(moqsess* s) {
  if (s->goaway_recv) {
    return moqsess_closed(s, MOQSESS_CLOSE_PROTOCOL_VIOLATION);
  }
  s->goaway_recv = 1;
  return MOQSESS_CLOSE_NONE;
}

static int moqsess_on_recv_goaway_bad_uri(moqsess* s) {
  return moqsess_closed(s, MOQSESS_CLOSE_PROTOCOL_VIOLATION);
}

static int moqsess_on_goaway_timeout(moqsess* s) {
  return moqsess_closed(s, MOQSESS_CLOSE_GOAWAY_TIMEOUT);
}

static int moqsess_on_bad_first(moqsess* s) {
  return moqsess_closed(s, MOQSESS_CLOSE_PROTOCOL_VIOLATION);
}

static int moqsess_on_bad_request_id(moqsess* s) {
  return moqsess_closed(s, MOQSESS_CLOSE_INVALID_REQUEST_ID);
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
  if (s->state == MOQSESS_CLOSED) {
    return s->close_reason;
  }
  if (idx >= MOQSESS_HANDLERS_N) {
    return MOQSESS_CLOSE_NONE;
  }
  return MOQSESS_HANDLERS[idx](s);
}

int moqsess_should_buffer(const moqsess* s) {
  return s->state != MOQSESS_ESTABLISHED && s->state != MOQSESS_CLOSED;
}

int moqsess_established(const moqsess* s) {
  return s->state == MOQSESS_ESTABLISHED;
}

/* ===================== B. Subscribe lifecycle ===================== */

void moqsub_init(moqsub* s) {
  moqsub zero = {0};
  *s          = zero;
}

/* SUBSCRIBE opens the request: Idle -> Pending. Anything else is a
 * caller misuse (ignored: no legal re-open of an active subscription). */
static int moqsess_sub_on_open(moqsub* s) {
  if (s->state != MOQSUB_IDLE) {
    return 0;
  }
  s->state = MOQSUB_PENDING;
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
  if (!moqsess_sub_guard_single_response(s)) {
    return 0;
  }
  s->state = MOQSUB_ESTABLISHED;
  return 1;
}

static int moqsess_sub_on_error(moqsub* s) {
  if (!moqsess_sub_guard_single_response(s)) {
    return 0;
  }
  s->state = MOQSUB_TERMINATED;
  return 1;
}

typedef int (*moqsess_sub_handler)(moqsub* s);

static const moqsess_sub_handler MOQSESS_SUB_HANDLERS[] = {
    moqsess_sub_on_open,  /* EV_OPEN */
    moqsess_sub_on_ok,    /* EV_OK */
    moqsess_sub_on_error, /* EV_ERROR */
};

#define MOQSESS_SUB_HANDLERS_N \
  (sizeof(MOQSESS_SUB_HANDLERS) / sizeof(MOQSESS_SUB_HANDLERS[0]))

int moqsub_step(moqsub* s, moqsub_event ev) {
  usz idx = (usz)ev;
  if (s->state == MOQSUB_TERMINATED) {
    return 0;
  }
  if (idx >= MOQSESS_SUB_HANDLERS_N) {
    return 0;
  }
  return MOQSESS_SUB_HANDLERS[idx](s);
}
