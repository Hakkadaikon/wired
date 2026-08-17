#ifndef MOQSESS_H
#define MOQSESS_H

#include "common/platform/sys/syscall.h"

/** @file
 * draft-ietf-moq-transport-19 3.3 / 5.1: session establishment/control-
 * stream discipline, and 5.1 SUBSCRIBE/PUBLISH lifecycle. Pure state
 * machines: callers (the run layer, decoding wire bytes via moqctl) drive
 * these with events; no wire codec is invoked here.
 */

/* ===================== A. Session establishment ===================== */

/** Session state (draft 3.3: each endpoint opens one uni control stream
 * and sends SETUP first; the session is established once both sides have
 * done so). */
typedef enum {
  MOQSESS_IDLE        = 0, /* neither SETUP sent nor peer's received */
  MOQSESS_SETUP_HALF  = 1, /* exactly one of (sent, peer recv'd) done */
  MOQSESS_ESTABLISHED = 2,
  MOQSESS_CLOSED      = 3,
} moqsess_state;

/** Events the run layer feeds in as it decodes the wire. */
typedef enum {
  MOQSESS_EV_SENT_SETUP          = 0, /* own SETUP finished sending */
  MOQSESS_EV_RECV_SETUP          = 1, /* peer's SETUP received */
  MOQSESS_EV_CTRL_CLOSED         = 2, /* control stream closed at transport */
  MOQSESS_EV_UNKNOWN_UNI         = 3, /* unknown uni stream type byte */
  MOQSESS_EV_SECOND_CTRL         = 4, /* 2nd control stream from same peer */
  MOQSESS_EV_MALFORMED_CTRL      = 5, /* unknown msg type / len mismatch */
  MOQSESS_EV_SEND_GOAWAY         = 6,
  MOQSESS_EV_RECV_GOAWAY         = 7,
  MOQSESS_EV_RECV_GOAWAY_BAD_URI = 8,  /* server: nonzero URI length */
  MOQSESS_EV_GOAWAY_TIMEOUT      = 9,  /* peer did not close in time */
  MOQSESS_EV_BAD_FIRST           = 10, /* new request stream's head is not a
                                        * First-type message (codec-detected) */
  MOQSESS_EV_BAD_REQUEST_ID = 11,      /* wrong parity or a reused Request
                                        * ID (codec-detected) */
} moqsess_event;

/** Close reasons a step can produce (0 = still open). */
#define MOQSESS_CLOSE_NONE 0
#define MOQSESS_CLOSE_PROTOCOL_VIOLATION 1
#define MOQSESS_CLOSE_INVALID_REQUEST_ID 2
#define MOQSESS_CLOSE_GOAWAY_TIMEOUT 3
#define MOQSESS_CLOSE_NO_ERROR 4

/** Session state including the GOAWAY-lifecycle flags (5.1: GOAWAY may be
 * sent/received at most once per direction; violations and shutdown
 * decisions read these). */
typedef struct {
  moqsess_state state;
  int           goaway_sent;
  int           goaway_recv;
  int           close_reason; /* MOQSESS_CLOSE_* once state==CLOSED */
} moqsess;

/** Zero-initialize (equivalent to `= {0}`; provided for callers that build
 * the struct at runtime rather than with a static initializer). */
void moqsess_init(moqsess* s);

/** Apply one event. Returns the resulting close_reason (MOQSESS_CLOSE_
 * NONE if the session is still open). Once state == CLOSED, further events
 * are no-ops (idempotent close). */
int moqsess_step(moqsess* s, moqsess_event ev);

/** True while SETUP has not yet completed both directions: requests and
 * data streams that arrive now must be buffered, not delivered to the
 * application (3.3 / draft 5.1 buffering discipline). */
int moqsess_should_buffer(const moqsess* s);

/** True once SETUP is fully established (both directions done). */
int moqsess_established(const moqsess* s);

/** True if a newly arriving request MAY be rejected with GOING_AWAY
 * (either side sent or received GOAWAY: draft 5.1 GOAWAY discipline). */
int moqsess_may_reject_request(const moqsess* s);

/** True if this endpoint SHOULD NOT initiate new requests of its own
 * (GOAWAY received on the control stream: draft 5.1, SHOULD NOT). */
int moqsess_suppress_own_requests(const moqsess* s);

/* ===================== B. Subscribe lifecycle ===================== */

/** One subscription's state (draft 5.1: SUBSCRIBE/PUBLISH -> response ->
 * termination, one instance per request stream). */
typedef enum {
  MOQSUB_IDLE        = 0,
  MOQSUB_PENDING     = 1,
  MOQSUB_ESTABLISHED = 2,
  MOQSUB_TERMINATED  = 3,
} moqsub_state;

/** Which side opened the request stream with its First message. */
typedef enum {
  MOQSUB_ROLE_SUBSCRIBER = 0, /* sent/received SUBSCRIBE first */
  MOQSUB_ROLE_PUBLISHER  = 1, /* sent/received PUBLISH first */
} moqsub_role;

typedef enum {
  MOQSUB_EV_OPEN         = 0, /* SUBSCRIBE or PUBLISH sent/received */
  MOQSUB_EV_OK           = 1, /* SUBSCRIBE_OK / PUBLISH_OK (REQUEST_OK) */
  MOQSUB_EV_ERROR        = 2, /* REQUEST_ERROR sent or received */
  MOQSUB_EV_UPDATE       = 3, /* REQUEST_UPDATE: no state change */
  MOQSUB_EV_STOP_SENDING = 4, /* STOP_SENDING sent or received */
  MOQSUB_EV_PUBLISH_DONE = 5, /* PUBLISH_DONE sent or received */
  MOQSUB_EV_FIN_RESP     = 6, /* the responder's direction FIN */
  MOQSUB_EV_FIN_REQ      = 7, /* the requester's direction FIN */
} moqsub_event;

/** Terminated reasons (informational; a subscription's own close does not
 * imply the session closes). 0 = not terminated. */
#define MOQSUB_TERM_NONE 0
#define MOQSUB_TERM_STOP_SENDING 1 /* cancel via STOP_SENDING */
#define MOQSUB_TERM_PUBLISH_DONE 2 /* publisher finished normally */
#define MOQSUB_TERM_ERROR 3        /* REQUEST_ERROR (reject or fault) */
#define MOQSUB_TERM_EARLY_FIN 4    /* peer FIN'd before responding */
#define MOQSUB_TERM_DUP_RESPONSE 5 /* a 2nd response: session fault */

typedef struct {
  moqsub_state state;
  moqsub_role  role;
  int          responded; /* exactly-one-response gate: OK or ERROR seen */
  int pending_ok;    /* publisher-initiated: OK deferred past PUBLISH_DONE */
  int fin_req;       /* requester's direction closed (FIN) */
  int fin_resp;      /* responder's direction closed (FIN) */
  int term_reason;   /* MOQSUB_TERM_* once state==TERMINATED */
  int session_fault; /* set on a duplicate-response violation */
} moqsub;

/** Initialize a fresh subscription: role is fixed by which message (SUBSCRIBE
 * vs PUBLISH) opened the request stream. */
void moqsub_init(moqsub* s, moqsub_role role);

/** Apply one event. Returns 1 if the event was legal for the current state
 * (state/flags updated), 0 if it violates the subscribe discipline (e.g. a
 * duplicate response) -- callers read s->session_fault to distinguish a
 * subscription-local termination from a session-level protocol error. */
int moqsub_step(moqsub* s, moqsub_event ev);

/** True once the subscription is Established (SS10.6/10.9 semantics apply:
 * REQUEST_UPDATE legal, Object forwarding gated by moqsub_may_forward). */
int moqsub_established(const moqsub* s);

/** True once Terminated (state machine done; s->term_reason explains why). */
int moqsub_terminated(const moqsub* s);

/** Forward State gate (5.1 / SS10.2 FORWARD parameter, subscribe notes
 * decision 9): Object sending toward this subscription is permitted only
 * while pending or established AND not yet errored. `forward` is the
 * negotiated FORWARD value (0 = never send Objects, 1 = normal gate). */
int moqsub_may_forward(const moqsub* s, int forward);

/** PUBLISH_DONE precondition (draft 8.9): a publisher may only send
 * PUBLISH_DONE once every data stream it opened for this subscription has
 * been closed. Callers pass their own open-stream count; this only encodes
 * the gate, not the count itself. */
int moqsub_may_send_publish_done(usz open_stream_count);

#endif
