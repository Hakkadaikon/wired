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
/** Close with PROTOCOL_VIOLATION: a control-stream or GOAWAY rule was
 * broken (e.g. a second GOAWAY, a malformed control message). */
#define MOQSESS_CLOSE_PROTOCOL_VIOLATION 1
/** Close with INVALID_REQUEST_ID: wrong-parity or reused Request ID. */
#define MOQSESS_CLOSE_INVALID_REQUEST_ID 2
/** Close with GOAWAY_TIMEOUT: the peer did not close after GOAWAY. */
#define MOQSESS_CLOSE_GOAWAY_TIMEOUT 3
/** Clean close (NO_ERROR); no moqsess_step event produces it. */
#define MOQSESS_CLOSE_NO_ERROR 4

/** Session state including the GOAWAY-lifecycle flags (5.1: GOAWAY may be
 * sent/received at most once per direction; violations and shutdown
 * decisions read these). */
typedef struct {
  /** Establishment state. */
  moqsess_state state;
  /** 1 once this endpoint sent GOAWAY. */
  int goaway_sent;
  /** 1 once the peer's GOAWAY arrived; a second one is a violation. */
  int goaway_recv;
  /** MOQSESS_CLOSE_* once state == MOQSESS_CLOSED, else 0. */
  int close_reason;
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

/* ===================== B. Subscribe lifecycle ===================== */

/** One upstream subscription's state (draft 5.1: SUBSCRIBE -> response,
 * one instance per request stream). */
typedef enum {
  MOQSUB_IDLE        = 0,
  MOQSUB_PENDING     = 1,
  MOQSUB_ESTABLISHED = 2,
  MOQSUB_TERMINATED  = 3,
} moqsub_state;

/** Events moqsub_step applies, each sent or received on the request
 * stream. */
typedef enum {
  MOQSUB_EV_OPEN  = 0, /* SUBSCRIBE sent */
  MOQSUB_EV_OK    = 1, /* SUBSCRIBE_OK (REQUEST_OK) */
  MOQSUB_EV_ERROR = 2, /* REQUEST_ERROR received */
} moqsub_event;

/** One subscription's lifecycle state plus the flags moqsub_step keeps. */
typedef struct {
  /** Lifecycle state. */
  moqsub_state state;
  /** Exactly-one-response gate: 1 once OK or ERROR was seen. */
  int responded;
  /** 1 after a duplicate response: a session-level violation. */
  int session_fault;
} moqsub;

/** Initialize a fresh subscription. */
void moqsub_init(moqsub* s);

/** Apply one event. Returns 1 if the event was legal for the current state
 * (state/flags updated), 0 if it violates the subscribe discipline (e.g. a
 * duplicate response) -- callers read s->session_fault to distinguish a
 * subscription-local termination from a session-level protocol error. */
int moqsub_step(moqsub* s, moqsub_event ev);

#endif
