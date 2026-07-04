#ifndef QUIC_H3_CONTROL_H
#define QUIC_H3_CONTROL_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 6.2.1/7.2.4/5.2: the HTTP/3 control stream, SETTINGS ordering, and
 * GOAWAY graceful shutdown. A peer opens at most one control stream which is
 * never closed; its first frame must be SETTINGS (once); GOAWAY ids are
 * monotonically non-increasing and forbid new requests at or above the
 * limit. Any violation latches a connection error (terminal). */

typedef enum {
  QUIC_H3_ERR_NONE = 0,
  QUIC_H3_ERR_STREAM_CREATION,  /* 2nd control stream */
  QUIC_H3_ERR_CLOSED_CRITICAL,  /* control stream closed */
  QUIC_H3_ERR_MISSING_SETTINGS, /* first control frame not SETTINGS */
  QUIC_H3_ERR_FRAME_UNEXPECTED, /* a second SETTINGS */
  QUIC_H3_ERR_ID                /* GOAWAY id increased */
} quic_h3_error;

typedef struct {
  u8  control_open;  /* a control stream is open */
  u8  settings_seen; /* SETTINGS was the first control frame */
  u8  goaway_seen;
  u64 goaway_limit;    /* highest request id still accepted is below this */
  quic_h3_error error; /* latched; nonzero means the connection failed */
} quic_h3_control;

void quic_h3_control_init(quic_h3_control* c);

/* A peer opened its control stream. The second one is a STREAM_CREATION error.
 */
void quic_h3_control_open(quic_h3_control* c);

/* The control stream closed: a CLOSED_CRITICAL_STREAM error. */
void quic_h3_control_closed(quic_h3_control* c);

/* A control-stream frame arrived; is_settings marks the SETTINGS type. The
 * first frame must be SETTINGS (else MISSING_SETTINGS); a later SETTINGS is
 * FRAME_UNEXPECTED. */
void quic_h3_control_frame(quic_h3_control* c, int is_settings);

/* A GOAWAY with `id` arrived. Accepted if not greater than a prior GOAWAY id;
 * an increase is an ID error. */
void quic_h3_control_goaway(quic_h3_control* c, u64 id);

/* Whether a new request with `id` may be accepted: not after a GOAWAY whose
 * limit it reaches (RFC 9114 5.2). Existing requests are unaffected. */
int quic_h3_control_accept_request(const quic_h3_control* c, u64 id);

#endif
