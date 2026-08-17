#ifndef QUIC_H3_CONTROL_H
#define QUIC_H3_CONTROL_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 6.2.1/7.2.4/5.2: the HTTP/3 control stream, SETTINGS ordering, and
 * GOAWAY graceful shutdown. A peer opens at most one control stream which is
 * never closed; its first frame must be SETTINGS (once); GOAWAY ids are
 * monotonically non-increasing and forbid new requests at or above the
 * limit. Any violation latches a connection error (terminal). */

/** RFC 9114 6.2.1/7.2.4/5.2: control-stream/SETTINGS/GOAWAY connection
 * error latched by this module (NONE means no violation yet). */
typedef enum {
  QUIC_H3_ERR_NONE = 0,
  QUIC_H3_ERR_STREAM_CREATION,  /* 2nd control stream */
  QUIC_H3_ERR_CLOSED_CRITICAL,  /* control stream closed */
  QUIC_H3_ERR_MISSING_SETTINGS, /* first control frame not SETTINGS */
  QUIC_H3_ERR_FRAME_UNEXPECTED, /* a second SETTINGS */
  QUIC_H3_ERR_ID                /* GOAWAY id increased */
} h3_error;

/** RFC 9114 6.2.1/7.2.4/5.2: this connection's control-stream state —
 * whether it is open, whether SETTINGS was its first frame, the latest
 * GOAWAY id, and any latched connection error. */
typedef struct {
  u8       control_open;  /**< a control stream is open */
  u8       settings_seen; /**< SETTINGS was the first control frame */
  u8       goaway_seen;   /**< a GOAWAY has been received */
  u64      goaway_limit; /**< highest request id still accepted is below this */
  h3_error error;        /**< latched; nonzero means the connection failed */
} h3_control;

void h3_control_init(h3_control* c);

/* A peer opened its control stream. The second one is a STREAM_CREATION error.
 */
void h3_control_open(h3_control* c);

/* The control stream closed: a CLOSED_CRITICAL_STREAM error. */
void h3_control_closed(h3_control* c);

/* A control-stream frame arrived; is_settings marks the SETTINGS type. The
 * first frame must be SETTINGS (else MISSING_SETTINGS); a later SETTINGS is
 * FRAME_UNEXPECTED. */
void h3_control_frame(h3_control* c, int is_settings);

/* A GOAWAY with `id` arrived. Accepted if not greater than a prior GOAWAY id;
 * an increase is an ID error. */
void h3_control_goaway(h3_control* c, u64 id);

/* Whether a new request with `id` may be accepted: not after a GOAWAY whose
 * limit it reaches (RFC 9114 5.2). Existing requests are unaffected. */
int h3_control_accept_request(const h3_control* c, u64 id);

#endif
