#ifndef QUIC_FLOWVIOL_CLOSEFRAME_H
#define QUIC_FLOWVIOL_CLOSEFRAME_H

#include "common/bytes/span/span.h"

/* RFC 9000 19.19: build a transport CONNECTION_CLOSE (type 0x1c) carrying the
 * error code, the type of the frame that triggered the violation, and a reason
 * phrase. A thin wrapper over quic_frame_put_conn_close fixing the transport
 * variant. */

/* What the CONNECTION_CLOSE reports: the error code, the type of the frame
 * that triggered the violation, and a reason phrase (may be empty). */
typedef struct {
  u64       error_code;
  u64       frame_type;
  quic_span reason;
} quic_flowviol_err;

/* Writes the frame to out and its length to out->len. Returns 1 on success,
 * 0 on overflow. */
int quic_flowviol_close_frame(const quic_flowviol_err* e, quic_obuf* out);

#endif
