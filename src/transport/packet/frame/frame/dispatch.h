#ifndef FRAME_DISPATCH_H
#define FRAME_DISPATCH_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 12.4: a frame begins with its type as a varint. This classifies
 * the type into a frame kind and reports whether it is ack-eliciting
 * (anything other than ACK, PADDING, CONNECTION_CLOSE — RFC 9000 1.2). */

/** The classified kind of a QUIC frame (RFC 9000 12.4), by type. */
typedef enum {
  FK_UNKNOWN = 0,
  FK_PADDING,
  FK_PING,
  FK_ACK,
  FK_RESET_STREAM,
  FK_STOP_SENDING,
  FK_CRYPTO,
  FK_NEW_TOKEN,
  FK_STREAM,
  FK_MAX_DATA,
  FK_MAX_STREAM_DATA,
  FK_MAX_STREAMS,
  FK_DATA_BLOCKED,
  FK_STREAM_DATA_BLOCKED,
  FK_STREAMS_BLOCKED,
  FK_NEW_CONNECTION_ID,
  FK_RETIRE_CONNECTION_ID,
  FK_PATH_CHALLENGE,
  FK_PATH_RESPONSE,
  FK_CONNECTION_CLOSE,
  FK_HANDSHAKE_DONE,
  FK_DATAGRAM,
  FK_RESET_STREAM_AT
} frame_kind;

/* Classify a frame type value into its kind. */
frame_kind frame_classify(u64 type);

/* True if a frame of this kind makes the packet ack-eliciting. */
int frame_ack_eliciting(frame_kind kind);

#endif
