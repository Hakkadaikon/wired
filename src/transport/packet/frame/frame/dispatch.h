#ifndef QUIC_FRAME_DISPATCH_H
#define QUIC_FRAME_DISPATCH_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 12.4: a frame begins with its type as a varint. This classifies
 * the type into a frame kind and reports whether it is ack-eliciting
 * (anything other than ACK, PADDING, CONNECTION_CLOSE — RFC 9000 1.2). */

/** The classified kind of a QUIC frame (RFC 9000 12.4), by type. */
typedef enum {
  QUIC_FK_UNKNOWN = 0,
  QUIC_FK_PADDING,
  QUIC_FK_PING,
  QUIC_FK_ACK,
  QUIC_FK_RESET_STREAM,
  QUIC_FK_STOP_SENDING,
  QUIC_FK_CRYPTO,
  QUIC_FK_NEW_TOKEN,
  QUIC_FK_STREAM,
  QUIC_FK_MAX_DATA,
  QUIC_FK_MAX_STREAM_DATA,
  QUIC_FK_MAX_STREAMS,
  QUIC_FK_DATA_BLOCKED,
  QUIC_FK_STREAM_DATA_BLOCKED,
  QUIC_FK_STREAMS_BLOCKED,
  QUIC_FK_NEW_CONNECTION_ID,
  QUIC_FK_RETIRE_CONNECTION_ID,
  QUIC_FK_PATH_CHALLENGE,
  QUIC_FK_PATH_RESPONSE,
  QUIC_FK_CONNECTION_CLOSE,
  QUIC_FK_HANDSHAKE_DONE,
  QUIC_FK_DATAGRAM,
  QUIC_FK_RESET_STREAM_AT
} frame_kind;

/* Classify a frame type value into its kind. */
frame_kind frame_classify(u64 type);

/* True if a frame of this kind makes the packet ack-eliciting. */
int frame_ack_eliciting(frame_kind kind);

#endif
