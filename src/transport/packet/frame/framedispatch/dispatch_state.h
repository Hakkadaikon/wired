#ifndef QUIC_FRAMEDISPATCH_DISPATCH_STATE_H
#define QUIC_FRAMEDISPATCH_DISPATCH_STATE_H

#include "common/platform/sys/syscall.h"
#include "flow/stream_read.h"
#include "sentpkt/sentpkt.h"
#include "flow/credit.h"

/* RFC 9000 12.4: after a payload is walked into frames, each frame is
 * dispatched by type to the subsystem that owns its effect. This bundles the
 * per-connection receive state those handlers touch. */
typedef struct {
    quic_stream_read *stream;   /* STREAM data sink (RFC 9000 19.8) */
    quic_sentpkt *sent;         /* sent-packet table for ACK (RFC 9000 19.3) */
    quic_flow_credit *credit;   /* connection flow credit (RFC 9000 19.9) */
    u8 ack_eliciting;           /* set when an ack-eliciting frame arrived */
    u8 close;                   /* set on CONNECTION_CLOSE (RFC 9000 19.19) */
    u8 has_ack;                 /* set when an ACK frame arrived (RFC 9000 19.3) */
    u64 largest_acked;          /* its Largest Acknowledged, when has_ack */
} quic_framedispatch_state;

/* Dispatch one frame by type. frame points at the type varint, len covers the
 * whole frame. Returns 1 if handled, 0 on an unknown type or malformed frame. */
int quic_framedispatch_handle(quic_framedispatch_state *st, u64 frame_type,
                              const u8 *frame, usz len);

/* RFC 9000 13.2.1: every frame except PADDING, ACK and CONNECTION_CLOSE is
 * ack-eliciting. Returns 1 or 0. */
int quic_framedispatch_ack_eliciting(u64 frame_type);

#endif
