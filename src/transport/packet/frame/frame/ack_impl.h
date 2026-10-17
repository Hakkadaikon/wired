#ifndef TRANSPORT_PACKET_FRAME_FRAME_ACK_IMPL_H
#define TRANSPORT_PACKET_FRAME_FRAME_ACK_IMPL_H

/* Internal to the ack*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "common/bytes/span/span.h"
#include "common/bytes/varint/varint.h"
#include "transport/packet/frame/frame/ack.h"

/* Decode-side scratch threaded through the take_* helpers. */
typedef struct {
  ack_frame* f;
  u64        largest;
  u64        first;
  u64        count;
} ackdec;

int ack_take_ack_head(wired_span in, usz* off, ackdec* d);

#endif
