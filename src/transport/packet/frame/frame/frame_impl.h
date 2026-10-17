#ifndef TRANSPORT_PACKET_FRAME_FRAME_FRAME_IMPL_H
#define TRANSPORT_PACKET_FRAME_FRAME_FRAME_IMPL_H

/* Internal to the frame*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "common/bytes/span/span.h"
#include "common/bytes/varint/varint.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/frame/stream_bounds.h"

usz frame_write_bytes(wired_obuf* out, const u8* src, u64 len);
usz frame_view_end(wired_span in, usz off, u64 len);

#endif
