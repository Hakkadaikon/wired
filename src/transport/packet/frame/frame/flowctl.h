#ifndef FRAME_FLOWCTL_H
#define FRAME_FLOWCTL_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 19.9-19.14 flow control frames. Every field is a varint. */

#define FRAME_MAX_DATA 0x10
#define FRAME_MAX_STREAM_DATA 0x11
#define FRAME_MAX_STREAMS_BIDI 0x12
#define FRAME_MAX_STREAMS_UNI 0x13
#define FRAME_DATA_BLOCKED 0x14
#define FRAME_STREAM_DATA_BLOCKED 0x15
#define FRAME_STREAMS_BLOCKED_BIDI 0x16
#define FRAME_STREAMS_BLOCKED_UNI 0x17

/** MAX_DATA (19.9) / DATA_BLOCKED (19.12): one varint. */
typedef struct {
  u64 value;
} data_frame;

/** MAX_STREAM_DATA (19.10) / STREAM_DATA_BLOCKED (19.13): two varints. */
typedef struct {
  u64 stream_id;
  u64 value;
} stream_data_frame;

/** MAX_STREAMS (19.11) / STREAMS_BLOCKED (19.14): one varint plus a
 * direction carried in the frame type's least significant bit (0 bidi, 1
 * uni). */
typedef struct {
  u64 max_streams;
  int uni; /* 0 bidi, 1 uni */
} streams_frame;

/* Each encode returns bytes written, or 0 on overflow / out-of-range value.
 * Each decode reads the type byte at buf[0], fills *f, and returns bytes
 * consumed, or 0 on truncated / malformed input. */

usz max_data_encode(u8* buf, usz cap, const data_frame* f);
usz max_data_decode(const u8* buf, usz n, data_frame* f);

usz data_blocked_encode(u8* buf, usz cap, const data_frame* f);
usz data_blocked_decode(const u8* buf, usz n, data_frame* f);

usz max_stream_data_encode(u8* buf, usz cap, const stream_data_frame* f);
usz max_stream_data_decode(const u8* buf, usz n, stream_data_frame* f);

usz stream_data_blocked_encode(u8* buf, usz cap, const stream_data_frame* f);
usz stream_data_blocked_decode(const u8* buf, usz n, stream_data_frame* f);

usz max_streams_encode(u8* buf, usz cap, const streams_frame* f);
usz max_streams_decode(const u8* buf, usz n, streams_frame* f);

usz streams_blocked_encode(u8* buf, usz cap, const streams_frame* f);
usz streams_blocked_decode(const u8* buf, usz n, streams_frame* f);

#endif
