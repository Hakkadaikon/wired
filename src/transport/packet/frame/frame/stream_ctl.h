#ifndef FRAME_STREAM_CTL_H
#define FRAME_STREAM_CTL_H

#include "common/platform/sys/syscall.h"

/** RFC 9000 19.4/19.5 stream control frames. RESET_STREAM abruptly terminates
 * the sending part of a stream; STOP_SENDING requests the peer to stop. */

#define FRAME_RESET_STREAM 0x04
#define FRAME_STOP_SENDING 0x05
#define FRAME_RESET_STREAM_AT 0x24

typedef struct {
  u64 stream_id;
  u64 error_code; /* Application Protocol Error Code */
  u64 final_size;
} reset_stream_frame;

typedef struct {
  u64 stream_id;
  u64 error_code; /* Application Protocol Error Code */
} stop_sending_frame;

/** draft-ietf-quic-reliable-stream-reset: RESET_STREAM_AT. Same first three
 * fields as RESET_STREAM plus a trailing reliable_size. */
typedef struct {
  u64 stream_id;
  u64 error_code; /* Application Protocol Error Code */
  u64 final_size;
  u64 reliable_size; /* delivery guarantee up to this byte offset; MUST be
                      * <= final_size (decode rejects a violation) */
} reset_stream_at_frame;

/* Encode into buf of cap bytes. Returns bytes written, or 0 on overflow. */
usz reset_stream_encode(u8* buf, usz cap, const reset_stream_frame* f);

/* Decode at buf (n readable, type byte 0x04 at buf[0]). Returns bytes
 * consumed, or 0 on malformed / truncated input. */
usz reset_stream_decode(const u8* buf, usz n, reset_stream_frame* f);

/* Encode into buf of cap bytes. Returns bytes written, or 0 on overflow. */
usz stop_sending_encode(u8* buf, usz cap, const stop_sending_frame* f);

/* Decode at buf (n readable, type byte 0x05 at buf[0]). Returns bytes
 * consumed, or 0 on malformed / truncated input. */
usz stop_sending_decode(const u8* buf, usz n, stop_sending_frame* f);

/* Encode into buf of cap bytes. Returns bytes written, or 0 on overflow, or
 * 0 if f->reliable_size > f->final_size (never encode a frame that would
 * violate the draft's MUST). */
usz reset_stream_at_encode(u8* buf, usz cap, const reset_stream_at_frame* f);

/* Decode at buf (n readable, type byte 0x24 at buf[0]). Returns bytes
 * consumed, or 0 on malformed / truncated input / reliable_size >
 * final_size (draft-ietf-quic-reliable-stream-reset: FRAME_ENCODING_ERROR
 * condition, surfaced here as a decode failure like other malformed-frame
 * cases). */
usz reset_stream_at_decode(const u8* buf, usz n, reset_stream_at_frame* f);

#endif
