#ifndef QUIC_PIPELINE_FRAMEWALK_H
#define QUIC_PIPELINE_FRAMEWALK_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 12.4: walk a decrypted payload frame by frame. Each frame begins
 * with its type as a varint; the walker reports the type and advances past the
 * whole frame. Frame lengths are measured with the existing frame decoders, so
 * only the frame kinds the pipeline emits (PADDING, PING, CRYPTO, STREAM,
 * CONNECTION_CLOSE) can be walked. */

typedef struct {
  const u8 *cur;
  usz       remaining;
} quic_framewalk;

void quic_framewalk_init(quic_framewalk *it, const u8 *frames, usz len);

/* One yielded frame: its type varint, where it starts, and the bytes left
 * from this frame onward (including it). */
typedef struct {
  u64       type;
  const u8 *start;
  usz       remaining;
} quic_framewalk_item;

/* Yield the next frame into *out. Returns 1 on success, 0 at end of input or
 * on a frame the walker cannot measure. */
int quic_framewalk_next(quic_framewalk *it, quic_framewalk_item *out);

#endif
