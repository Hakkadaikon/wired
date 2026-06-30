#ifndef QUIC_MAXSTREAMS_MAXSTREAMS_H
#define QUIC_MAXSTREAMS_MAXSTREAMS_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 4.6 / 19.11: MAX_STREAMS frame and the open-permission check it
 * feeds. Wire codec delegates to frame/flowctl; this layer presents the
 * out_len convention and a stateless admission predicate. */

/* Build a MAX_STREAMS frame (0x12 bidi, 0x13 uni) into out[0..cap).
 * Returns 1 and sets *out_len on success, 0 on overflow / out-of-range. */
int quic_maxstreams_frame(int uni, u64 max, u8 *out, usz cap, usz *out_len);

/* Parse a MAX_STREAMS frame from buf[0..n). Returns 1 and fills *uni and
 * *max on success, 0 on truncated / malformed input. */
int quic_maxstreams_parse(const u8 *buf, usz n, int *uni, u64 *max);

/* RFC 9000 4.6: admission. Returns 1 if opening one more stream stays within
 * max_streams (opened < max_streams), 0 once the limit is reached
 * (a STREAM_LIMIT_ERROR). */
int quic_maxstreams_can_open(u64 opened, u64 max_streams);

#endif
