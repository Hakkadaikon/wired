#ifndef FRAME_CRYPTO_OFFSET_H
#define FRAME_CRYPTO_OFFSET_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 19.6, 7.5: CRYPTO frames carry an offset in a stream-independent
 * space. The receiver must bound writes by a buffer limit and accept gaps. */

/* Whether [offset, offset+len) fits within max_offset (the receive buffer
 * upper bound). Returns 1 if in range, 0 on overflow or past the limit. */
int crypto_offset_ok(u64 offset, u64 len, u64 max_offset);

/* Whether new_offset extends the contiguous prefix without a gap: it is
 * contiguous when new_offset <= received_upto (overlap allowed). Returns 1
 * if contiguous, 0 if a gap would form. */
int crypto_contiguous(u64 received_upto, u64 new_offset);

#endif
