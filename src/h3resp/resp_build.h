#ifndef QUIC_H3RESP_RESP_BUILD_H
#define QUIC_H3RESP_RESP_BUILD_H

#include "sys/syscall.h"

/* RFC 9114 4.1. Assemble a response stream byte sequence: a HEADERS frame
 * carrying the QPACK-encoded :status field section, followed by a DATA frame
 * carrying the body. When body_len is 0 only the HEADERS frame is emitted.
 * Returns 1 with *out_len set on success, 0 if out lacks capacity. */
int quic_h3resp_build(u16 status, const u8 *body, usz body_len,
                      u8 *out, usz cap, usz *out_len);

#endif
