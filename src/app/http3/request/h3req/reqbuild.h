#ifndef QUIC_H3REQ_REQBUILD_H
#define QUIC_H3REQ_REQBUILD_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9114 4.1. Assemble a request stream byte sequence: a HEADERS frame
 * carrying the QPACK-encoded field section, followed by a DATA frame carrying
 * the body. When body is empty only the HEADERS frame is emitted.
 * Returns 1 with out->len set on success, 0 if out lacks capacity. */
int quic_h3req_build(quic_span qpack_headers, quic_span body, quic_obuf* out);

#endif
