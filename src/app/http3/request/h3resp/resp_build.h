#ifndef QUIC_H3RESP_RESP_BUILD_H
#define QUIC_H3RESP_RESP_BUILD_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9114 4.1. Assemble a response stream byte sequence: a HEADERS frame
 * carrying the QPACK-encoded :status (plus a content-type field line when
 * content_type is non-null) field section, followed by a DATA frame carrying
 * the body. When body is empty only the HEADERS frame is emitted. Returns 1
 * with out->len set on success, 0 if out lacks capacity. */
int quic_h3resp_build(
    u16 status, const char* content_type, quic_span body, quic_obuf* out);

#endif
