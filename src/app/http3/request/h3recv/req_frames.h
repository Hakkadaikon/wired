#ifndef QUIC_H3RECV_REQ_FRAMES_H
#define QUIC_H3RECV_REQ_FRAMES_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9114 4.1. A request stream begins with a HEADERS frame whose payload is
 * a QPACK-encoded field section. View the first HEADERS frame's payload in
 * place (no copy). Returns 1 if the stream starts with a HEADERS frame, else 0
 * (a different first frame, or truncation). */
int quic_h3req_recv_first_headers(quic_span stream, quic_span* field_section);

#endif
