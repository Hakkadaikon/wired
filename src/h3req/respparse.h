#ifndef QUIC_H3REQ_RESPPARSE_H
#define QUIC_H3REQ_RESPPARSE_H

#include "sys/syscall.h"

/* RFC 9114 4.1. Split a response stream into its leading HEADERS frame (the
 * status/header field section) and the following DATA frame (the body). The
 * field section and body are viewed in place (no copy). When no DATA frame
 * follows, *body is 0 and *body_len is 0.
 * Returns 1 on success, 0 if the stream does not begin with a well-formed
 * HEADERS frame or a following frame is malformed. */
int quic_h3req_resp_parse(const u8 *stream, usz len,
                          const u8 **headers, usz *h_len,
                          const u8 **body, usz *body_len);

#endif
