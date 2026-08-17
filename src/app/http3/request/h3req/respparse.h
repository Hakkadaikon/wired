#ifndef H3REQ_RESPPARSE_H
#define H3REQ_RESPPARSE_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** RFC 9114 4.1. The response stream's HEADERS field section and (optional)
 * DATA body, both viewed in place (no copy). An absent body has body.n == 0. */
typedef struct {
  wired_span headers;
  wired_span body;
} h3req_resp;

/* RFC 9114 4.1. Split a response stream into its leading HEADERS frame (the
 * status/header field section) and the following DATA frame (the body).
 * Returns 1 on success, 0 if the stream does not begin with a well-formed
 * HEADERS frame or a following frame is malformed. */
int h3req_resp_parse(wired_span stream, h3req_resp* resp);

#endif
