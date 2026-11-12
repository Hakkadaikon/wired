#ifndef H3REQENC_REQUEST_HEADERS_H
#define H3REQENC_REQUEST_HEADERS_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** The :path and :authority values of h3req_enc_method. */
typedef struct {
  wired_span path;
  wired_span authority;
} h3req_headers_in;

/* RFC 9114 4.3.1 / RFC 9204 4.5. Build the complete QPACK field section for a
 * request: the empty field section prefix followed by the four request
 * pseudo-headers in the order :method, :scheme, :authority, :path with the
 * given :method (GET, HEAD, POST, ...) and :scheme = https. The given
 * authority and path become the :authority and :path values. Returns 1 with
 * out->len set, 0 on overflow. */
int h3req_enc_method(
    wired_span method, const h3req_headers_in* in, wired_obuf* out);

#endif
