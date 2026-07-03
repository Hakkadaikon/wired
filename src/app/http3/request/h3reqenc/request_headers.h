#ifndef QUIC_H3REQENC_REQUEST_HEADERS_H
#define QUIC_H3REQENC_REQUEST_HEADERS_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* The :path and :authority values shared by enc_get/enc_method. */
typedef struct {
  quic_span path;
  quic_span authority;
} quic_h3req_headers_in;

/* RFC 9114 4.3.1 / RFC 9204 4.5. Build the complete QPACK field section for a
 * GET request: the empty field section prefix followed by the four request
 * pseudo-headers in the order :method, :scheme, :authority, :path with
 * :method = GET and :scheme = https. The given authority and path become the
 * :authority and :path values. Returns 1 with out->len set, 0 on overflow. */
int quic_h3req_enc_get(const quic_h3req_headers_in *in, quic_obuf *out);

/* RFC 9114 4.3.1 / RFC 9204 4.5. Like quic_h3req_enc_get but for an arbitrary
 * :method (GET, HEAD, POST, ...); :scheme stays https. Returns 1 with
 * out->len set, 0 on overflow. */
int quic_h3req_enc_method(
    quic_span method, const quic_h3req_headers_in *in, quic_obuf *out);

#endif
