#ifndef QUIC_H3REQENC_REQUEST_HEADERS_H
#define QUIC_H3REQENC_REQUEST_HEADERS_H

#include "sys/syscall.h"

/* RFC 9114 4.3.1 / RFC 9204 4.5. Build the complete QPACK field section for a
 * GET request: the empty field section prefix followed by the four request
 * pseudo-headers in the order :method, :scheme, :authority, :path with
 * :method = GET and :scheme = https. The given authority and path become the
 * :authority and :path values. Returns 1 with *out_len set, 0 on overflow. */
int quic_h3req_enc_get(const u8 *path, usz p_len, const u8 *authority,
                       usz a_len, u8 *out, usz cap, usz *out_len);

#endif
