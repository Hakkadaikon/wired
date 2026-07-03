#ifndef QUIC_H3REQENC_HEADER_ENCODE_H
#define QUIC_H3REQENC_HEADER_ENCODE_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9204 4.5.6. Encode one ordinary request header (e.g. user-agent) as a
 * single Literal Field Line With Literal Name (raw name, raw value, not marked
 * never-indexed). No field section prefix is emitted (the caller assembles
 * prefix + lines). Returns 1 with out->len set, 0 if out lacks capacity. */
int quic_h3req_enc_header(quic_span name, quic_span value, quic_obuf *out);

#endif
