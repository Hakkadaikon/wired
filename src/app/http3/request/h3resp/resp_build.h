#ifndef QUIC_H3RESP_RESP_BUILD_H
#define QUIC_H3RESP_RESP_BUILD_H

#include "app/qpack/qpack/field.h"
#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9114 4.1. Assemble a response stream byte sequence: a HEADERS frame
 * carrying the QPACK-encoded :status (plus a content-type field line when
 * content_type is non-null) field section, followed by a DATA frame carrying
 * the body. When body is empty only the HEADERS frame is emitted. Returns 1
 * with out->len set on success, 0 if out lacks capacity. */
int quic_h3resp_build(
    u16 status, const char* content_type, quic_span body, quic_obuf* out);

/* RFC 9114 4.1 / 7.1: the response prefix alone — the HEADERS frame plus the
 * DATA frame header (type + length varints, no payload bytes) for a body of
 * body_len bytes already sitting elsewhere. body_len 0 emits HEADERS only.
 * Returns 1 with out->len set, 0 if out lacks capacity. */
int quic_h3resp_prefix(
    u16 status, const char* content_type, u64 body_len, quic_obuf* out);

/* Same as quic_h3resp_prefix plus, when extra is non-null, one trailing
 * Literal Field Line With Literal Name (RFC 9204 4.5.6) in the HEADERS
 * frame's field section carrying extra's (name, value) verbatim -- e.g. the
 * wt-protocol response header of WebTransport subprotocol negotiation.
 * extra == 0 behaves identically to quic_h3resp_prefix. Returns 1 with
 * out->len set, 0 if out lacks capacity. */
int quic_h3resp_prefix_field(
    u16                     status,
    const char*             content_type,
    u64                     body_len,
    const quic_qpack_field* extra,
    quic_obuf*              out);

#endif
