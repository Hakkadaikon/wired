#ifndef QUIC_H3RESP_FIELD_ENCODE_H
#define QUIC_H3RESP_FIELD_ENCODE_H

#include "app/qpack/qpack/field.h"
#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9204 4.5. Encode a response field section: the Encoded Field Section
 * Prefix (Required Insert Count 0, Base 0, no dynamic table), the :status
 * field line, then, when content_type is non-null, a content-type field
 * line. Each field is Indexed when its (name, value) pair exists in the
 * static table, else a Literal Field Line referencing the static name.
 * content_type == 0 emits only :status. Returns 1 with out->len set, 0 if
 * out lacks capacity. */
int quic_h3resp_encode_headers(
    u16 status, const char* content_type, quic_obuf* out);

/* Same as quic_h3resp_encode_headers plus, when extra is non-null, one
 * trailing Literal Field Line With Literal Name (RFC 9204 4.5.6) carrying
 * extra's (name, value) verbatim -- e.g. the wt-protocol response header of
 * WebTransport subprotocol negotiation. extra == 0 behaves identically to
 * quic_h3resp_encode_headers. Returns 1 with out->len set, 0 if out lacks
 * capacity. */
int quic_h3resp_encode_headers_field(
    u16                     status,
    const char*             content_type,
    const quic_qpack_field* extra,
    quic_obuf*              out);

#endif
