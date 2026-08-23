#ifndef H3RESP_FIELD_ENCODE_H
#define H3RESP_FIELD_ENCODE_H

#include "app/qpack/qpack/field.h"
#include "app/qpack/qpackenc/qpackenc.h"
#include "app/qpack/qpackenc/status_line.h"
#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9204 4.5. Encode a response field section: the Encoded Field Section
 * Prefix (Required Insert Count 0, Base 0, no dynamic table), the :status
 * field line, then, when content_type is non-null, a content-type field
 * line. Each field is Indexed when its (name, value) pair exists in the
 * static table, else a Literal Field Line referencing the static name.
 * content_type == 0 emits only :status. Returns 1 with out->len set, 0 if
 * out lacks capacity. */
int h3resp_encode_headers(
    u16 status, const char* content_type, wired_obuf* out);

/* Same as h3resp_encode_headers plus, when extra is non-null, one
 * trailing Literal Field Line With Literal Name (RFC 9204 4.5.6) carrying
 * extra's (name, value) verbatim -- e.g. the wt-protocol response header of
 * WebTransport subprotocol negotiation. extra == 0 behaves identically to
 * h3resp_encode_headers. Returns 1 with out->len set, 0 if out lacks
 * capacity. */
int h3resp_encode_headers_field(
    u16                status,
    const char*        content_type,
    const qpack_field* extra,
    wired_obuf*        out);

/* Same as h3resp_encode_headers_field, but :status is encoded through
 * qenc's dynamic table (qpackenc_status_line) instead of the static-or-
 * literal-only path -- the Prefix's Required Insert Count reflects the
 * outcome. qenc == 0 behaves exactly as h3resp_encode_headers_field.
 * *insert_out (caller-owned scratch, never null) receives the qpackenc
 * result the :status line was built from -- insert_out->insert_len > 0
 * means a fresh Insert instruction must be sent on the QPACK encoder
 * stream (RFC 9204 4.3.3) and qpackenc_note_sent called once it is.
 * Returns 1 with out->len set, 0 if out lacks capacity. */
int h3resp_encode_headers_field_qenc(
    u16                     status,
    const char*             content_type,
    const qpack_field*      extra,
    qpackenc_state*         qenc,
    qpackenc_status_result* insert_out,
    wired_obuf*             out);

#endif
