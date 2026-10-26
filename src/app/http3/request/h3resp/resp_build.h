#ifndef H3RESP_RESP_BUILD_H
#define H3RESP_RESP_BUILD_H

#include "app/qpack/qpack/field.h"
#include "app/qpack/qpackenc/qpackenc.h"
#include "app/qpack/qpackenc/status_line.h"
#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* Largest field section a response prefix encodes: srvrun's header room
 * (SRVRUN_RESP_HDR_ROOM, sized from the same budget). */
#define H3RESP_FIELD_SECTION_MAX 640

/* RFC 9114 4.1. Assemble a response stream byte sequence: a HEADERS frame
 * carrying the QPACK-encoded :status (plus a content-type field line when
 * content_type is non-null) field section, followed by a DATA frame carrying
 * the body. When body is empty only the HEADERS frame is emitted. Returns 1
 * with out->len set on success, 0 if out lacks capacity. */
int h3resp_build(
    u16 status, const char* content_type, wired_span body, wired_obuf* out);

/* RFC 9114 4.1 / 7.1: the response prefix alone — the HEADERS frame plus the
 * DATA frame header (type + length varints, no payload bytes) for a body of
 * body_len bytes already sitting elsewhere. body_len 0 emits HEADERS only.
 * Returns 1 with out->len set, 0 if out lacks capacity. */
int h3resp_prefix(
    u16 status, const char* content_type, u64 body_len, wired_obuf* out);

/* Same as h3resp_prefix plus, when extra is non-null, one trailing
 * Literal Field Line With Literal Name (RFC 9204 4.5.6) in the HEADERS
 * frame's field section carrying extra's (name, value) verbatim -- e.g. the
 * wt-protocol response header of WebTransport subprotocol negotiation.
 * extra == 0 behaves identically to h3resp_prefix. Returns 1 with
 * out->len set, 0 if out lacks capacity. */
int h3resp_prefix_field(
    u16                status,
    const char*        content_type,
    u64                body_len,
    const qpack_field* extra,
    wired_obuf*        out);

/* Same as h3resp_prefix_field, but :status is encoded through qenc's
 * dynamic table (RFC 9204 4.5.1's Required Insert Count reflects the
 * outcome) instead of the static-or-literal-only path. qenc == 0 behaves
 * identically to h3resp_prefix_field. *insert_out (caller-owned scratch,
 * never null) receives any pending encoder-stream instruction the :status
 * line generated -- insert_out->insert_len > 0 means a fresh Insert
 * instruction must be sent on the QPACK encoder stream (RFC 9204 4.3.3) and
 * qpackenc_note_sent called once it is; always 0 when qenc == 0. Returns 1
 * with out->len set, 0 if out lacks capacity. */
int h3resp_prefix_field_qenc(
    u16                     status,
    const char*             content_type,
    u64                     body_len,
    const qpack_field*      extra,
    qpackenc_state*         qenc,
    qpackenc_status_result* insert_out,
    wired_obuf*             out);

/* A list of response fields: p[0..n). */
typedef struct {
  const qpack_field* p;
  usz                n;
} h3resp_fields;

/* Same as h3resp_prefix_field_qenc, but with extra.n trailing Literal
 * Field Lines With Literal Name (RFC 9204 4.5.6), one per entry of
 * extra.p[0..extra.n), in order -- e.g. an application's own response
 * headers. extra.n == 0 adds none. Returns 1 with out->len set, 0 if out
 * lacks capacity. */
int h3resp_prefix_fields_qenc(
    u16                     status,
    const char*             content_type,
    u64                     body_len,
    h3resp_fields           extra,
    qpackenc_state*         qenc,
    qpackenc_status_result* insert_out,
    wired_obuf*             out);

#endif
