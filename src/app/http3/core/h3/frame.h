#ifndef QUIC_H3_FRAME_H
#define QUIC_H3_FRAME_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9114 7.2. HTTP/3 frame: Type (varint) Length (varint) Payload.
 * DATA, HEADERS and PUSH_PROMISE carry opaque payload bytes (HEADERS holds a
 * QPACK-encoded field section; the QPACK dynamic table of RFC 9204 is out of
 * scope here, so the field block is passed through verbatim). */

#define QUIC_H3_FRAME_DATA 0x00
#define QUIC_H3_FRAME_HEADERS 0x01
#define QUIC_H3_FRAME_CANCEL_PUSH 0x03
#define QUIC_H3_FRAME_SETTINGS 0x04
#define QUIC_H3_FRAME_PUSH_PROMISE 0x05
#define QUIC_H3_FRAME_GOAWAY 0x07
#define QUIC_H3_FRAME_MAX_PUSH_ID 0x0d

/* RFC 9114 6.2 unidirectional stream types. */
#define QUIC_H3_STREAM_CONTROL 0x00
#define QUIC_H3_STREAM_PUSH 0x01
#define QUIC_H3_STREAM_QPACK_ENCODER 0x02
#define QUIC_H3_STREAM_QPACK_DECODER 0x03

/* draft-ietf-webtrans-http3-15 4.3: WebTransport unidirectional stream. */
#define QUIC_H3_STREAM_WEBTRANSPORT 0x54

/* draft-ietf-webtrans-http3-15 4.3: the WT_STREAM signal a WebTransport bidi
 * stream (client- or server-initiated) MUST send as the varint-encoded value
 * of its very first bytes, before any application data. 65 exceeds the 1-byte
 * varint range (RFC 9000 16, max 0x3F), so on the wire it is the 2-byte
 * encoding {0x40, 0x41} — decode with varint_take/varint_decode,
 * never compare a raw leading byte to 0x41. */
#define QUIC_H3_STREAM_WEBTRANSPORT_BIDI 0x41

/* RFC 9114 8.1 error codes. */
#define QUIC_H3_NO_ERROR 0x0100
#define QUIC_H3_GENERAL_PROTOCOL_ERROR 0x0101
#define QUIC_H3_INTERNAL_ERROR 0x0102
#define QUIC_H3_STREAM_CREATION_ERROR 0x0103
#define QUIC_H3_CLOSED_CRITICAL_STREAM 0x0104
#define QUIC_H3_FRAME_UNEXPECTED 0x0105
#define QUIC_H3_FRAME_ERROR 0x0106
#define QUIC_H3_EXCESSIVE_LOAD 0x0107
#define QUIC_H3_ID_ERROR 0x0108
#define QUIC_H3_SETTINGS_ERROR 0x0109
#define QUIC_H3_MISSING_SETTINGS 0x010a
#define QUIC_H3_REQUEST_REJECTED 0x010b
#define QUIC_H3_REQUEST_CANCELLED 0x010c
#define QUIC_H3_REQUEST_INCOMPLETE 0x010d
#define QUIC_H3_MESSAGE_ERROR 0x010e
#define QUIC_H3_CONNECT_ERROR 0x010f
#define QUIC_H3_VERSION_FALLBACK 0x0110

/* RFC 9297 2.1: an HTTP/3 connection error for a malformed or out-of-range
 * HTTP Datagram Quarter Stream ID. */
#define QUIC_H3_DATAGRAM_ERROR 0x33

/* RFC 9114 7.2.4.1 SETTINGS parameter. */
#define QUIC_H3_SETTINGS_MAX_FIELD_SECTION_SIZE 0x06

/* 11 defined pairs this SDK ever builds (MAX_FIELD_SECTION_SIZE, QPACK's
 * two, ENABLE_CONNECT_PROTOCOL, H3_DATAGRAM, WebTransport session-negotiation
 * three, WebTransport flow-control three -- draft-ietf-webtrans-http3-15
 * 5.5's SETTINGS_WT_INITIAL_MAX_STREAMS_UNI/BIDI/MAX_DATA) plus one slot for
 * an optional grease identifier (RFC 9114 7.2.4.1 / 9114-064,
 * h3settings_build's append_grease). */
#define QUIC_H3_SETTINGS_MAX 12

/** RFC 9114 7.2.4: a SETTINGS frame's payload, as decoded (Identifier,
 * Value) pairs. */
typedef struct {
  usz n;
  struct {
    u64 id;
    u64 value;
  } pairs[QUIC_H3_SETTINGS_MAX];
} h3_settings;

/** RFC 9114 7.2 decoded frame head + payload view (payload borrowed in
 * place, no copy). */
typedef struct {
  u64       type;
  const u8* payload;
  u64       payload_len;
} h3_frame;

/* Generic frame (Type Length Payload). Encode returns bytes written or 0;
 * decode returns bytes consumed or 0 and views payload in place (no copy). */
usz h3_frame_put(wired_obuf* out, u64 type, wired_span payload);
usz h3_frame_get(wired_span buf, h3_frame* f);

/* Single-varint-payload frames: CANCEL_PUSH / MAX_PUSH_ID carry a Push ID,
 * GOAWAY carries a Stream ID or Push ID. */
usz h3_cancel_push_put(u8* buf, usz cap, u64 push_id);
usz h3_cancel_push_get(const u8* buf, usz n, u64* push_id);
usz h3_goaway_put(u8* buf, usz cap, u64 id);
usz h3_goaway_get(const u8* buf, usz n, u64* id);
usz h3_max_push_id_put(u8* buf, usz cap, u64 push_id);
usz h3_max_push_id_get(const u8* buf, usz n, u64* push_id);

/* SETTINGS: payload is a sequence of (Identifier Value) varint pairs. */
usz h3_settings_put(u8* buf, usz cap, const h3_settings* s);
usz h3_settings_get(const u8* buf, usz n, h3_settings* s);

#endif
