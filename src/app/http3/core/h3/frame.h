#ifndef QUIC_H3_FRAME_H
#define QUIC_H3_FRAME_H

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

/* RFC 9114 7.2.4.1 SETTINGS parameter. */
#define QUIC_H3_SETTINGS_MAX_FIELD_SECTION_SIZE 0x06

#define QUIC_H3_SETTINGS_MAX 8

typedef struct {
  usz n;
  struct {
    u64 id;
    u64 value;
  } pairs[QUIC_H3_SETTINGS_MAX];
} quic_h3_settings;

/* Generic frame (Type Length Payload). Encode returns bytes written or 0;
 * decode returns bytes consumed or 0 and views payload in place (no copy). */
usz quic_h3_frame_put(
    u8 *buf, usz cap, u64 type, const u8 *payload, usz payload_len);
usz quic_h3_frame_get(
    const u8 *buf, usz n, u64 *type, const u8 **payload, u64 *payload_len);

/* Single-varint-payload frames: CANCEL_PUSH / MAX_PUSH_ID carry a Push ID,
 * GOAWAY carries a Stream ID or Push ID. */
usz quic_h3_cancel_push_put(u8 *buf, usz cap, u64 push_id);
usz quic_h3_cancel_push_get(const u8 *buf, usz n, u64 *push_id);
usz quic_h3_goaway_put(u8 *buf, usz cap, u64 id);
usz quic_h3_goaway_get(const u8 *buf, usz n, u64 *id);
usz quic_h3_max_push_id_put(u8 *buf, usz cap, u64 push_id);
usz quic_h3_max_push_id_get(const u8 *buf, usz n, u64 *push_id);

/* SETTINGS: payload is a sequence of (Identifier Value) varint pairs. */
usz quic_h3_settings_put(u8 *buf, usz cap, const quic_h3_settings *s);
usz quic_h3_settings_get(const u8 *buf, usz n, quic_h3_settings *s);

#endif
