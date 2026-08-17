#include "app/webtransport/capsule/wtcapsule/wtcapsule.h"

#include "app/http3/core/capsule/capsule.h"
#include "common/bytes/util/be.h"
#include "common/bytes/varint/varint.h"

#define QUIC_WTCAPSULE_TYPE_CLOSE 0x2843ULL
#define QUIC_WTCAPSULE_TYPE_DRAIN 0x78aeULL
#define QUIC_WTCAPSULE_CLOSE_CODE_LEN 4

/* draft-ietf-webtrans-http3-15 SS9.6: session-level flow-control capsule
 * types, each body a single varint. */
#define QUIC_WTCAPSULE_TYPE_MAX_STREAMS_BIDI 0x190B4D3FULL
#define QUIC_WTCAPSULE_TYPE_MAX_STREAMS_UNI 0x190B4D40ULL
#define QUIC_WTCAPSULE_TYPE_STREAMS_BLOCKED_BIDI 0x190B4D43ULL
#define QUIC_WTCAPSULE_TYPE_STREAMS_BLOCKED_UNI 0x190B4D44ULL
#define QUIC_WTCAPSULE_TYPE_MAX_DATA 0x190B4D3DULL
#define QUIC_WTCAPSULE_TYPE_DATA_BLOCKED 0x190B4D41ULL

/* type for the bidi/uni variant of a two-type capsule family (MAX_STREAMS,
 * STREAMS_BLOCKED). */
static u64 wtcapsule_dir_type(int bidi, u64 bidi_type, u64 uni_type) {
  return bidi ? bidi_type : uni_type;
}

/* Encode a capsule whose entire body is one varint (RFC 9000 SS16: a varint
 * is at most 8 bytes). */
static int wtcapsule_encode_varint(wired_obuf* out, u64 type, u64 v) {
  u8  body[8];
  usz off = 0;
  if (!varint_put(wired_mspan_of(body, sizeof body), &off, v)) return 0;
  return capsule_encode(out, type, wired_span_of(body, off));
}

/* 1 iff got_type/value is a well-formed single-varint capsule of exactly
 * `type`: the right type, and a body that is exactly one varint (fully
 * consumed, no trailing bytes). The well-formedness check shared by every
 * capsule in this file whose body is a single varint. */
static int wtcapsule_is_sole_varint(
    u64 got_type, u64 type, wired_span value, u64* v) {
  usz voff = 0;
  if (got_type != type) return 0;
  return varint_take(value, &voff, v) && voff == value.n;
}

/* Decode a capsule of exactly `type`, whose entire body is one varint.
 * Same "wrong type/incomplete, don't consume" contract as the other
 * decode_* functions in this file. */
static int wtcapsule_decode_varint(wired_span data, usz* at, u64 type, u64* v) {
  usz        local_at = *at;
  u64        got_type;
  wired_span value;
  if (!capsule_decode(data, &local_at, &got_type, &value)) return 0;
  if (!wtcapsule_is_sole_varint(got_type, type, value, v)) return 0;
  *at = local_at;
  return 1;
}

int wired_wtcapsule_encode_close(
    wired_obuf* out, u32 app_error_code, wired_span message) {
  u8  body[QUIC_WTCAPSULE_CLOSE_CODE_LEN + QUIC_WTCAPSULE_CLOSE_MESSAGE_MAX];
  usz i;
  if (message.n > QUIC_WTCAPSULE_CLOSE_MESSAGE_MAX) return 0;
  be_put_be32(body, app_error_code);
  for (i = 0; i < message.n; i++)
    body[QUIC_WTCAPSULE_CLOSE_CODE_LEN + i] = message.p[i];
  return capsule_encode(
      out, QUIC_WTCAPSULE_TYPE_CLOSE,
      wired_span_of(body, QUIC_WTCAPSULE_CLOSE_CODE_LEN + message.n));
}

int wtcapsule_encode_drain(wired_obuf* out) {
  return capsule_encode(out, QUIC_WTCAPSULE_TYPE_DRAIN, wired_span_of(0, 0));
}

/* 1 iff type/value is a well-formed WT_CLOSE_SESSION capsule: the right
 * type, long enough for the 32-bit error code, and its message within the
 * WT-level cap. */
static int wtcapsule_is_close(u64 type, wired_span value) {
  return type == QUIC_WTCAPSULE_TYPE_CLOSE &&
         value.n >= QUIC_WTCAPSULE_CLOSE_CODE_LEN &&
         value.n - QUIC_WTCAPSULE_CLOSE_CODE_LEN <=
             QUIC_WTCAPSULE_CLOSE_MESSAGE_MAX;
}

/* Split out of wired_wtcapsule_decode_close to keep it at CCN<=3: this
 * unconditionally reads app_error_code/message out of an already-validated
 * WT_CLOSE_SESSION value. */
static void wtcapsule_take_close(
    wired_span value, u32* app_error_code, wired_span* message) {
  *app_error_code = be_get_be32(value.p);
  *message        = wired_span_of(
      value.p + QUIC_WTCAPSULE_CLOSE_CODE_LEN,
      value.n - QUIC_WTCAPSULE_CLOSE_CODE_LEN);
}

int wired_wtcapsule_decode_close(
    wired_span data, usz* at, u32* app_error_code, wired_span* message) {
  usz        local_at = *at;
  u64        type;
  wired_span value;
  if (!capsule_decode(data, &local_at, &type, &value)) return 0;
  if (!wtcapsule_is_close(type, value)) return 0;
  wtcapsule_take_close(value, app_error_code, message);
  *at = local_at;
  return 1;
}

int wtcapsule_decode_drain(wired_span data, usz* at) {
  usz        local_at = *at;
  u64        type;
  wired_span value;
  if (!capsule_decode(data, &local_at, &type, &value)) return 0;
  if (type != QUIC_WTCAPSULE_TYPE_DRAIN) return 0;
  *at = local_at;
  return 1;
}

int wtcapsule_encode_max_streams(wired_obuf* out, int bidi, u64 max_streams) {
  u64 type = wtcapsule_dir_type(
      bidi, QUIC_WTCAPSULE_TYPE_MAX_STREAMS_BIDI,
      QUIC_WTCAPSULE_TYPE_MAX_STREAMS_UNI);
  return wtcapsule_encode_varint(out, type, max_streams);
}

int wtcapsule_decode_max_streams(
    wired_span data, usz* at, int bidi, u64* max_streams) {
  u64 type = wtcapsule_dir_type(
      bidi, QUIC_WTCAPSULE_TYPE_MAX_STREAMS_BIDI,
      QUIC_WTCAPSULE_TYPE_MAX_STREAMS_UNI);
  return wtcapsule_decode_varint(data, at, type, max_streams);
}

int wtcapsule_encode_streams_blocked(
    wired_obuf* out, int bidi, u64 max_streams) {
  u64 type = wtcapsule_dir_type(
      bidi, QUIC_WTCAPSULE_TYPE_STREAMS_BLOCKED_BIDI,
      QUIC_WTCAPSULE_TYPE_STREAMS_BLOCKED_UNI);
  return wtcapsule_encode_varint(out, type, max_streams);
}

int wtcapsule_decode_streams_blocked(
    wired_span data, usz* at, int bidi, u64* max_streams) {
  u64 type = wtcapsule_dir_type(
      bidi, QUIC_WTCAPSULE_TYPE_STREAMS_BLOCKED_BIDI,
      QUIC_WTCAPSULE_TYPE_STREAMS_BLOCKED_UNI);
  return wtcapsule_decode_varint(data, at, type, max_streams);
}

int wtcapsule_encode_max_data(wired_obuf* out, u64 max_data) {
  return wtcapsule_encode_varint(out, QUIC_WTCAPSULE_TYPE_MAX_DATA, max_data);
}

int wtcapsule_decode_max_data(wired_span data, usz* at, u64* max_data) {
  return wtcapsule_decode_varint(
      data, at, QUIC_WTCAPSULE_TYPE_MAX_DATA, max_data);
}

int wtcapsule_encode_data_blocked(wired_obuf* out, u64 max_data) {
  return wtcapsule_encode_varint(
      out, QUIC_WTCAPSULE_TYPE_DATA_BLOCKED, max_data);
}

int wtcapsule_decode_data_blocked(wired_span data, usz* at, u64* max_data) {
  return wtcapsule_decode_varint(
      data, at, QUIC_WTCAPSULE_TYPE_DATA_BLOCKED, max_data);
}
