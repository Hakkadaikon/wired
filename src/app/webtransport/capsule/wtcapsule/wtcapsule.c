#include "app/webtransport/capsule/wtcapsule/wtcapsule.h"

#include "app/http3/core/capsule/capsule.h"
#include "common/bytes/util/be.h"
#include "common/bytes/varint/varint.h"

/* draft-ietf-webtrans-http3-15 SS9.6: WT_STREAMS_BLOCKED's two directions
 * are public now (wtcapsule.h: a receiver, srvrun.c, must recognize the type
 * to apply -16's 2^60 ceiling check even though it applies no state).
 * WT_DATA_BLOCKED stays file-local: nothing outside this codec dispatches
 * on it. */
#define WTCAPSULE_TYPE_DATA_BLOCKED 0x190B4D41ULL

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

int wtcapsule_value_varint(wired_span value, u64* v) {
  usz voff = 0;
  return varint_take(value, &voff, v) && voff == value.n;
}

/* 1 iff got_type/value is a well-formed single-varint capsule of exactly
 * `type`: the right type, and a body that is exactly one varint (fully
 * consumed, no trailing bytes) -- wtcapsule_value_varint, the
 * well-formedness check shared by every capsule whose body is a single
 * varint. */
static int wtcapsule_is_sole_varint(
    u64 got_type, u64 type, wired_span value, u64* v) {
  if (got_type != type) return 0;
  return wtcapsule_value_varint(value, v);
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
  u8  body[WTCAPSULE_CLOSE_CODE_LEN + WTCAPSULE_CLOSE_MESSAGE_MAX];
  usz i;
  if (message.n > WTCAPSULE_CLOSE_MESSAGE_MAX) return 0;
  be_put_be32(body, app_error_code);
  for (i = 0; i < message.n; i++)
    body[WTCAPSULE_CLOSE_CODE_LEN + i] = message.p[i];
  return capsule_encode(
      out, WTCAPSULE_TYPE_CLOSE,
      wired_span_of(body, WTCAPSULE_CLOSE_CODE_LEN + message.n));
}

int wtcapsule_encode_drain(wired_obuf* out) {
  return capsule_encode(out, WTCAPSULE_TYPE_DRAIN, wired_span_of(0, 0));
}

/* 1 iff type/value is a well-formed WT_CLOSE_SESSION capsule: the right
 * type, long enough for the 32-bit error code, and its message within the
 * WT-level cap. */
static int wtcapsule_is_close(u64 type, wired_span value) {
  return type == WTCAPSULE_TYPE_CLOSE && value.n >= WTCAPSULE_CLOSE_CODE_LEN &&
         value.n - WTCAPSULE_CLOSE_CODE_LEN <= WTCAPSULE_CLOSE_MESSAGE_MAX;
}

/* Split out of wired_wtcapsule_decode_close to keep it at CCN<=3: this
 * unconditionally reads app_error_code/message out of an already-validated
 * WT_CLOSE_SESSION value. */
static void wtcapsule_take_close(
    wired_span value, u32* app_error_code, wired_span* message) {
  *app_error_code = be_get_be32(value.p);
  *message        = wired_span_of(
      value.p + WTCAPSULE_CLOSE_CODE_LEN, value.n - WTCAPSULE_CLOSE_CODE_LEN);
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
  if (type != WTCAPSULE_TYPE_DRAIN) return 0;
  *at = local_at;
  return 1;
}

int wtcapsule_encode_max_streams(wired_obuf* out, int bidi, u64 max_streams) {
  u64 type = wtcapsule_dir_type(
      bidi, WTCAPSULE_TYPE_MAX_STREAMS_BIDI, WTCAPSULE_TYPE_MAX_STREAMS_UNI);
  return wtcapsule_encode_varint(out, type, max_streams);
}

int wtcapsule_decode_max_streams(
    wired_span data, usz* at, int bidi, u64* max_streams) {
  u64 type = wtcapsule_dir_type(
      bidi, WTCAPSULE_TYPE_MAX_STREAMS_BIDI, WTCAPSULE_TYPE_MAX_STREAMS_UNI);
  return wtcapsule_decode_varint(data, at, type, max_streams);
}

int wtcapsule_encode_streams_blocked(
    wired_obuf* out, int bidi, u64 max_streams) {
  u64 type = wtcapsule_dir_type(
      bidi, WTCAPSULE_TYPE_STREAMS_BLOCKED_BIDI,
      WTCAPSULE_TYPE_STREAMS_BLOCKED_UNI);
  return wtcapsule_encode_varint(out, type, max_streams);
}

int wtcapsule_decode_streams_blocked(
    wired_span data, usz* at, int bidi, u64* max_streams) {
  u64 type = wtcapsule_dir_type(
      bidi, WTCAPSULE_TYPE_STREAMS_BLOCKED_BIDI,
      WTCAPSULE_TYPE_STREAMS_BLOCKED_UNI);
  return wtcapsule_decode_varint(data, at, type, max_streams);
}

int wtcapsule_encode_max_data(wired_obuf* out, u64 max_data) {
  return wtcapsule_encode_varint(out, WTCAPSULE_TYPE_MAX_DATA, max_data);
}

int wtcapsule_decode_max_data(wired_span data, usz* at, u64* max_data) {
  return wtcapsule_decode_varint(data, at, WTCAPSULE_TYPE_MAX_DATA, max_data);
}

int wtcapsule_encode_data_blocked(wired_obuf* out, u64 max_data) {
  return wtcapsule_encode_varint(out, WTCAPSULE_TYPE_DATA_BLOCKED, max_data);
}

int wtcapsule_decode_data_blocked(wired_span data, usz* at, u64* max_data) {
  return wtcapsule_decode_varint(
      data, at, WTCAPSULE_TYPE_DATA_BLOCKED, max_data);
}

/* RFC 3629 SS3: byte length of a 3- or 4-byte lead, 0 if lead (already
 * known to be >= 0xE0, utf8_multibyte_len's own check) encodes past
 * U+10FFFF -- split out purely to keep each caller's branch count at the
 * CCN gate. */
static usz utf8_long_seq_len(u8 lead) {
  if (lead < 0xF0) return 3;
  return lead < 0xF5 ? 4 : 0;
}

/* RFC 3629 SS3: byte length of a 2/3/4-byte lead, 0 if lead (already known
 * to be >= 0x80, utf8_seq_len's own check) is a continuation byte or an
 * overlong C0/C1 lead. */
static usz utf8_multibyte_len(u8 lead) {
  if (lead < 0xC2) return 0;
  return lead < 0xE0 ? 2 : utf8_long_seq_len(lead);
}

/* RFC 3629 SS3: byte length of the UTF-8 sequence lead starts, 0 if lead is
 * not a valid lead byte at all. */
static usz utf8_seq_len(u8 lead) {
  return lead < 0x80 ? 1 : utf8_multibyte_len(lead);
}

/* 1 iff msg[i+1 .. i+n-1] are all continuation bytes (0x80-0xBF) -- the
 * generic shape check every multi-byte sequence needs regardless of length,
 * so utf8_valid_at itself only branches on the sequence-specific rules. */
static int utf8_continuation_byte_ok(const u8* p, usz k) {
  return (p[k] & 0xC0) == 0x80;
}

/* 1 iff every one of n-1 continuation bytes starting right after lead p[0]
 * is well-formed -- the bytes-in-range half of utf8_continuations_ok,
 * split out so the "does the sequence even fit" bounds check stays its own
 * branch. */
static int utf8_continuations_shaped(const u8* p, usz n) {
  for (usz k = 1; k < n; k++)
    if (!utf8_continuation_byte_ok(p, k)) return 0;
  return 1;
}

static int utf8_continuations_ok(wired_span msg, usz i, usz n) {
  if (i + n > msg.n) return 0;
  return utf8_continuations_shaped(msg.p + i, n);
}

/* RFC 3629 SS3: reject the two shapes that are structurally 2/3-byte
 * sequences but never valid scalar values -- an overlong 2-byte sequence
 * (lead 0xC0/0xC1, already excluded by utf8_seq_len) is impossible here, so
 * the remaining disallowed shapes are a 3-byte lead 0xE0 whose second byte
 * is an overlong continuation (< 0xA0), and the UTF-16 surrogate range
 * (lead 0xED, second byte 0xA0-0xBF). */
static int utf8_3byte_shape_ok(const u8* p) {
  if (p[0] == 0xE0) return p[1] >= 0xA0;
  if (p[0] == 0xED) return p[1] < 0xA0;
  return 1;
}

/* RFC 3629 SS3: a 4-byte lead's second byte must stay within the Unicode
 * range -- 0xF0 forbids an overlong second byte (< 0x90), and 0xF4 forbids
 * one that would reach past U+10FFFF (>= 0x90). */
static int utf8_4byte_shape_ok(const u8* p) {
  if (p[0] == 0xF0) return p[1] >= 0x90;
  if (p[0] == 0xF4) return p[1] < 0x90;
  return 1;
}

/* RFC 3629 SS3: the overlong/surrogate/out-of-range exclusions only a 3- or
 * 4-byte lead can violate (a 1- or 2-byte sequence has no such exclusion
 * left once utf8_seq_len already rejected an overlong C0/C1 lead). */
static int utf8_shape_ok(const u8* p, usz n) {
  if (n == 3) return utf8_3byte_shape_ok(p);
  return n == 4 ? utf8_4byte_shape_ok(p) : 1;
}

/* 1 iff the sequence of length n starting at msg[i] is shaped correctly per
 * RFC 3629 SS3. */
static int utf8_valid_at(wired_span msg, usz i, usz n) {
  return utf8_continuations_ok(msg, i, n) && utf8_shape_ok(msg.p + i, n);
}

/* 1 iff msg[i] starts a sequence this SDK accepts -- the one point where a
 * zero-length-or-invalid sequence turns into a reject, split out so the
 * scanning loop itself carries only the loop condition. */
static int utf8_at_ok(wired_span msg, usz i, usz* n) {
  *n = utf8_seq_len(msg.p[i]);
  return *n && utf8_valid_at(msg, i, *n);
}

int wtcapsule_utf8_valid(wired_span msg) {
  usz i = 0, n;
  while (i < msg.n && utf8_at_ok(msg, i, &n)) i += n;
  return i == msg.n;
}

/* 1 iff the sequence starting at msg[i] still fits before cap. A byte that
 * starts no sequence (seq_len 0) also stops the scan there, so an invalid
 * byte ends the prefix instead of looping forever. */
static int utf8_seq_fits(wired_span msg, usz i, usz cap, usz* n) {
  *n = utf8_seq_len(msg.p[i]);
  return *n && i + *n <= cap;
}

/* The scan loop itself, once cap is already known to be the shorter bound
 * (cap < msg.n) -- split out so wtcapsule_utf8_truncate_len's own early
 * "no truncation needed" return stays its only other branch (CCN). */
static usz utf8_truncate_scan(wired_span msg, usz cap) {
  usz i = 0, n;
  while (i < cap && utf8_seq_fits(msg, i, cap, &n)) i += n;
  return i;
}

usz wtcapsule_utf8_truncate_len(wired_span msg, usz cap) {
  return cap >= msg.n ? msg.n : utf8_truncate_scan(msg, cap);
}
