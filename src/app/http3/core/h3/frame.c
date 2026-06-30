#include "app/http3/core/h3/frame.h"

#include "common/bytes/util/bytes.h"
#include "common/bytes/varint/varint.h"

/* Write Type then Length (two varints). Returns 1 ok, 0 on overflow. */
static int put_head(u8 *buf, usz cap, usz *off, u64 type, u64 len) {
  if (!quic_varint_put(buf, cap, off, type)) return 0;
  return quic_varint_put(buf, cap, off, len);
}

usz quic_h3_frame_put(
    u8 *buf, usz cap, u64 type, const u8 *payload, usz payload_len) {
  usz off = 0;
  if (!put_head(buf, cap, &off, type, payload_len)) return 0;
  if (!quic_put_bytes(buf, cap, &off, payload, payload_len)) return 0;
  return off;
}

/* Read Type then Length (two varints). Returns 1 ok, 0 if truncated. */
static int get_head(const u8 *buf, usz n, usz *off, u64 *type, u64 *len) {
  if (!quic_varint_take(buf, n, off, type)) return 0;
  return quic_varint_take(buf, n, off, len);
}

usz quic_h3_frame_get(
    const u8 *buf, usz n, u64 *type, const u8 **payload, u64 *payload_len) {
  usz off = 0;
  if (!get_head(buf, n, &off, type, payload_len)) return 0;
  if (off + *payload_len > n) return 0;
  *payload = buf + off;
  return off + *payload_len;
}

/* Encode a frame whose entire payload is a single varint (CANCEL_PUSH,
 * GOAWAY, MAX_PUSH_ID). Writes type, length, then the value varint. */
static usz put_one(u8 *buf, usz cap, u64 type, u64 v) {
  usz off = 0;
  if (!put_head(buf, cap, &off, type, quic_varint_len(v))) return 0;
  if (!quic_varint_put(buf, cap, &off, v)) return 0;
  return off;
}

/* Read the head of a single-varint frame and require the type. On success
 * *len holds the Length field. Returns 1 ok, 0 bad. */
static int get_one_head(
    const u8 *buf, usz n, usz *off, u64 want_type, u64 *len) {
  u64 type;
  if (!get_head(buf, n, off, &type, len)) return 0;
  return type == want_type;
}

/* Read the single varint value and require it to exactly fill len bytes.
 * On success advances *off past the value. Returns 1 ok, 0 bad. */
static int get_one_body(const u8 *buf, usz n, usz *off, u64 len, u64 *v) {
  usz vstart = *off;
  if (!quic_varint_take(buf, n, off, v)) return 0;
  return *off - vstart == len;
}

/* Decode a frame of expected type whose payload is a single varint. The
 * Length field must exactly cover that varint. Returns bytes consumed or 0. */
static usz get_one(const u8 *buf, usz n, u64 want_type, u64 *v) {
  usz off = 0;
  u64 len;
  if (!get_one_head(buf, n, &off, want_type, &len)) return 0;
  if (!get_one_body(buf, n, &off, len, v)) return 0;
  return off;
}

usz quic_h3_cancel_push_put(u8 *buf, usz cap, u64 push_id) {
  return put_one(buf, cap, QUIC_H3_FRAME_CANCEL_PUSH, push_id);
}

usz quic_h3_cancel_push_get(const u8 *buf, usz n, u64 *push_id) {
  return get_one(buf, n, QUIC_H3_FRAME_CANCEL_PUSH, push_id);
}

usz quic_h3_goaway_put(u8 *buf, usz cap, u64 id) {
  return put_one(buf, cap, QUIC_H3_FRAME_GOAWAY, id);
}

usz quic_h3_goaway_get(const u8 *buf, usz n, u64 *id) {
  return get_one(buf, n, QUIC_H3_FRAME_GOAWAY, id);
}

usz quic_h3_max_push_id_put(u8 *buf, usz cap, u64 push_id) {
  return put_one(buf, cap, QUIC_H3_FRAME_MAX_PUSH_ID, push_id);
}

usz quic_h3_max_push_id_get(const u8 *buf, usz n, u64 *push_id) {
  return get_one(buf, n, QUIC_H3_FRAME_MAX_PUSH_ID, push_id);
}

/* Write one (Identifier Value) pair. Returns 1 ok, 0 on overflow. */
static int frame_put_pair(
    u8 *buf, usz cap, usz *off, const u64 *id, const u64 *value) {
  if (!quic_varint_put(buf, cap, off, *id)) return 0;
  return quic_varint_put(buf, cap, off, *value);
}

/* Read the Identifier into the next free slot, rejecting a full array. */
static int take_pair_id(const u8 *buf, usz end, usz *off, quic_h3_settings *s) {
  if (s->n >= QUIC_H3_SETTINGS_MAX) return 0;
  return quic_varint_take(buf, end, off, &s->pairs[s->n].id);
}

/* Read one (Identifier Value) pair into the next free slot of s. Returns 1
 * ok, 0 if truncated or the fixed pair array is already full. */
static int frame_take_pair(
    const u8 *buf, usz end, usz *off, quic_h3_settings *s) {
  if (!take_pair_id(buf, end, off, s)) return 0;
  if (!quic_varint_take(buf, end, off, &s->pairs[s->n].value)) return 0;
  s->n++;
  return 1;
}

/* Read the SETTINGS head, check the type, and bound the payload within n.
 * On success *off points at the first pair and *end at the payload end. */
static int get_settings_head(const u8 *buf, usz n, usz *off, usz *end) {
  u64 type, len;
  if (!get_head(buf, n, off, &type, &len)) return 0;
  if (type != QUIC_H3_FRAME_SETTINGS) return 0;
  *end = *off + (usz)len;
  return *end <= n;
}

/* Total byte length of the (Identifier Value) pairs. 0 if any varint is out
 * of range (so the caller rejects the whole frame). */
static usz settings_body_len(const quic_h3_settings *s) {
  usz total = 0;
  for (usz i = 0; i < s->n; i++)
    total +=
        quic_varint_len(s->pairs[i].id) + quic_varint_len(s->pairs[i].value);
  return total;
}

/* Append every (Identifier Value) pair after the head. Returns 1 ok, 0. */
static int put_settings_pairs(
    u8 *buf, usz cap, usz *off, const quic_h3_settings *s) {
  int ok = 1;
  for (usz i = 0; i < s->n; i++)
    if (!frame_put_pair(buf, cap, off, &s->pairs[i].id, &s->pairs[i].value))
      ok = 0;
  return ok;
}

/* Bound the pair count and write the SETTINGS head. Returns 1 ok, 0 bad. */
static int put_settings_head(
    u8 *buf, usz cap, usz *off, const quic_h3_settings *s) {
  if (s->n > QUIC_H3_SETTINGS_MAX) return 0;
  return put_head(buf, cap, off, QUIC_H3_FRAME_SETTINGS, settings_body_len(s));
}

usz quic_h3_settings_put(u8 *buf, usz cap, const quic_h3_settings *s) {
  usz off = 0;
  if (!put_settings_head(buf, cap, &off, s)) return 0;
  if (!put_settings_pairs(buf, cap, &off, s)) return 0;
  return off;
}

/* Read pairs until *off reaches end. Returns 1 ok, 0 on truncation/overflow. */
static int get_settings_pairs(
    const u8 *buf, usz end, usz *off, quic_h3_settings *s) {
  s->n = 0;
  while (*off < end)
    if (!frame_take_pair(buf, end, off, s)) return 0;
  return 1;
}

usz quic_h3_settings_get(const u8 *buf, usz n, quic_h3_settings *s) {
  usz off = 0, end;
  if (!get_settings_head(buf, n, &off, &end)) return 0;
  if (!get_settings_pairs(buf, end, &off, s)) return 0;
  return off;
}
