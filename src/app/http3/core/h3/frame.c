#include "app/http3/core/h3/frame.h"

#include "common/bytes/util/bytes.h"
#include "common/bytes/varint/varint.h"

/* A write cursor: the output buffer, its capacity, and the write offset,
 * folded into one parameter so the frame-head helpers below stay <=3 args. */
typedef struct {
  u8 *buf;
  usz cap;
  usz off;
} h3frame_wcur;

/* Write Type then Length (two varints). Returns 1 ok, 0 on overflow. */
static int put_head(h3frame_wcur *w, u64 type, u64 len) {
  if (!quic_varint_put(w->buf, w->cap, &w->off, type)) return 0;
  return quic_varint_put(w->buf, w->cap, &w->off, len);
}

usz quic_h3_frame_put(quic_obuf *out, u64 type, quic_span payload) {
  h3frame_wcur w = {out->p, out->cap, 0};
  if (!put_head(&w, type, payload.n)) return 0;
  if (!quic_put_bytes(w.buf, w.cap, &w.off, payload.p, payload.n)) return 0;
  out->len = w.off;
  return w.off;
}

/* A read cursor: the input buffer, its length, and the read offset. */
typedef struct {
  const u8 *buf;
  usz       n;
  usz       off;
} h3frame_rcur;

/* Read Type then Length (two varints). Returns 1 ok, 0 if truncated. */
static int get_head(h3frame_rcur *r, u64 *type, u64 *len) {
  if (!quic_varint_take(r->buf, r->n, &r->off, type)) return 0;
  return quic_varint_take(r->buf, r->n, &r->off, len);
}

usz quic_h3_frame_get(quic_span buf, quic_h3_frame *f) {
  h3frame_rcur r = {buf.p, buf.n, 0};
  if (!get_head(&r, &f->type, &f->payload_len)) return 0;
  if (r.off + f->payload_len > buf.n) return 0;
  f->payload = buf.p + r.off;
  return r.off + f->payload_len;
}

/* Encode a frame whose entire payload is a single varint (CANCEL_PUSH,
 * GOAWAY, MAX_PUSH_ID). Writes type, length, then the value varint. */
static usz put_one(quic_obuf *out, u64 type, u64 v) {
  h3frame_wcur w = {out->p, out->cap, 0};
  if (!put_head(&w, type, quic_varint_len(v))) return 0;
  if (!quic_varint_put(w.buf, w.cap, &w.off, v)) return 0;
  out->len = w.off;
  return w.off;
}

/* Read the head of a single-varint frame and require the type. On success
 * *len holds the Length field. Returns 1 ok, 0 bad. */
static int get_one_head(h3frame_rcur *r, u64 want_type, u64 *len) {
  u64 type;
  if (!get_head(r, &type, len)) return 0;
  return type == want_type;
}

/* Read the single varint value and require it to exactly fill len bytes.
 * On success advances r->off past the value. Returns 1 ok, 0 bad. */
static int get_one_body(h3frame_rcur *r, u64 len, u64 *v) {
  usz vstart = r->off;
  if (!quic_varint_take(r->buf, r->n, &r->off, v)) return 0;
  return r->off - vstart == len;
}

/* Decode a frame of expected type whose payload is a single varint. The
 * Length field must exactly cover that varint. Returns bytes consumed or 0. */
static usz get_one(quic_span buf, u64 want_type, u64 *v) {
  h3frame_rcur r = {buf.p, buf.n, 0};
  u64          len;
  if (!get_one_head(&r, want_type, &len)) return 0;
  if (!get_one_body(&r, len, v)) return 0;
  return r.off;
}

usz quic_h3_cancel_push_put(u8 *buf, usz cap, u64 push_id) {
  quic_obuf ob = quic_obuf_of(buf, cap);
  return put_one(&ob, QUIC_H3_FRAME_CANCEL_PUSH, push_id);
}

usz quic_h3_cancel_push_get(const u8 *buf, usz n, u64 *push_id) {
  return get_one(quic_span_of(buf, n), QUIC_H3_FRAME_CANCEL_PUSH, push_id);
}

usz quic_h3_goaway_put(u8 *buf, usz cap, u64 id) {
  quic_obuf ob = quic_obuf_of(buf, cap);
  return put_one(&ob, QUIC_H3_FRAME_GOAWAY, id);
}

usz quic_h3_goaway_get(const u8 *buf, usz n, u64 *id) {
  return get_one(quic_span_of(buf, n), QUIC_H3_FRAME_GOAWAY, id);
}

usz quic_h3_max_push_id_put(u8 *buf, usz cap, u64 push_id) {
  quic_obuf ob = quic_obuf_of(buf, cap);
  return put_one(&ob, QUIC_H3_FRAME_MAX_PUSH_ID, push_id);
}

usz quic_h3_max_push_id_get(const u8 *buf, usz n, u64 *push_id) {
  return get_one(quic_span_of(buf, n), QUIC_H3_FRAME_MAX_PUSH_ID, push_id);
}

/* Write one (Identifier Value) pair. Returns 1 ok, 0 on overflow. */
static int frame_put_pair(h3frame_wcur *w, const u64 *id, const u64 *value) {
  if (!quic_varint_put(w->buf, w->cap, &w->off, *id)) return 0;
  return quic_varint_put(w->buf, w->cap, &w->off, *value);
}

/* Read the Identifier into the next free slot, rejecting a full array. */
static int take_pair_id(h3frame_rcur *r, quic_h3_settings *s) {
  if (s->n >= QUIC_H3_SETTINGS_MAX) return 0;
  return quic_varint_take(r->buf, r->n, &r->off, &s->pairs[s->n].id);
}

/* Read one (Identifier Value) pair into the next free slot of s. Returns 1
 * ok, 0 if truncated or the fixed pair array is already full. */
static int frame_take_pair(h3frame_rcur *r, quic_h3_settings *s) {
  if (!take_pair_id(r, s)) return 0;
  if (!quic_varint_take(r->buf, r->n, &r->off, &s->pairs[s->n].value))
    return 0;
  s->n++;
  return 1;
}

/* Read the SETTINGS head, check the type, and bound the payload within
 * r->n. On success r->off points at the first pair and *end at the payload
 * end. */
static int get_settings_head(h3frame_rcur *r, usz *end) {
  u64 type, len;
  if (!get_head(r, &type, &len)) return 0;
  if (type != QUIC_H3_FRAME_SETTINGS) return 0;
  *end = r->off + (usz)len;
  return *end <= r->n;
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
static int put_settings_pairs(h3frame_wcur *w, const quic_h3_settings *s) {
  int ok = 1;
  for (usz i = 0; i < s->n; i++)
    if (!frame_put_pair(w, &s->pairs[i].id, &s->pairs[i].value)) ok = 0;
  return ok;
}

/* Bound the pair count and write the SETTINGS head. Returns 1 ok, 0 bad. */
static int put_settings_head(h3frame_wcur *w, const quic_h3_settings *s) {
  if (s->n > QUIC_H3_SETTINGS_MAX) return 0;
  return put_head(w, QUIC_H3_FRAME_SETTINGS, settings_body_len(s));
}

usz quic_h3_settings_put(u8 *buf, usz cap, const quic_h3_settings *s) {
  h3frame_wcur w = {buf, cap, 0};
  if (!put_settings_head(&w, s)) return 0;
  if (!put_settings_pairs(&w, s)) return 0;
  return w.off;
}

/* Read pairs until r->off reaches end. Returns 1 ok, 0 on
 * truncation/overflow. */
static int get_settings_pairs(h3frame_rcur *r, usz end, quic_h3_settings *s) {
  s->n = 0;
  while (r->off < end)
    if (!frame_take_pair(r, s)) return 0;
  return 1;
}

usz quic_h3_settings_get(const u8 *buf, usz n, quic_h3_settings *s) {
  h3frame_rcur r = {buf, n, 0};
  usz          end;
  if (!get_settings_head(&r, &end)) return 0;
  if (!get_settings_pairs(&r, end, s)) return 0;
  return r.off;
}
