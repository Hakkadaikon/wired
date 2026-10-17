#include "app/http3/core/h3/frame_impl.h"

static usz put_one(wired_obuf* out, u64 type, u64 v);
static int get_one_head(h3frame_rcur* r, u64 want_type, u64* len);
static int get_one_body(h3frame_rcur* r, u64 len, u64* v);
static usz get_one(wired_span buf, u64 want_type, u64* v);

/* Write Type then Length (two varints). Returns 1 ok, 0 on overflow. */
int h3frame_put_head(h3frame_wcur* w, u64 type, u64 len) {
  if (!varint_put(wired_mspan_of(w->buf, w->cap), &w->off, type)) return 0;
  return varint_put(wired_mspan_of(w->buf, w->cap), &w->off, len);
}

usz h3_frame_put(wired_obuf* out, u64 type, wired_span payload) {
  h3frame_wcur w = {out->p, out->cap, 0};
  if (!h3frame_put_head(&w, type, payload.n)) return 0;
  if (!bytes_put(
          wired_mspan_of(w.buf, w.cap), &w.off,
          wired_span_of(payload.p, payload.n)))
    return 0;
  out->len = w.off;
  return w.off;
}

/* Read Type then Length (two varints). Returns 1 ok, 0 if truncated. */
int h3frame_get_head(h3frame_rcur* r, u64* type, u64* len) {
  if (!varint_take(wired_span_of(r->buf, r->n), &r->off, type)) return 0;
  return varint_take(wired_span_of(r->buf, r->n), &r->off, len);
}

usz h3_frame_get(wired_span buf, h3_frame* f) {
  h3frame_rcur r = {buf.p, buf.n, 0};
  if (!h3frame_get_head(&r, &f->type, &f->payload_len)) return 0;
  if (r.off + f->payload_len > buf.n) return 0;
  f->payload = buf.p + r.off;
  return r.off + f->payload_len;
}

/* Encode a frame whose entire payload is a single varint (CANCEL_PUSH,
 * GOAWAY, MAX_PUSH_ID). Writes type, length, then the value varint. */
static usz put_one(wired_obuf* out, u64 type, u64 v) {
  h3frame_wcur w = {out->p, out->cap, 0};
  if (!h3frame_put_head(&w, type, varint_len(v))) return 0;
  if (!varint_put(wired_mspan_of(w.buf, w.cap), &w.off, v)) return 0;
  out->len = w.off;
  return w.off;
}

/* Read the head of a single-varint frame and require the type. On success
 * *len holds the Length field. Returns 1 ok, 0 bad. */
static int get_one_head(h3frame_rcur* r, u64 want_type, u64* len) {
  u64 type;
  if (!h3frame_get_head(r, &type, len)) return 0;
  return type == want_type;
}

/* Read the single varint value and require it to exactly fill len bytes.
 * On success advances r->off past the value. Returns 1 ok, 0 bad. */
static int get_one_body(h3frame_rcur* r, u64 len, u64* v) {
  usz vstart = r->off;
  if (!varint_take(wired_span_of(r->buf, r->n), &r->off, v)) return 0;
  return r->off - vstart == len;
}

/* Decode a frame of expected type whose payload is a single varint. The
 * Length field must exactly cover that varint. Returns bytes consumed or 0. */
static usz get_one(wired_span buf, u64 want_type, u64* v) {
  h3frame_rcur r = {buf.p, buf.n, 0};
  u64          len;
  if (!get_one_head(&r, want_type, &len)) return 0;
  if (!get_one_body(&r, len, v)) return 0;
  return r.off;
}

usz h3_cancel_push_put(u8* buf, usz cap, u64 push_id) {
  wired_obuf ob = obuf_of(buf, cap);
  return put_one(&ob, H3_FRAME_CANCEL_PUSH, push_id);
}

usz h3_cancel_push_get(const u8* buf, usz n, u64* push_id) {
  return get_one(wired_span_of(buf, n), H3_FRAME_CANCEL_PUSH, push_id);
}

usz h3_goaway_put(u8* buf, usz cap, u64 id) {
  wired_obuf ob = obuf_of(buf, cap);
  return put_one(&ob, H3_FRAME_GOAWAY, id);
}

usz h3_goaway_get(const u8* buf, usz n, u64* id) {
  return get_one(wired_span_of(buf, n), H3_FRAME_GOAWAY, id);
}

usz h3_max_push_id_put(u8* buf, usz cap, u64 push_id) {
  wired_obuf ob = obuf_of(buf, cap);
  return put_one(&ob, H3_FRAME_MAX_PUSH_ID, push_id);
}

usz h3_max_push_id_get(const u8* buf, usz n, u64* push_id) {
  return get_one(wired_span_of(buf, n), H3_FRAME_MAX_PUSH_ID, push_id);
}
