#include "app/http3/server/srvloop/body_window_impl.h"

static int  bodywin_forbidden(u64 type);
static usz  bodywin_header_take(const bodywin_run* r, u64* type, u64* len);
static int  bodywin_header(bodywin_run* r);
static int  bodywin_chunk_fin(const bodywin_run* r, usz n);
static void bodywin_call(
    bodywin* w, wired_span chunk, int fin, bodywin_sink fn, void* ctx);
static void bodywin_deliver(const bodywin_run* r, usz n, int fin);
static int  bodywin_payload(bodywin_run* r);
static int  bodywin_step(bodywin_run* r);
static int  bodywin_all_in(const bodywin* w);
static int  bodywin_at_end(const bodywin* w);
static void bodywin_end(bodywin* w, bodywin_sink fn, void* ctx);

/* RFC 9114 7.2.3-7.2.7 / 11.2.1: CANCEL_PUSH, SETTINGS, PUSH_PROMISE (from a
 * client), GOAWAY, MAX_PUSH_ID and the reserved HTTP/2 types 0x2, 0x6, 0x8,
 * 0x9 are H3_FRAME_UNEXPECTED on a request stream. */
static int bodywin_forbidden(u64 type) {
  return type < 14 && ((0x23fcu >> type) & 1u);
}

/* RFC 9114 7.1 / RFC 9297 3.2: a frame or capsule header counts only once
 * both varints are whole -- a partial one stays put. Returns its length, or
 * 0. */
usz bodywin_head(const u8* p, usz n, u64* type, u64* len) {
  usz a = varint_decode(p, n, type);
  usz b = a ? varint_decode(p + a, n - a, len) : 0;
  return b ? a + b : 0;
}

static usz bodywin_header_take(const bodywin_run* r, u64* type, u64* len) {
  return bodywin_head(r->buf + r->pos, r->fr - r->pos, type, len);
}

static int bodywin_header(bodywin_run* r) {
  u64 type, len;
  usz n = bodywin_header_take(r, &type, &len);
  if (!n) return 0;
  if (bodywin_forbidden(type)) {
    r->w->state = BODYWIN_FRAME_UNEXPECTED;
    return 0;
  }
  r->w->left    = len;
  r->w->is_data = type == H3_FRAME_DATA;
  r->pos += n;
  return 1;
}

/* fin rides on a chunk that ends its frame exactly at the final size. */
static int bodywin_chunk_fin(const bodywin_run* r, usz n) {
  const bodywin* w = r->w;
  return w->left == n && w->fin && w->base + r->pos + n == w->fin_off;
}

/* Hand chunk to fn and move to the state its answer and fin select. */
static void bodywin_call(
    bodywin* w, wired_span chunk, int fin, bodywin_sink fn, void* ctx) {
  static const u8 next[2][2] = {
      {BODYWIN_REJECTED, BODYWIN_REJECTED}, {BODYWIN_OPEN, BODYWIN_DONE}};
  w->state = next[fn(ctx, chunk, fin) != 0][fin != 0];
}

/* Only DATA payload reaches fn; other frame types are skipped. */
static void bodywin_deliver(const bodywin_run* r, usz n, int fin) {
  if (r->w->is_data)
    bodywin_call(r->w, wired_span_of(r->buf + r->pos, n), fin, r->fn, r->ctx);
}

/* The available part of the current frame's payload, never past its end. */
static int bodywin_payload(bodywin_run* r) {
  usz n   = (usz)u64_min(r->w->left, r->fr - r->pos);
  int fin = bodywin_chunk_fin(r, n);
  if (!n) return 0;
  bodywin_deliver(r, n, fin);
  r->w->left -= n;
  r->pos += n;
  return 1;
}

static int bodywin_step(bodywin_run* r) {
  if (r->w->left) return bodywin_payload(r);
  return bodywin_header(r);
}

/* 1 once every byte up to the final size is in the window. */
static int bodywin_all_in(const bodywin* w) {
  return w->fin && w->base + bodywin_frontier(w) == w->fin_off;
}

/* RFC 9114 7.1: at the final size either the parser sits on a frame
 * boundary with nothing buffered (fin=1 still owed: an empty chunk) or the
 * stream ended inside a frame (H3_FRAME_ERROR). */
static int bodywin_at_end(const bodywin* w) {
  return w->state == BODYWIN_OPEN && bodywin_all_in(w);
}

static void bodywin_end(bodywin* w, bodywin_sink fn, void* ctx) {
  if (!bodywin_at_end(w)) return;
  if (w->left + bodywin_frontier(w)) {
    w->state = BODYWIN_FRAME_ERROR;
    return;
  }
  bodywin_call(w, wired_span_of(0, 0), 1, fn, ctx);
}

int bodywin_pump(bodywin* w, u8* buf, bodywin_sink fn, void* ctx) {
  bodywin_run r = {w, buf, 0, bodywin_frontier(w), fn, ctx};
  while (w->state == BODYWIN_OPEN && bodywin_step(&r)) {
  }
  bodywin_consume(w, buf, r.pos);
  bodywin_end(w, fn, ctx);
  return w->state;
}
