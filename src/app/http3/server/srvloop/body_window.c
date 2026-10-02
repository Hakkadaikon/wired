#include "app/http3/server/srvloop/body_window.h"

#include "app/http3/core/h3/frame.h"
#include "common/bytes/util/num.h"
#include "common/bytes/varint/varint.h"

static int bodywin_bit(const bodywin* w, usz i) {
  return (w->have[i / 8] >> (i % 8)) & 1;
}

static void bodywin_set(bodywin* w, usz i, int v) {
  w->have[i / 8] = (u8)((w->have[i / 8] & ~(1u << (i % 8))) | (v << (i % 8)));
}

/* RFC 9000 2.2: the received byte at stream offset off is kept only inside
 * [base, base + BODYWIN_CAP) -- the credit never reaches past it. */
static int bodywin_in(const bodywin* w, u64 off) {
  return off >= w->base && off - w->base < BODYWIN_CAP;
}

static void bodywin_put(bodywin* w, u8* buf, u64 off, u8 v) {
  if (!bodywin_in(w, off)) return;
  buf[off - w->base] = v;
  bodywin_set(w, (usz)(off - w->base), 1);
}

void bodywin_land(bodywin* w, u8* buf, u64 off, wired_span data, int fin) {
  for (usz i = 0; i < data.n; i++) bodywin_put(w, buf, off + i, data.p[i]);
  if (fin) w->fin_off = off + data.n;
  w->fin |= (u8)(fin != 0);
}

usz bodywin_frontier(const bodywin* w) {
  usz n = 0;
  while (n < BODYWIN_CAP && bodywin_bit(w, n)) n++;
  return n;
}

/* have[] bit i, 0 past the window. */
static int bodywin_bit_at(const bodywin* w, usz i) {
  return i < BODYWIN_CAP ? bodywin_bit(w, i) : 0;
}

void bodywin_consume(bodywin* w, u8* buf, usz n) {
  for (usz i = 0; i + n < BODYWIN_CAP; i++) buf[i] = buf[i + n];
  for (usz i = 0; i < BODYWIN_CAP; i++)
    bodywin_set(w, i, bodywin_bit_at(w, i + n));
  w->base += n;
}

/* One pump's cursor: frames are parsed at buf[pos..fr) (fr: the frontier,
 * fixed for the pump) and the window slides once, by pos, at the end. */
typedef struct {
  bodywin*     w;
  u8*          buf;
  usz          pos;
  usz          fr;
  bodywin_sink fn;
  void*        ctx;
} bodywin_run;

/* RFC 9114 7.2.3-7.2.7 / 11.2.1: CANCEL_PUSH, SETTINGS, PUSH_PROMISE (from a
 * client), GOAWAY, MAX_PUSH_ID and the reserved HTTP/2 types 0x2, 0x6, 0x8,
 * 0x9 are H3_FRAME_UNEXPECTED on a request stream. */
static int bodywin_forbidden(u64 type) {
  return type < 14 && ((0x23fcu >> type) & 1u);
}

/* RFC 9114 7.1: a frame header counts only once both varints are whole --
 * a partial one stays in the window untouched. Returns its length, or 0. */
static usz bodywin_header_take(const bodywin_run* r, u64* type, u64* len) {
  const u8* p = r->buf + r->pos;
  usz       n = r->fr - r->pos;
  usz       a = varint_decode(p, n, type);
  usz       b = a ? varint_decode(p + a, n - a, len) : 0;
  return b ? a + b : 0;
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

/* One capsule pump: the frame cursor plus the capsule receiver. */
typedef struct {
  bodywin_run        r;
  bodywin_capsule_fn fn;
  void*              ctx;
} bodywin_caprun;

static void bodywin_cap_call(bodywin_caprun* c, u64 type, wired_span value) {
  if (!c->fn(c->ctx, type, value)) c->r.w->state = BODYWIN_REJECTED;
}

/* Skip the available part of an oversized capsule's value. */
static int bodywin_cap_skip(bodywin_run* r) {
  usz n = (usz)u64_min(r->w->left, r->fr - r->pos);
  r->w->left -= n;
  r->pos += n;
  return n != 0;
}

/* A capsule whose n-byte header and len-byte value can never share the
 * window: announce it, then skip its value by length. */
static int bodywin_cap_oversized(bodywin_caprun* c, u64 type, usz n, u64 len) {
  bodywin_cap_call(c, type, wired_span_of(0, 0));
  c->r.w->left = len;
  c->r.pos += n;
  return 1;
}

/* Hand over the capsule at pos once its value is inside the frontier. */
static int bodywin_cap_whole(bodywin_caprun* c, u64 type, usz n, u64 len) {
  bodywin_run* r = &c->r;
  if (len > r->fr - r->pos - n) return 0;
  bodywin_cap_call(c, type, wired_span_of(r->buf + r->pos + n, (usz)len));
  r->pos += n + (usz)len;
  return 1;
}

static int bodywin_cap_one(bodywin_caprun* c) {
  u64 type, len;
  usz n = bodywin_header_take(&c->r, &type, &len);
  if (!n) return 0;
  if (len > BODYWIN_CAP - n) return bodywin_cap_oversized(c, type, n, len);
  return bodywin_cap_whole(c, type, n, len);
}

static int bodywin_cap_step(bodywin_caprun* c) {
  if (c->r.w->left) return bodywin_cap_skip(&c->r);
  return bodywin_cap_one(c);
}

/* RFC 9297 3.3: the stream ended inside a capsule. */
static void bodywin_cap_end(bodywin* w) {
  if (bodywin_at_end(w) && w->left + bodywin_frontier(w))
    w->state = BODYWIN_FRAME_ERROR;
}

int bodywin_capsules(bodywin* w, u8* buf, bodywin_capsule_fn fn, void* ctx) {
  bodywin_caprun c = {{w, buf, 0, bodywin_frontier(w), 0, 0}, fn, ctx};
  while (w->state == BODYWIN_OPEN && bodywin_cap_step(&c)) {
  }
  bodywin_consume(w, buf, c.r.pos);
  bodywin_cap_end(w);
  return w->state;
}

u64 bodywin_credit_due(bodywin* w) {
  if (w->base <= w->granted) return 0;
  w->granted = w->base;
  return w->base + BODYWIN_CAP;
}
