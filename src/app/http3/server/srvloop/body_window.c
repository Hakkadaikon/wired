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

/* RFC 9114 7.1 / RFC 9297 3.2: a frame or capsule header counts only once
 * both varints are whole -- a partial one stays put. Returns its length, or
 * 0. */
static usz bodywin_head(const u8* p, usz n, u64* type, u64* len) {
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

/* One capsule pass: the reassembly buffer plus the capsule receiver. */
typedef struct {
  bodywin_capq*      q;
  bodywin_capsule_fn fn;
  void*              ctx;
} bodywin_capctx;

/* Drop the n buffered bytes in front of q. */
static void bodywin_capq_shift(bodywin_capq* q, usz n) {
  for (usz i = 0; i + n < q->n; i++) q->buf[i] = q->buf[i + n];
  q->n -= n;
}

/* A capsule whose h-byte header and len-byte value can never fit q:
 * announce it, then drop the value bytes held now and skip the rest. */
static int bodywin_capq_oversized(bodywin_capctx* k, u64 type, usz h, u64 len) {
  k->q->skip = len - (k->q->n - h);
  k->q->n    = 0;
  return k->fn(k->ctx, type, wired_span_of(0, 0)) != 0;
}

/* Hand over the whole capsule in front of q, or wait (2) for its value. */
static int bodywin_capq_whole(bodywin_capctx* k, u64 type, usz h, u64 len) {
  bodywin_capq* q = k->q;
  int           ok;
  if (len > q->n - h) return 2;
  ok = k->fn(k->ctx, type, wired_span_of(q->buf + h, (usz)len));
  bodywin_capq_shift(q, h + (usz)len);
  return ok != 0;
}

/* One capsule out of q: 1 handed over, 2 waiting for more bytes, 0 fn
 * said stop. */
static int bodywin_capq_pop(bodywin_capctx* k) {
  u64 type, len;
  usz h = bodywin_head(k->q->buf, k->q->n, &type, &len);
  if (!h) return 2;
  if (len > BODYWIN_CAPSULE_CAP - h)
    return bodywin_capq_oversized(k, type, h, len);
  return bodywin_capq_whole(k, type, h, len);
}

static int bodywin_capq_drain(bodywin_capctx* k) {
  int r;
  while ((r = bodywin_capq_pop(k)) == 1) {
  }
  return r != 0;
}

/* Take what fits of chunk from *at: skipped value bytes, or bytes appended
 * to q and every capsule they complete. 0 when fn said stop. */
static int bodywin_capq_feed(bodywin_capctx* k, wired_span chunk, usz* at) {
  bodywin_capq* q = k->q;
  usz           n = chunk.n - *at;
  if (q->skip) {
    n = (usz)u64_min(q->skip, n);
    q->skip -= n;
    *at += n;
    return 1;
  }
  n = (usz)u64_min(BODYWIN_CAPSULE_CAP - q->n, n);
  for (usz i = 0; i < n; i++) q->buf[q->n++] = chunk.p[(*at)++];
  return bodywin_capq_drain(k);
}

/* bodywin_pump sink: every DATA payload chunk is capsule bytes. */
static int bodywin_cap_sink(void* ctx, wired_span chunk, int fin) {
  usz at = 0;
  (void)fin;
  while (at < chunk.n)
    if (!bodywin_capq_feed(ctx, chunk, &at)) return 0;
  return 1;
}

static int bodywin_capq_partial(const bodywin_capq* q) {
  return q->n || q->skip;
}

int bodywin_capsules(
    bodywin* w, u8* buf, bodywin_capq* q, bodywin_capsule_fn fn, void* ctx) {
  bodywin_capctx k = {q, fn, ctx};
  /* RFC 9297 3.3: the stream ended inside a capsule. */
  if (bodywin_pump(w, buf, bodywin_cap_sink, &k) == BODYWIN_DONE &&
      bodywin_capq_partial(q))
    w->state = BODYWIN_FRAME_ERROR;
  return w->state;
}

u64 bodywin_credit_due(bodywin* w) {
  if (w->base <= w->granted) return 0;
  w->granted = w->base;
  return w->base + BODYWIN_CAP;
}
