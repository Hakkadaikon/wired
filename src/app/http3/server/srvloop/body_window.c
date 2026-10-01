#include "app/http3/server/srvloop/body_window.h"

#include "app/http3/core/h3/frame.h"
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

/* RFC 9114 7.1: consume a frame header only once both varints are whole --
 * a partial one stays in the window untouched. */
static int bodywin_header(bodywin* w, u8* buf, usz fr) {
  u64 type, len;
  usz a = varint_decode(buf, fr, &type);
  usz b = a ? varint_decode(buf + a, fr - a, &len) : 0;
  if (!b) return 0;
  w->left    = len;
  w->is_data = type == H3_FRAME_DATA;
  bodywin_consume(w, buf, a + b);
  return 1;
}

/* fin rides on a chunk that ends its frame exactly at the final size. */
static int bodywin_chunk_fin(const bodywin* w, usz n) {
  return w->left == n && w->fin && w->base + n == w->fin_off;
}

/* Hand chunk to fn and move to the state its answer and fin select. */
static void bodywin_call(
    bodywin* w, wired_span chunk, int fin, bodywin_sink fn, void* ctx) {
  static const u8 next[2][2] = {
      {BODYWIN_REJECTED, BODYWIN_REJECTED}, {BODYWIN_OPEN, BODYWIN_DONE}};
  w->state = next[fn(ctx, chunk, fin) != 0][fin != 0];
}

/* Only DATA payload reaches fn; other frame types are skipped. */
static void bodywin_deliver(
    bodywin* w, wired_span chunk, int fin, bodywin_sink fn, void* ctx) {
  if (w->is_data) bodywin_call(w, chunk, fin, fn, ctx);
}

/* The available part of the current frame's payload, never past its end. */
static int bodywin_payload(
    bodywin* w, u8* buf, usz fr, bodywin_sink fn, void* ctx) {
  usz n   = w->left < fr ? (usz)w->left : fr;
  int fin = bodywin_chunk_fin(w, n);
  if (!n) return 0;
  bodywin_deliver(w, wired_span_of(buf, n), fin, fn, ctx);
  w->left -= n;
  bodywin_consume(w, buf, n);
  return 1;
}

static int bodywin_step(bodywin* w, u8* buf, bodywin_sink fn, void* ctx) {
  usz fr = bodywin_frontier(w);
  if (w->left) return bodywin_payload(w, buf, fr, fn, ctx);
  return bodywin_header(w, buf, fr);
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
  while (w->state == BODYWIN_OPEN && bodywin_step(w, buf, fn, ctx)) {
  }
  bodywin_end(w, fn, ctx);
  return w->state;
}

u64 bodywin_credit_due(bodywin* w) {
  if (w->base <= w->granted) return 0;
  w->granted = w->base;
  return w->base + BODYWIN_CAP;
}
