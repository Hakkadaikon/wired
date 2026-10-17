#include "transport/packet/frame/frame/ack_impl.h"

static int put_pair(wired_obuf* o, const ack_range* prev, const ack_range* cur);
static u64 ack_type(const ack_frame* f);
static int put_ack_meta(wired_obuf* o, const ack_frame* f);
static int put_two(wired_obuf* o, u64 a, u64 b);
static int put_ack_ecn(wired_obuf* o, const ack_frame* f);
static int put_ack_head(wired_obuf* o, const ack_frame* f);
static int put_ack_pairs(wired_obuf* o, const ack_frame* f);
static int ranges_ok(usz n);
static int put_ack_pairs_ecn(wired_obuf* o, const ack_frame* f);
static int put_ack_body(wired_obuf* o, const ack_frame* f);
static int take_ack_meta(wired_span in, usz* off, ackdec* d);
static int take_first(wired_span in, usz* off, ackdec* d);

/* Encode the (Gap, Range Length) pair for range i (i >= 1). Gap counts the
 * unacknowledged packets between the previous range's low and this range's
 * high: gap = prev.lo - cur.hi - 2 (RFC 9000 19.3). */
static int put_pair(
    wired_obuf* o, const ack_range* prev, const ack_range* cur) {
  if (!varint_put(
          wired_mspan_of(o->p, o->cap), &o->len, prev->lo - cur->hi - 2))
    return 0;
  return varint_put(wired_mspan_of(o->p, o->cap), &o->len, cur->hi - cur->lo);
}

/* The frame type is 0x03 when ECN counts are present, else 0x02. */
static u64 ack_type(const ack_frame* f) {
  return f->has_ecn ? FRAME_ACK_ECN : FRAME_ACK;
}

/* Write type, largest, ack_delay (three varints). Returns 1 ok, 0. */
static int put_ack_meta(wired_obuf* o, const ack_frame* f) {
  if (!varint_put(wired_mspan_of(o->p, o->cap), &o->len, ack_type(f))) return 0;
  if (!varint_put(wired_mspan_of(o->p, o->cap), &o->len, f->ranges[0].hi))
    return 0;
  return varint_put(wired_mspan_of(o->p, o->cap), &o->len, f->ack_delay);
}

/* Write two consecutive varints. Returns 1 ok, 0 on overflow. */
static int put_two(wired_obuf* o, u64 a, u64 b) {
  if (!varint_put(wired_mspan_of(o->p, o->cap), &o->len, a)) return 0;
  return varint_put(wired_mspan_of(o->p, o->cap), &o->len, b);
}

/* Append the ECN counts (ECT0, ECT1, CE) when present. Returns 1 ok, 0. */
static int put_ack_ecn(wired_obuf* o, const ack_frame* f) {
  if (!f->has_ecn) return 1;
  if (!put_two(o, f->ect0, f->ect1)) return 0;
  return varint_put(wired_mspan_of(o->p, o->cap), &o->len, f->ce);
}

/* Encode the fixed prologue: type, largest, ack_delay, range count, first. */
static int put_ack_head(wired_obuf* o, const ack_frame* f) {
  const ack_range* r0 = &f->ranges[0];
  if (!put_ack_meta(o, f)) return 0;
  return put_two(o, f->n_ranges - 1, r0->hi - r0->lo);
}

/* Append all subsequent (Gap, Range Length) pairs. Returns 1 ok, 0 on error. */
static int put_ack_pairs(wired_obuf* o, const ack_frame* f) {
  int ok = 1;
  for (usz i = 1; i < f->n_ranges; i++)
    if (!put_pair(o, &f->ranges[i - 1], &f->ranges[i])) ok = 0;
  return ok;
}

/* A frame must carry between 1 and ACK_MAX_RANGES ranges. */
static int ranges_ok(usz n) { return n != 0 && n <= ACK_MAX_RANGES; }

/* Write all (Gap, Range Length) pairs then any ECN counts. */
static int put_ack_pairs_ecn(wired_obuf* o, const ack_frame* f) {
  if (!put_ack_pairs(o, f)) return 0;
  return put_ack_ecn(o, f);
}

/* Write the head then all pairs and ECN. Returns 1 ok, 0 on overflow. */
static int put_ack_body(wired_obuf* o, const ack_frame* f) {
  if (!put_ack_head(o, f)) return 0;
  return put_ack_pairs_ecn(o, f);
}

usz ack_encode(u8* buf, usz cap, const ack_frame* f) {
  wired_obuf o = obuf_of(buf, cap);
  if (!ranges_ok(f->n_ranges)) return 0;
  if (!put_ack_body(&o, f)) return 0;
  return o.len;
}

/* Read largest, ack_delay, range count (three varints). Returns 1 ok, 0. */
static int take_ack_meta(wired_span in, usz* off, ackdec* d) {
  if (!varint_take(wired_span_of(in.p, in.n), off, &d->largest)) return 0;
  if (!varint_take(wired_span_of(in.p, in.n), off, &d->f->ack_delay)) return 0;
  return varint_take(wired_span_of(in.p, in.n), off, &d->count);
}

/* Read the First ACK Range and require it not to underflow below zero. */
static int take_first(wired_span in, usz* off, ackdec* d) {
  if (!varint_take(wired_span_of(in.p, in.n), off, &d->first)) return 0;
  return d->first <= d->largest;
}

/* Read the prologue, filling ranges[0] and d->count. Returns 1 ok, 0 bad. */
int ack_take_ack_head(wired_span in, usz* off, ackdec* d) {
  if (!take_ack_meta(in, off, d)) return 0;
  if (!take_first(in, off, d)) return 0;
  d->f->ranges[0].hi = d->largest;
  d->f->ranges[0].lo = d->largest - d->first;
  return 1;
}
