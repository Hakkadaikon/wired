#include "transport/packet/frame/frame/ack.h"

#include "common/bytes/span/span.h"
#include "common/bytes/varint/varint.h"

/* Encode the (Gap, Range Length) pair for range i (i >= 1). Gap counts the
 * unacknowledged packets between the previous range's low and this range's
 * high: gap = prev.lo - cur.hi - 2 (RFC 9000 19.3). */
static int put_pair(
    quic_obuf *o, const quic_ack_range *prev, const quic_ack_range *cur) {
  if (!quic_varint_put(
          quic_mspan_of(o->p, o->cap), &o->len, prev->lo - cur->hi - 2))
    return 0;
  return quic_varint_put(
      quic_mspan_of(o->p, o->cap), &o->len, cur->hi - cur->lo);
}

/* The frame type is 0x03 when ECN counts are present, else 0x02. */
static u64 ack_type(const quic_ack_frame *f) {
  return f->has_ecn ? QUIC_FRAME_ACK_ECN : QUIC_FRAME_ACK;
}

/* Write type, largest, ack_delay (three varints). Returns 1 ok, 0. */
static int put_ack_meta(quic_obuf *o, const quic_ack_frame *f) {
  if (!quic_varint_put(quic_mspan_of(o->p, o->cap), &o->len, ack_type(f)))
    return 0;
  if (!quic_varint_put(quic_mspan_of(o->p, o->cap), &o->len, f->ranges[0].hi))
    return 0;
  return quic_varint_put(quic_mspan_of(o->p, o->cap), &o->len, f->ack_delay);
}

/* Write two consecutive varints. Returns 1 ok, 0 on overflow. */
static int put_two(quic_obuf *o, u64 a, u64 b) {
  if (!quic_varint_put(quic_mspan_of(o->p, o->cap), &o->len, a)) return 0;
  return quic_varint_put(quic_mspan_of(o->p, o->cap), &o->len, b);
}

/* Append the ECN counts (ECT0, ECT1, CE) when present. Returns 1 ok, 0. */
static int put_ack_ecn(quic_obuf *o, const quic_ack_frame *f) {
  if (!f->has_ecn) return 1;
  if (!put_two(o, f->ect0, f->ect1)) return 0;
  return quic_varint_put(quic_mspan_of(o->p, o->cap), &o->len, f->ce);
}

/* Encode the fixed prologue: type, largest, ack_delay, range count, first. */
static int put_ack_head(quic_obuf *o, const quic_ack_frame *f) {
  const quic_ack_range *r0 = &f->ranges[0];
  if (!put_ack_meta(o, f)) return 0;
  return put_two(o, f->n_ranges - 1, r0->hi - r0->lo);
}

/* Append all subsequent (Gap, Range Length) pairs. Returns 1 ok, 0 on error. */
static int put_ack_pairs(quic_obuf *o, const quic_ack_frame *f) {
  int ok = 1;
  for (usz i = 1; i < f->n_ranges; i++)
    if (!put_pair(o, &f->ranges[i - 1], &f->ranges[i])) ok = 0;
  return ok;
}

/* A frame must carry between 1 and QUIC_ACK_MAX_RANGES ranges. */
static int ranges_ok(usz n) { return n != 0 && n <= QUIC_ACK_MAX_RANGES; }

/* Write all (Gap, Range Length) pairs then any ECN counts. */
static int put_ack_pairs_ecn(quic_obuf *o, const quic_ack_frame *f) {
  if (!put_ack_pairs(o, f)) return 0;
  return put_ack_ecn(o, f);
}

/* Write the head then all pairs and ECN. Returns 1 ok, 0 on overflow. */
static int put_ack_body(quic_obuf *o, const quic_ack_frame *f) {
  if (!put_ack_head(o, f)) return 0;
  return put_ack_pairs_ecn(o, f);
}

usz quic_ack_encode(u8 *buf, usz cap, const quic_ack_frame *f) {
  quic_obuf o = quic_obuf_of(buf, cap);
  if (!ranges_ok(f->n_ranges)) return 0;
  if (!put_ack_body(&o, f)) return 0;
  return o.len;
}

/* Decode-side scratch threaded through the take_* helpers. */
typedef struct {
  quic_ack_frame *f;
  u64             largest;
  u64             first;
  u64             count;
} ackdec;

/* Read largest, ack_delay, range count (three varints). Returns 1 ok, 0. */
static int take_ack_meta(quic_span in, usz *off, ackdec *d) {
  if (!quic_varint_take(quic_span_of(in.p, in.n), off, &d->largest)) return 0;
  if (!quic_varint_take(quic_span_of(in.p, in.n), off, &d->f->ack_delay))
    return 0;
  return quic_varint_take(quic_span_of(in.p, in.n), off, &d->count);
}

/* Read the First ACK Range and require it not to underflow below zero. */
static int take_first(quic_span in, usz *off, ackdec *d) {
  if (!quic_varint_take(quic_span_of(in.p, in.n), off, &d->first)) return 0;
  return d->first <= d->largest;
}

/* Read the prologue, filling ranges[0] and d->count. Returns 1 ok, 0 bad. */
static int take_ack_head(quic_span in, usz *off, ackdec *d) {
  if (!take_ack_meta(in, off, d)) return 0;
  if (!take_first(in, off, d)) return 0;
  d->f->ranges[0].hi = d->largest;
  d->f->ranges[0].lo = d->largest - d->first;
  return 1;
}

/* A (gap, len) pair fits below prev_lo without underflowing past zero. */
static int pair_fits(u64 prev_lo, u64 gap, u64 len) {
  return prev_lo >= gap + 2 && prev_lo - gap - 2 >= len;
}

/* Read two consecutive varints into v[0], v[1]. Returns 1 ok, 0 truncated. */
static int take_two(quic_span in, usz *off, u64 v[2]) {
  if (!quic_varint_take(quic_span_of(in.p, in.n), off, &v[0])) return 0;
  return quic_varint_take(quic_span_of(in.p, in.n), off, &v[1]);
}

/* Read one (Gap, Range Length) pair into ranges[i] from ranges[i-1]. cur
 * points at ranges[i]; the previous range is cur[-1]. */
static int take_pair(quic_span in, usz *off, quic_ack_range *cur) {
  u64 gl[2], prev_lo = cur[-1].lo;
  if (!take_two(in, off, gl)) return 0;
  if (!pair_fits(prev_lo, gl[0], gl[1])) return 0;
  cur->hi = prev_lo - gl[0] - 2;
  cur->lo = cur->hi - gl[1];
  return 1;
}

/* Read d->count additional pairs (ranges 1..count). Returns 1 ok, 0 bad. */
static int take_ack_pairs(quic_span in, usz *off, ackdec *d) {
  int ok = 1;
  for (u64 i = 1; i <= d->count; i++)
    if (!take_pair(in, off, &d->f->ranges[(usz)i])) ok = 0;
  return ok;
}

/* The decoded range count plus the first range must fit our fixed array. */
static int count_fits(u64 count) { return count + 1 <= QUIC_ACK_MAX_RANGES; }

/* Read the prologue and bound-check the range count together. */
static int take_ack_prologue(quic_span in, usz *off, ackdec *d) {
  if (!take_ack_head(in, off, d)) return 0;
  return count_fits(d->count);
}

/* Read the ECN counts when the type byte was 0x03. Returns 1 ok, 0 bad. */
static int take_ack_ecn(quic_span in, usz *off, quic_ack_frame *f) {
  u64 e[2] = {0, 0};
  f->ect0 = f->ect1 = f->ce = 0;
  if (!f->has_ecn) return 1;
  if (!take_two(in, off, e)) return 0;
  f->ect0 = e[0];
  f->ect1 = e[1];
  return quic_varint_take(quic_span_of(in.p, in.n), off, &f->ce);
}

/* Read the ranges then any ECN counts after the prologue. */
static int take_ack_rest(quic_span in, usz *off, ackdec *d) {
  if (!take_ack_pairs(in, off, d)) return 0;
  return take_ack_ecn(in, off, d->f);
}

usz quic_ack_decode(const u8 *buf, usz n, quic_ack_frame *f) {
  quic_span in  = quic_span_of(buf, n);
  usz       off = 1; /* type byte */
  ackdec    d   = {f, 0, 0, 0};
  f->has_ecn    = (buf[0] == QUIC_FRAME_ACK_ECN);
  if (!take_ack_prologue(in, &off, &d)) return 0;
  if (!take_ack_rest(in, &off, &d)) return 0;
  f->n_ranges = (usz)d.count + 1;
  return off;
}
