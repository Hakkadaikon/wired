#include "transport/packet/frame/frame/ack_impl.h"

static int  pair_fits(u64 prev_lo, u64 gap, u64 len);
static int  take_two(wired_span in, usz* off, u64 v[2]);
static void pair_store(ack_range* cur, u64 hi, u64 lo);
static int  take_pair(wired_span in, usz* off, u64* prev_lo, ack_range* cur);
static ack_range* pair_slot(ackdec* d, u64 i);
static int        take_ack_pairs(wired_span in, usz* off, ackdec* d);
static usz        ranges_kept(u64 count);
static int        take_ack_ecn(wired_span in, usz* off, ack_frame* f);
static int        take_ack_rest(wired_span in, usz* off, ackdec* d);

/* A (gap, len) pair fits below prev_lo without underflowing past zero. */
static int pair_fits(u64 prev_lo, u64 gap, u64 len) {
  return prev_lo >= gap + 2 && prev_lo - gap - 2 >= len;
}

/* Read two consecutive varints into v[0], v[1]. Returns 1 ok, 0 truncated. */
static int take_two(wired_span in, usz* off, u64 v[2]) {
  if (!varint_take(wired_span_of(in.p, in.n), off, &v[0])) {
    return 0;
  }
  return varint_take(wired_span_of(in.p, in.n), off, &v[1]);
}

/* Store one decoded range when a slot exists (cur may be null: ranges past
 * ACK_MAX_RANGES are parsed to consume their bytes, then dropped). */
static void pair_store(ack_range* cur, u64 hi, u64 lo) {
  if (!cur) {
    return;
  }
  cur->hi = hi;
  cur->lo = lo;
}

/* Read one (Gap, Range Length) pair, chaining down from *prev_lo. */
static int take_pair(wired_span in, usz* off, u64* prev_lo, ack_range* cur) {
  u64 gl[2], hi;
  if (!take_two(in, off, gl)) {
    return 0;
  }
  if (!pair_fits(*prev_lo, gl[0], gl[1])) {
    return 0;
  }
  hi = *prev_lo - gl[0] - 2;
  pair_store(cur, hi, hi - gl[1]);
  *prev_lo = hi - gl[1];
  return 1;
}

/* ranges[i]'s slot, or null once i is past our fixed array. */
static ack_range* pair_slot(ackdec* d, u64 i) {
  return i < ACK_MAX_RANGES ? &d->f->ranges[(usz)i] : 0;
}

/* Read d->count additional pairs (ranges 1..count). Every pair is parsed
 * (the frame's bytes must be consumed for the walk to continue past it),
 * but only the first ACK_MAX_RANGES ranges -- the ones nearest Largest
 * Acknowledged, exactly the pns still in flight -- are kept. RFC 9000 does
 * not bound the range count, and a real peer (quinn, under 30% loss) sent
 * 34 ranges; rejecting the whole frame at our array bound threw away every
 * later ACK and the connection retransmitted the same packets to death. */
static int take_ack_pairs(wired_span in, usz* off, ackdec* d) {
  u64 prev_lo = d->f->ranges[0].lo;
  for (u64 i = 1; i <= d->count; i++) {
    if (!take_pair(in, off, &prev_lo, pair_slot(d, i))) {
      return 0;
    }
  }
  return 1;
}

/* The ranges actually kept in f->ranges (see take_ack_pairs). */
static usz ranges_kept(u64 count) {
  return count + 1 <= ACK_MAX_RANGES ? (usz)count + 1 : ACK_MAX_RANGES;
}

/* Read the ECN counts when the type byte was 0x03. Returns 1 ok, 0 bad. */
static int take_ack_ecn(wired_span in, usz* off, ack_frame* f) {
  u64 e[2] = {0, 0};
  f->ect0 = f->ect1 = f->ce = 0;
  if (!f->has_ecn) {
    return 1;
  }
  if (!take_two(in, off, e)) {
    return 0;
  }
  f->ect0 = e[0];
  f->ect1 = e[1];
  return varint_take(wired_span_of(in.p, in.n), off, &f->ce);
}

/* Read the ranges then any ECN counts after the prologue. */
static int take_ack_rest(wired_span in, usz* off, ackdec* d) {
  if (!take_ack_pairs(in, off, d)) {
    return 0;
  }
  return take_ack_ecn(in, off, d->f);
}

usz ack_decode(const u8* buf, usz n, ack_frame* f) {
  wired_span in  = wired_span_of(buf, n);
  usz        off = 1; /* type byte */
  ackdec     d   = {f, 0, 0, 0};
  f->has_ecn     = (buf[0] == FRAME_ACK_ECN);
  if (!ack_take_ack_head(in, &off, &d)) {
    return 0;
  }
  if (!take_ack_rest(in, &off, &d)) {
    return 0;
  }
  f->n_ranges = ranges_kept(d.count);
  return off;
}
