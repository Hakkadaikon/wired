#include "transport/recovery/detect/ackgen/ackrangeconv.h"

/* 1 if n is a valid raw layout: at least the First ACK Range Length, then
 * zero or more complete (Gap, Range Length) pairs (odd total count). */
static int raw_layout_ok(usz n) { return n >= 1 && n % 2 == 1; }

/* Ranges the pairs after the first would add (n-1)/2), plus the first
 * itself, must fit f->ranges[]. */
static int range_count_ok(usz n) {
  usz pairs = (n - 1) / 2;
  return pairs + 1 <= QUIC_ACK_MAX_RANGES;
}

/* Fill f->ranges[0] (the First ACK Range) from largest and raw[0]. */
static void conv_first(u64 largest, u64 first_len, quic_ack_frame* f) {
  f->ranges[0].hi = largest;
  f->ranges[0].lo = largest - first_len;
}

/* Fill f->ranges[i] from the (gap, len) pair at raw[2i-1..2i], continuing
 * below the previous range's lo (RFC 9000 19.3.1: hi = prev_lo - gap - 2). */
static void conv_pair(
    const u64* raw, usz i, quic_ack_range* prev, quic_ack_range* cur) {
  u64 gap = raw[2 * i - 1];
  u64 len = raw[2 * i];
  cur->hi = prev->lo - gap - 2;
  cur->lo = cur->hi - len;
}

static int raw_ok(usz n) { return raw_layout_ok(n) && range_count_ok(n); }

static void conv_all_pairs(const u64* raw, usz n, quic_ack_frame* f) {
  usz i;
  for (i = 1; i <= (n - 1) / 2; i++)
    conv_pair(raw, i, &f->ranges[i - 1], &f->ranges[i]);
}

int quic_ackrangeconv_to_frame(
    u64 largest, const u64* raw, usz n, quic_ack_frame* f) {
  if (!raw_ok(n)) return 0;
  conv_first(largest, raw[0], f);
  conv_all_pairs(raw, n, f);
  f->n_ranges = (n - 1) / 2 + 1;
  return 1;
}
