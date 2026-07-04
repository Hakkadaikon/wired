#include "transport/recovery/detect/ackgen/ackrange.h"

/* RFC 9000 19.3.1: Gap between a lower block's smallest and the next block's
 * largest is (prev_lo - hi) - 2. */
static u64 gap_of(u64 prev_lo, u64 hi) { return prev_lo - hi - 2; }

/* Write one value, advancing out->len; 0 if it would exceed out->cap. */
static int push(quic_u64obuf* out, u64 v) {
  if (out->len >= out->cap) return 0;
  out->p[out->len++] = v;
  return 1;
}

/* Running state while descending the received list, plus the output buffer
 * (always threaded together). */
typedef struct {
  u64          hi;      /* largest pn of the block currently being scanned */
  u64          prev_lo; /* smallest pn of the last closed block */
  int          first;   /* the block to close next is the first (no gap) */
  quic_u64obuf out;
} build_st;

/* Append one block (length, plus a preceding gap for non-first blocks) to
 * s->out. Returns 0 if the write would exceed s->out.cap. */
static int ackrange_emit(build_st* s, u64 lo) {
  if (!s->first && !push(&s->out, gap_of(s->prev_lo, s->hi))) return 0;
  return push(&s->out, s->hi - lo); /* ACK Range Length = count - 1 */
}

/* Close the block ending at lo (a gap to the lower pn was found), recording
 * it and starting a new block at next_hi. Returns 0 on cap overflow. */
static int close_block(build_st* s, u64 lo, u64 next_hi) {
  if (!ackrange_emit(s, lo)) return 0;
  s->prev_lo = lo;
  s->hi      = next_hi;
  s->first   = 0;
  return 1;
}

/* One descent step at index i: continue the block, or close it at a gap. */
static int step(build_st* s, quic_u64view pns, usz i) {
  if (pns.p[i] - pns.p[i - 1] == 1) return 1; /* contiguous: extend block */
  return close_block(s, pns.p[i], pns.p[i - 1]);
}

/* Walk all blocks high-to-low, then close the final (lowest) block. */
static int descend(build_st* s, quic_u64view pns) {
  usz i;
  for (i = pns.n - 1; i > 0; i--)
    if (!step(s, pns, i)) return 0;
  return ackrange_emit(s, pns.p[0]);
}

int quic_ackgen_build_ranges(
    quic_u64view received_pns, u64* largest, quic_u64obuf* ranges) {
  build_st s = {0, 0, 1, {0, 0, 0}};

  if (received_pns.n == 0) return 0;
  *largest  = received_pns.p[received_pns.n - 1];
  s.hi      = received_pns.p[received_pns.n - 1];
  s.out     = *ranges;
  s.out.len = 0;
  if (!descend(&s, received_pns)) return 0;
  ranges->len = s.out.len;
  return 1;
}
