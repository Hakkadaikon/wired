#include "transport/conn/pnspace/recvpn/recvpn.h"

void recvpn_init(recvpn* r) {
  r->largest = 0;
  r->bitmap  = 0;
  r->any     = 0;
}

/* For pn below largest: in the window and its bit is set. */
static int below_seen(const recvpn* r, u64 pn) {
  u64 delta = r->largest - pn;
  if (delta > RECVPN_WINDOW) return 0; /* fell out of the window */
  return (int)((r->bitmap >> (delta - 1)) & 1u);
}

/* Classify pn against largest: 1 seen (==), 0 not (>), else check the window.
 */
static int seen_at_or_above(const recvpn* r, u64 pn) {
  if (pn == r->largest) return 1;
  return (pn > r->largest) ? 0 : below_seen(r, pn);
}

int recvpn_seen(const recvpn* r, u64 pn) {
  if (!r->any) return 0;
  return seen_at_or_above(r, pn);
}

/* Advance largest to pn, shifting the window and marking the old largest. */
static void recvpn_advance(recvpn* r, u64 pn) {
  u64 step    = pn - r->largest;
  u64 shifted = (step >= 64) ? 0 : (r->bitmap << step);
  u64 old_bit = (step <= 64) ? ((u64)1 << (step - 1)) : 0;
  r->bitmap   = shifted | old_bit;
  r->largest  = pn;
}

/* Set the bit for a pn at or below largest, if it is within the window. */
static void mark_below(recvpn* r, u64 pn) {
  u64 delta = r->largest - pn;
  if (delta == 0 || delta > RECVPN_WINDOW) return;
  r->bitmap |= (u64)1 << (delta - 1);
}

void recvpn_record(recvpn* r, u64 pn) {
  if (!r->any) {
    r->any     = 1;
    r->largest = pn;
    return;
  }
  if (pn > r->largest) {
    recvpn_advance(r, pn);
    return;
  }
  mark_below(r, pn);
}

/* Whether the run continues at offset i below largest. */
static int run_continues(const recvpn* r, u64 i) {
  return i < RECVPN_WINDOW && ((r->bitmap >> i) & 1u);
}

u64 recvpn_first_range(const recvpn* r) {
  u64 count = 0;
  if (!r->any) return 0;
  while (run_continues(r, count)) count++;
  return count; /* contiguous packets immediately below largest */
}
