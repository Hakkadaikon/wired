#include "ackgen/ackrange.h"

/* RFC 9000 19.3.1: Gap between a lower block's smallest and the next block's
 * largest is (prev_lo - hi) - 2. */
static u64 gap_of(u64 prev_lo, u64 hi)
{
    return prev_lo - hi - 2;
}

/* Write one value, advancing *w; 0 if it would exceed cap. */
static int push(u64 *ranges, usz *w, usz cap, u64 v)
{
    if (*w >= cap) return 0;
    ranges[(*w)++] = v;
    return 1;
}

/* Append one block (length, plus a preceding gap for non-first blocks) to the
 * output, advancing *w. Returns 0 if the write would exceed cap. */
static int ackrange_emit(u64 *ranges, usz *w, usz cap, int first,
                u64 prev_lo, u64 hi, u64 lo)
{
    if (!first && !push(ranges, w, cap, gap_of(prev_lo, hi))) return 0;
    return push(ranges, w, cap, hi - lo); /* ACK Range Length = count - 1 */
}

/* Running state while descending the received list. */
typedef struct {
    usz w;      /* values written */
    u64 hi;     /* largest pn of the block currently being scanned */
    u64 prev_lo;/* smallest pn of the last closed block */
    int first;  /* the block to close next is the first (no leading gap) */
} build_st;

/* Close the block ending at lo (a gap to the lower pn was found), recording it
 * and starting a new block at next_hi. Returns 0 on cap overflow. */
static int close_block(build_st *s, u64 *ranges, usz cap, u64 lo, u64 next_hi)
{
    if (!ackrange_emit(ranges, &s->w, cap, s->first, s->prev_lo, s->hi, lo)) return 0;
    s->prev_lo = lo;
    s->hi = next_hi;
    s->first = 0;
    return 1;
}

/* One descent step at index i: continue the block, or close it at a gap. */
static int step(build_st *s, const u64 *pns, usz i, u64 *ranges, usz cap)
{
    if (pns[i] - pns[i - 1] == 1) return 1; /* contiguous: extend block */
    return close_block(s, ranges, cap, pns[i], pns[i - 1]);
}

/* Walk all blocks high-to-low, then close the final (lowest) block. */
static int descend(build_st *s, const u64 *pns, usz n, u64 *ranges, usz cap)
{
    usz i;
    for (i = n - 1; i > 0; i--)
        if (!step(s, pns, i, ranges, cap)) return 0;
    return ackrange_emit(ranges, &s->w, cap, s->first, s->prev_lo, s->hi, pns[0]);
}

int quic_ackgen_build_ranges(const u64 *received_pns, usz n, u64 *largest,
                             u64 *ranges, usz *n_ranges, usz cap)
{
    build_st s = {0, 0, 0, 1};

    if (n == 0) return 0;
    *largest = received_pns[n - 1];
    s.hi = received_pns[n - 1];
    if (!descend(&s, received_pns, n, ranges, cap)) return 0;
    *n_ranges = s.w;
    return 1;
}
