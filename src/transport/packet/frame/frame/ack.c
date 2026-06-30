#include "transport/packet/frame/frame/ack.h"
#include "common/bytes/varint/varint.h"

/* Encode the (Gap, Range Length) pair for range i (i >= 1). Gap counts the
 * unacknowledged packets between the previous range's low and this range's
 * high: gap = prev.lo - cur.hi - 2 (RFC 9000 19.3). */
static int put_pair(u8 *buf, usz cap, usz *off, const quic_ack_range *prev,
                    const quic_ack_range *cur)
{
    if (!quic_varint_put(buf, cap, off, prev->lo - cur->hi - 2)) return 0;
    return quic_varint_put(buf, cap, off, cur->hi - cur->lo);
}

/* The frame type is 0x03 when ECN counts are present, else 0x02. */
static u64 ack_type(const quic_ack_frame *f)
{
    return f->has_ecn ? QUIC_FRAME_ACK_ECN : QUIC_FRAME_ACK;
}

/* Write type, largest, ack_delay (three varints). Returns 1 ok, 0. */
static int put_ack_meta(u8 *buf, usz cap, usz *off, const quic_ack_frame *f)
{
    if (!quic_varint_put(buf, cap, off, ack_type(f))) return 0;
    if (!quic_varint_put(buf, cap, off, f->ranges[0].hi)) return 0;
    return quic_varint_put(buf, cap, off, f->ack_delay);
}

/* Write three consecutive varints. Returns 1 ok, 0 on overflow. */
static int put_three(u8 *buf, usz cap, usz *off, u64 a, u64 b, u64 c)
{
    if (!quic_varint_put(buf, cap, off, a)) return 0;
    if (!quic_varint_put(buf, cap, off, b)) return 0;
    return quic_varint_put(buf, cap, off, c);
}

/* Append the ECN counts (ECT0, ECT1, CE) when present. Returns 1 ok, 0. */
static int put_ack_ecn(u8 *buf, usz cap, usz *off, const quic_ack_frame *f)
{
    if (!f->has_ecn) return 1;
    return put_three(buf, cap, off, f->ect0, f->ect1, f->ce);
}

/* Encode the fixed prologue: type, largest, ack_delay, range count, first. */
static int put_ack_head(u8 *buf, usz cap, usz *off, const quic_ack_frame *f)
{
    const quic_ack_range *r0 = &f->ranges[0];
    if (!put_ack_meta(buf, cap, off, f)) return 0;
    if (!quic_varint_put(buf, cap, off, f->n_ranges - 1)) return 0;
    return quic_varint_put(buf, cap, off, r0->hi - r0->lo);
}

/* Append all subsequent (Gap, Range Length) pairs. Returns 1 ok, 0 on error. */
static int put_ack_pairs(u8 *buf, usz cap, usz *off, const quic_ack_frame *f)
{
    int ok = 1;
    for (usz i = 1; i < f->n_ranges; i++)
        if (!put_pair(buf, cap, off, &f->ranges[i - 1], &f->ranges[i])) ok = 0;
    return ok;
}

/* A frame must carry between 1 and QUIC_ACK_MAX_RANGES ranges. */
static int ranges_ok(usz n) { return n != 0 && n <= QUIC_ACK_MAX_RANGES; }

/* Write all (Gap, Range Length) pairs then any ECN counts. */
static int put_ack_pairs_ecn(u8 *buf, usz cap, usz *off, const quic_ack_frame *f)
{
    if (!put_ack_pairs(buf, cap, off, f)) return 0;
    return put_ack_ecn(buf, cap, off, f);
}

/* Write the head then all pairs and ECN. Returns 1 ok, 0 on overflow. */
static int put_ack_body(u8 *buf, usz cap, usz *off, const quic_ack_frame *f)
{
    if (!put_ack_head(buf, cap, off, f)) return 0;
    return put_ack_pairs_ecn(buf, cap, off, f);
}

usz quic_ack_encode(u8 *buf, usz cap, const quic_ack_frame *f)
{
    usz off = 0;
    if (!ranges_ok(f->n_ranges)) return 0;
    if (!put_ack_body(buf, cap, &off, f)) return 0;
    return off;
}

/* Read largest, ack_delay, range count (three varints). Returns 1 ok, 0. */
static int take_ack_meta(const u8 *buf, usz n, usz *off, quic_ack_frame *f,
                         u64 *largest, u64 *count)
{
    if (!quic_varint_take(buf, n, off, largest)) return 0;
    if (!quic_varint_take(buf, n, off, &f->ack_delay)) return 0;
    return quic_varint_take(buf, n, off, count);
}

/* Read the First ACK Range and require it not to underflow below zero. */
static int take_first(const u8 *buf, usz n, usz *off, u64 largest, u64 *first)
{
    if (!quic_varint_take(buf, n, off, first)) return 0;
    return *first <= largest;
}

/* Read the prologue, filling ranges[0] and *count. Returns 1 ok, 0 bad. */
static int take_ack_head(const u8 *buf, usz n, usz *off, quic_ack_frame *f,
                         u64 *count)
{
    u64 largest, first;
    if (!take_ack_meta(buf, n, off, f, &largest, count)) return 0;
    if (!take_first(buf, n, off, largest, &first)) return 0;
    f->ranges[0].hi = largest;
    f->ranges[0].lo = largest - first;
    return 1;
}

/* A (gap, len) pair fits below prev_lo without underflowing past zero. */
static int pair_fits(u64 prev_lo, u64 gap, u64 len)
{
    return prev_lo >= gap + 2 && prev_lo - gap - 2 >= len;
}

/* Read two consecutive varints. Returns 1 ok, 0 if either is truncated. */
static int take_two(const u8 *buf, usz n, usz *off, u64 *a, u64 *b)
{
    if (!quic_varint_take(buf, n, off, a)) return 0;
    return quic_varint_take(buf, n, off, b);
}

/* Read one (Gap, Range Length) pair into ranges[i] from ranges[i-1]. */
static int take_pair(const u8 *buf, usz n, usz *off, quic_ack_frame *f, usz i)
{
    u64 gap, len, prev_lo = f->ranges[i - 1].lo;
    if (!take_two(buf, n, off, &gap, &len)) return 0;
    if (!pair_fits(prev_lo, gap, len)) return 0;
    f->ranges[i].hi = prev_lo - gap - 2;
    f->ranges[i].lo = f->ranges[i].hi - len;
    return 1;
}

/* Read `count` additional pairs (ranges 1..count). Returns 1 ok, 0 bad. */
static int take_ack_pairs(const u8 *buf, usz n, usz *off, quic_ack_frame *f,
                          u64 count)
{
    int ok = 1;
    for (u64 i = 1; i <= count; i++)
        if (!take_pair(buf, n, off, f, (usz)i)) ok = 0;
    return ok;
}

/* The decoded range count plus the first range must fit our fixed array. */
static int count_fits(u64 count)
{
    return count + 1 <= QUIC_ACK_MAX_RANGES;
}

/* Read the prologue and bound-check the range count together. */
static int take_ack_prologue(const u8 *buf, usz n, usz *off, quic_ack_frame *f,
                             u64 *count)
{
    if (!take_ack_head(buf, n, off, f, count)) return 0;
    return count_fits(*count);
}

/* Read the ECN counts when the type byte was 0x03. Returns 1 ok, 0 bad. */
static int take_ack_ecn(const u8 *buf, usz n, usz *off, quic_ack_frame *f)
{
    f->ect0 = f->ect1 = f->ce = 0;
    if (!f->has_ecn) return 1;
    if (!take_two(buf, n, off, &f->ect0, &f->ect1)) return 0;
    return quic_varint_take(buf, n, off, &f->ce);
}

/* Read the ranges then any ECN counts after the prologue. */
static int take_ack_rest(const u8 *buf, usz n, usz *off, quic_ack_frame *f,
                         u64 count)
{
    if (!take_ack_pairs(buf, n, off, f, count)) return 0;
    return take_ack_ecn(buf, n, off, f);
}

usz quic_ack_decode(const u8 *buf, usz n, quic_ack_frame *f)
{
    usz off = 1; /* type byte */
    u64 count;
    f->has_ecn = (buf[0] == QUIC_FRAME_ACK_ECN);
    if (!take_ack_prologue(buf, n, &off, f, &count)) return 0;
    if (!take_ack_rest(buf, n, &off, f, count)) return 0;
    f->n_ranges = (usz)count + 1;
    return off;
}
