#include "transport/conn/cid/cid/cidpool.h"

void quic_cidpool_init(quic_cidpool *p, u64 limit)
{
    p->limit = limit;
    p->next_seq = 0;
    p->retire_lo = 0;
}

u64 quic_cidpool_active_count(const quic_cidpool *p)
{
    return p->next_seq - p->retire_lo;
}

int quic_cidpool_issue(quic_cidpool *p, u64 *seq)
{
    if (quic_cidpool_active_count(p) >= p->limit) return 0;
    *seq = p->next_seq++;
    return 1;
}

int quic_cidpool_retire_prior_to(quic_cidpool *p, u64 retire_prior_to)
{
    if (retire_prior_to > p->next_seq) return 0; /* retires an unissued seq */
    if (retire_prior_to > p->retire_lo) p->retire_lo = retire_prior_to;
    return 1;
}
