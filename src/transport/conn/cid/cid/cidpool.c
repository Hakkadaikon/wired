#include "transport/conn/cid/cid/cidpool.h"

void cidpool_init(cidpool* p, u64 limit) {
  p->limit     = limit;
  p->next_seq  = 0;
  p->retire_lo = 0;
}

u64 cidpool_active_count(const cidpool* p) {
  return p->next_seq - p->retire_lo;
}

int cidpool_issue(cidpool* p, u64* seq) {
  if (cidpool_active_count(p) >= p->limit) return 0;
  *seq = p->next_seq++;
  return 1;
}

int cidpool_retire_prior_to(cidpool* p, u64 retire_prior_to) {
  if (retire_prior_to > p->next_seq) return 0; /* retires an unissued seq */
  if (retire_prior_to > p->retire_lo) p->retire_lo = retire_prior_to;
  return 1;
}
