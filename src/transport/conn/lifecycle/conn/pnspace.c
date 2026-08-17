#include "transport/conn/lifecycle/conn/pnspace.h"

/* RFC 9000 12.3 */
void pnspace_init(pnspace* s) {
  for (usz i = 0; i < QUIC_PNS_COUNT; i++) s->next[i] = 0;
}

u64 pnspace_next(pnspace* s, pns_space space) {
  u64 pn = s->next[space];
  s->next[space] += 1; /* strictly monotonic: no reuse, no regress */
  return pn;
}

int pnspace_exhausted(const pnspace* s, pns_space space) {
  return s->next[space] > QUIC_PN_LIMIT;
}
