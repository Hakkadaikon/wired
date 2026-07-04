#include "transport/conn/lifecycle/conn/pnspace.h"

/* RFC 9000 12.3 */
void quic_pnspace_init(quic_pnspace* s) {
  for (usz i = 0; i < QUIC_PNS_COUNT; i++) s->next[i] = 0;
}

u64 quic_pnspace_next(quic_pnspace* s, quic_pns_space space) {
  u64 pn = s->next[space];
  s->next[space] += 1; /* strictly monotonic: no reuse, no regress */
  return pn;
}
