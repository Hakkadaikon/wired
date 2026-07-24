#include "transport/conn/pnspace/pnspaces/spaces.h"

void quic_pnspaces_init(quic_pnspaces* s) { quic_pnspace_init(&s->pn); }

u64 quic_pnspaces_next_pn(quic_pnspaces* s, int space) {
  return quic_pnspace_next(&s->pn, (quic_pns_space)space);
}

int quic_pnspaces_exhausted(const quic_pnspaces* s, int space) {
  return quic_pnspace_exhausted(&s->pn, (quic_pns_space)space);
}
