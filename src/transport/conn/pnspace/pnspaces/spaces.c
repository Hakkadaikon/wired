#include "transport/conn/pnspace/pnspaces/spaces.h"

void pnspaces_init(pnspaces* s) { pnspace_init(&s->pn); }

u64 pnspaces_next_pn(pnspaces* s, int space) {
  return pnspace_next(&s->pn, (pns_space)space);
}

int pnspaces_exhausted(const pnspaces* s, int space) {
  return pnspace_exhausted(&s->pn, (pns_space)space);
}
