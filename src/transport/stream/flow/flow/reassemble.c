#include "transport/stream/flow/flow/reassemble.h"

void reasm_init(reasm* r) {
  for (usz i = 0; i < REASM_CAP; i++) {
    r->have[i] = 0;
  }
  r->delivered = 0;
}

int reasm_insert(reasm* r, u64 offset, wired_span data) {
  if (offset + data.n > REASM_CAP) {
    return 0;
  }
  for (usz i = 0; i < data.n; i++) {
    r->buf[offset + i]  = data.p[i]; /* idempotent: overlaps re-set */
    r->have[offset + i] = 1;
  }
  return 1;
}

u64 reasm_deliver(reasm* r) {
  while (r->delivered < REASM_CAP && r->have[r->delivered]) {
    r->delivered++;
  }
  return r->delivered;
}
