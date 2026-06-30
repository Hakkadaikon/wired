#include "transport/stream/flow/flow/reassemble.h"

void quic_reasm_init(quic_reasm *r) {
  for (usz i = 0; i < QUIC_REASM_CAP; i++) r->have[i] = 0;
  r->delivered  = 0;
  r->final_size = 0;
  r->have_final = 0;
}

/* True if [offset, offset+len) fits the buffer and any known final size. */
static int insert_fits(const quic_reasm *r, u64 offset, usz len) {
  if (offset + len > QUIC_REASM_CAP) return 0;
  return !r->have_final || offset + len <= r->final_size;
}

int quic_reasm_insert(quic_reasm *r, u64 offset, const u8 *data, usz len) {
  if (!insert_fits(r, offset, len)) return 0;
  for (usz i = 0; i < len; i++) {
    r->buf[offset + i]  = data[i]; /* idempotent: overlapping data re-set */
    r->have[offset + i] = 1;
  }
  return 1;
}

int quic_reasm_set_final(quic_reasm *r, u64 final_size) {
  if (final_size > QUIC_REASM_CAP) return 0;
  r->final_size = final_size;
  r->have_final = 1;
  return 1;
}

u64 quic_reasm_deliver(quic_reasm *r) {
  while (r->delivered < QUIC_REASM_CAP && r->have[r->delivered]) r->delivered++;
  return r->delivered;
}
