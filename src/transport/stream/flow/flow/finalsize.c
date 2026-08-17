#include "transport/stream/flow/flow/finalsize.h"

void finalsize_init(finalsize* f) {
  f->highest    = 0;
  f->final_size = 0;
  f->known      = 0;
}

/* Track the highest offset+len seen; returns the new end of this data. */
static u64 note_highest(finalsize* f, u64 offset, u64 len) {
  u64 end = offset + len;
  if (end > f->highest) f->highest = end;
  return end;
}

int finalsize_data(finalsize* f, u64 offset, u64 len) {
  u64 end = note_highest(f, offset, len);
  if (!f->known) return 1;
  return end <= f->final_size; /* data past the final size is a violation */
}

/* A new final size is consistent if it equals any prior one and is not below
 * the highest offset already seen. */
static int size_consistent(const finalsize* f, u64 size) {
  if (f->known) return size == f->final_size;
  return size >= f->highest;
}

int finalsize_set(finalsize* f, u64 size) {
  if (!size_consistent(f, size)) return 0;
  f->final_size = size;
  f->known      = 1;
  return 1;
}

void dual_finalsize_init(dual_finalsize* d) {
  finalsize_init(&d->send);
  finalsize_init(&d->recv);
}

int dual_finalsize_reset_send(dual_finalsize* d, u64 size) {
  return finalsize_set(&d->send, size);
}

int dual_finalsize_reset_recv(dual_finalsize* d, u64 size) {
  return finalsize_set(&d->recv, size);
}
