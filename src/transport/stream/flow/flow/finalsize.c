#include "transport/stream/flow/flow/finalsize.h"

void quic_finalsize_init(quic_finalsize *f) {
  f->highest    = 0;
  f->final_size = 0;
  f->known      = 0;
}

/* Track the highest offset+len seen; returns the new end of this data. */
static u64 note_highest(quic_finalsize *f, u64 offset, u64 len) {
  u64 end = offset + len;
  if (end > f->highest) f->highest = end;
  return end;
}

int quic_finalsize_data(quic_finalsize *f, u64 offset, u64 len) {
  u64 end = note_highest(f, offset, len);
  if (!f->known) return 1;
  return end <= f->final_size; /* data past the final size is a violation */
}

/* A new final size is consistent if it equals any prior one and is not below
 * the highest offset already seen. */
static int size_consistent(const quic_finalsize *f, u64 size) {
  if (f->known) return size == f->final_size;
  return size >= f->highest;
}

int quic_finalsize_set(quic_finalsize *f, u64 size) {
  if (!size_consistent(f, size)) return 0;
  f->final_size = size;
  f->known      = 1;
  return 1;
}
