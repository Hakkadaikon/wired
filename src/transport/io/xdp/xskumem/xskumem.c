#include "transport/io/xdp/xskumem/xskumem.h"

void quic_xskumem_alloc_init(
    quic_xskumem_alloc* a, u64 base_addr, u32 nframes) {
  u32 n = nframes;
  if (n > QUIC_XSKUMEM_FRAMES) {
    n = QUIC_XSKUMEM_FRAMES;
  }
  for (u32 i = 0; i < n; i++) {
    a->free[i] = base_addr + (u64)i * QUIC_XSKUMEM_FRAME_SIZE;
  }
  a->nfree = n;
}

i64 quic_xskumem_alloc_get(quic_xskumem_alloc* a) {
  if (a->nfree == 0) {
    return -1;
  }
  a->nfree--;
  return (i64)a->free[a->nfree];
}

void quic_xskumem_alloc_put(quic_xskumem_alloc* a, u64 addr) {
  if (a->nfree >= QUIC_XSKUMEM_FRAMES) {
    return;
  }
  a->free[a->nfree] = addr;
  a->nfree++;
}
