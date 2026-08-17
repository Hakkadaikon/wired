#include "transport/io/xdp/xskumem/xskumem.h"

void xskumem_alloc_init(xskumem_alloc* a, u64 base_addr, u32 nframes) {
  u32 n = nframes;
  if (n > XSKUMEM_FRAMES) {
    n = XSKUMEM_FRAMES;
  }
  for (u32 i = 0; i < n; i++) {
    a->free[i] = base_addr + (u64)i * XSKUMEM_FRAME_SIZE;
  }
  a->nfree = n;
}

i64 xskumem_alloc_get(xskumem_alloc* a) {
  if (a->nfree == 0) {
    return -1;
  }
  a->nfree--;
  return (i64)a->free[a->nfree];
}

void xskumem_alloc_put(xskumem_alloc* a, u64 addr) {
  if (a->nfree >= XSKUMEM_FRAMES) {
    return;
  }
  a->free[a->nfree] = addr;
  a->nfree++;
}
