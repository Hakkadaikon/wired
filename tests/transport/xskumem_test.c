#include "transport/io/xdp/xskumem/xskumem.h"

#include "test.h"

static int xskumem_addr_valid(u64 addr, u32 nframes) {
  return addr % QUIC_XSKUMEM_FRAME_SIZE == 0 &&
         addr < (u64)nframes * QUIC_XSKUMEM_FRAME_SIZE;
}

static void test_xskumem_drain_all(void) {
  quic_xskumem_alloc a;
  u8                 seen[QUIC_XSKUMEM_FRAMES];
  quic_xskumem_alloc_init(&a, 0, 64);

  for (u32 i = 0; i < 64; i++) {
    seen[i] = 0;
  }

  for (u32 i = 0; i < 64; i++) {
    i64 v = quic_xskumem_alloc_get(&a);
    CHECK(v >= 0);
    CHECK(xskumem_addr_valid((u64)v, 64));
    u32 idx = (u32)((u64)v / QUIC_XSKUMEM_FRAME_SIZE);
    CHECK(seen[idx] == 0);
    seen[idx] = 1;
  }

  CHECK(quic_xskumem_alloc_get(&a) == -1);
}

/* Simple deterministic LCG so the soak test is reproducible. */
static u32 xskumem_lcg(u32* state) {
  *state = *state * 1103515245u + 12345u;
  return *state;
}

static void test_xskumem_soak_conservation(void) {
  quic_xskumem_alloc a;
  u8                 out[QUIC_XSKUMEM_FRAMES]; /* oracle: is frame i on loan? */
  u64                loaned[QUIC_XSKUMEM_FRAMES];
  u32                nloaned = 0;
  u32                rng     = 12345;
  quic_xskumem_alloc_init(&a, 0, QUIC_XSKUMEM_FRAMES);

  for (u32 i = 0; i < QUIC_XSKUMEM_FRAMES; i++) {
    out[i] = 0;
  }

  for (u32 step = 0; step < 500; step++) {
    int do_get = (nloaned == 0) ||
                 (xskumem_lcg(&rng) % 2 == 0 && nloaned < QUIC_XSKUMEM_FRAMES);
    if (do_get) {
      i64 v = quic_xskumem_alloc_get(&a);
      if (v >= 0) {
        u32 idx = (u32)((u64)v / QUIC_XSKUMEM_FRAME_SIZE);
        CHECK(out[idx] == 0); /* no double-loan */
        out[idx]          = 1;
        loaned[nloaned++] = (u64)v;
      }
    } else {
      u32 pick     = xskumem_lcg(&rng) % nloaned;
      u64 addr     = loaned[pick];
      loaned[pick] = loaned[--nloaned];
      u32 idx      = (u32)(addr / QUIC_XSKUMEM_FRAME_SIZE);
      out[idx]     = 0;
      quic_xskumem_alloc_put(&a, addr);
    }
    CHECK(nloaned <= QUIC_XSKUMEM_FRAMES);
  }
}

static void test_xskumem_lifo_reuse(void) {
  quic_xskumem_alloc a;
  quic_xskumem_alloc_init(&a, 0, 64);

  for (u32 i = 0; i < 64; i++) {
    CHECK(quic_xskumem_alloc_get(&a) >= 0);
  }
  CHECK(quic_xskumem_alloc_get(&a) == -1);

  u64 freed = 5 * QUIC_XSKUMEM_FRAME_SIZE;
  quic_xskumem_alloc_put(&a, freed);

  i64 v = quic_xskumem_alloc_get(&a);
  CHECK(v == (i64)freed);
  CHECK(quic_xskumem_alloc_get(&a) == -1);
}

void test_xskumem(void) {
  test_xskumem_drain_all();
  test_xskumem_soak_conservation();
  test_xskumem_lifo_reuse();
}
