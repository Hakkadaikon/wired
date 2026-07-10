#include "test.h"

static quic_xskring xskt_make(u32* prod, u32* cons, void* desc, u32 size) {
  quic_xskring      r;
  quic_xskring_view v = {prod, cons, desc, size};
  quic_xskring_init(&r, &v);
  return r;
}

/* 1: an empty ring has nothing to consume. */
static void test_xskring_empty_peek(void) {
  u32          prod = 0, cons = 0;
  u64          desc[8];
  quic_xskring r = xskt_make(&prod, &cons, desc, 8);
  u32          idx;
  CHECK(quic_xskring_cons_peek(&r, 1, &idx) == 0);
}

/* 2: reserving past capacity grants only what fits. */
static void test_xskring_reserve_caps_at_capacity(void) {
  u32          prod = 0, cons = 0;
  u64          desc[8];
  quic_xskring r = xskt_make(&prod, &cons, desc, 8);
  u32          idx;
  CHECK(quic_xskring_prod_reserve(&r, 8, &idx) == 8);
  quic_xskring_prod_submit(&r, 8);
  CHECK(quic_xskring_prod_reserve(&r, 1, &idx) == 0);
}

/* 3: what's produced is what's peeked, in order, at the right slots. */
static void test_xskring_produce_then_peek(void) {
  u32          prod = 0, cons = 0;
  u64          desc[8];
  quic_xskring r = xskt_make(&prod, &cons, desc, 8);
  u32          idx;
  CHECK(quic_xskring_prod_reserve(&r, 3, &idx) == 3 && idx == 0);
  *quic_xskring_addr_at(&r, 0) = 100;
  *quic_xskring_addr_at(&r, 1) = 101;
  *quic_xskring_addr_at(&r, 2) = 102;
  quic_xskring_prod_submit(&r, 3);

  CHECK(quic_xskring_cons_peek(&r, 3, &idx) == 3 && idx == 0);
  CHECK(*quic_xskring_addr_at(&r, 0) == 100);
  CHECK(*quic_xskring_addr_at(&r, 1) == 101);
  CHECK(*quic_xskring_addr_at(&r, 2) == 102);
  quic_xskring_cons_release(&r, 3);
  CHECK(quic_xskring_cons_peek(&r, 1, &idx) == 0);
}

/* 4: wraparound over many cycles never corrupts a reused slot. */
static void test_xskring_wraparound(void) {
  u32          prod = 0, cons = 0;
  u64          desc[8];
  quic_xskring r = xskt_make(&prod, &cons, desc, 8);
  for (u32 cycle = 0; cycle < 25; cycle++) {
    u32 idx;
    CHECK(quic_xskring_prod_reserve(&r, 3, &idx) == 3);
    for (u32 i = 0; i < 3; i++)
      *quic_xskring_addr_at(&r, idx + i) = 1000 + cycle * 3 + i;
    quic_xskring_prod_submit(&r, 3);

    CHECK(quic_xskring_cons_peek(&r, 3, &idx) == 3);
    for (u32 i = 0; i < 3; i++)
      CHECK(*quic_xskring_addr_at(&r, idx + i) == 1000 + cycle * 3 + i);
    quic_xskring_cons_release(&r, 3);
  }
}

/* 5: u32 index overflow wraps correctly through free/avail arithmetic. */
static void test_xskring_index_overflow(void) {
  u32          prod = 0xfffffffeu, cons = 0xfffffffeu;
  u64          desc[8];
  quic_xskring r = xskt_make(&prod, &cons, desc, 8);
  u32          idx;
  CHECK(quic_xskring_prod_reserve(&r, 4, &idx) == 4 && idx == 0xfffffffeu);
  quic_xskring_prod_submit(&r, 4);
  CHECK(prod == 2u); /* wrapped past 0xffffffff */

  CHECK(quic_xskring_cons_peek(&r, 4, &idx) == 4 && idx == 0xfffffffeu);
  quic_xskring_cons_release(&r, 4);
  CHECK(cons == 2u);
  CHECK(quic_xskring_cons_peek(&r, 1, &idx) == 0);
}

/* Tiny fixed-seed LCG: no libc rand(), just a deterministic PRNG. */
static u32 xskt_lcg(u32* state) {
  *state = *state * 1103515245u + 12345u;
  return *state;
}

/* 6: soak test asserting the TLA+ InvOcc invariant: occupancy never
 * exceeds capacity, for either raw (unmasked) index difference. */
static void test_xskring_soak_invariant(void) {
  u32           prod = 0, cons = 0;
  quic_xdp_desc desc[8];
  quic_xskring  r     = xskt_make(&prod, &cons, desc, 8);
  u32           state = 42;
  for (int i = 0; i < 1000; i++) {
    u32 pick = xskt_lcg(&state) % 5;
    u32 idx;
    if (pick < 3) {
      u32 g = quic_xskring_prod_reserve(&r, pick + 1, &idx);
      if (g) quic_xskring_prod_submit(&r, g);
    } else {
      u32 g = quic_xskring_cons_peek(&r, pick - 2, &idx);
      if (g) quic_xskring_cons_release(&r, g);
    }
    CHECK(prod - cons <= 8);
  }
}

/* 7: addr_at / desc_at hit the exact slot offsets in the raw arrays. */
static void test_xskring_accessors(void) {
  u32          prod = 0, cons = 0;
  u64          udesc[4]         = {0, 0, 0, 0};
  quic_xskring ur               = xskt_make(&prod, &cons, udesc, 4);
  *quic_xskring_addr_at(&ur, 2) = 0xdeadbeefu;
  CHECK(udesc[2] == 0xdeadbeefu);

  quic_xdp_desc ddesc[4];
  for (usz i = 0; i < 4; i++) {
    ddesc[i].addr    = 0;
    ddesc[i].len     = 0;
    ddesc[i].options = 0;
  }
  quic_xskring   dr = xskt_make(&prod, &cons, ddesc, 4);
  quic_xdp_desc* d  = quic_xskring_desc_at(&dr, 1);
  d->addr           = 7;
  d->len            = 9;
  d->options        = 11;
  CHECK(ddesc[1].addr == 7 && ddesc[1].len == 9 && ddesc[1].options == 11);
  /* mask wraps a raw index past size back to the same slot */
  CHECK(quic_xskring_desc_at(&dr, 1 + 4) == &ddesc[1]);
}

void test_xskring(void) {
  test_xskring_empty_peek();
  test_xskring_reserve_caps_at_capacity();
  test_xskring_produce_then_peek();
  test_xskring_wraparound();
  test_xskring_index_overflow();
  test_xskring_soak_invariant();
  test_xskring_accessors();
}
