#include "test.h"

static xskring xskt_make(u32* prod, u32* cons, void* desc, u32 size) {
  xskring      r;
  xskring_view v = {prod, cons, desc, size};
  xskring_init(&r, &v);
  return r;
}

/* 1: an empty ring has nothing to consume. */
static void test_xskring_empty_peek(void) {
  u32     prod = 0, cons = 0;
  u64     desc[8];
  xskring r = xskt_make(&prod, &cons, desc, 8);
  u32     idx;
  CHECK(xskring_cons_peek(&r, 1, &idx) == 0);
}

/* 2: reserving past capacity grants only what fits. */
static void test_xskring_reserve_caps_at_capacity(void) {
  u32     prod = 0, cons = 0;
  u64     desc[8];
  xskring r = xskt_make(&prod, &cons, desc, 8);
  u32     idx;
  CHECK(xskring_prod_reserve(&r, 8, &idx) == 8);
  xskring_prod_submit(&r, 8);
  CHECK(xskring_prod_reserve(&r, 1, &idx) == 0);
}

/* 3: what's produced is what's peeked, in order, at the right slots. */
static void test_xskring_produce_then_peek(void) {
  u32     prod = 0, cons = 0;
  u64     desc[8];
  xskring r = xskt_make(&prod, &cons, desc, 8);
  u32     idx;
  CHECK(xskring_prod_reserve(&r, 3, &idx) == 3 && idx == 0);
  *xskring_addr_at(&r, 0) = 100;
  *xskring_addr_at(&r, 1) = 101;
  *xskring_addr_at(&r, 2) = 102;
  xskring_prod_submit(&r, 3);

  CHECK(xskring_cons_peek(&r, 3, &idx) == 3 && idx == 0);
  CHECK(*xskring_addr_at(&r, 0) == 100);
  CHECK(*xskring_addr_at(&r, 1) == 101);
  CHECK(*xskring_addr_at(&r, 2) == 102);
  xskring_cons_release(&r, 3);
  CHECK(xskring_cons_peek(&r, 1, &idx) == 0);
}

/* 4: wraparound over many cycles never corrupts a reused slot. */
static void test_xskring_wraparound(void) {
  u32     prod = 0, cons = 0;
  u64     desc[8];
  xskring r = xskt_make(&prod, &cons, desc, 8);
  for (u32 cycle = 0; cycle < 25; cycle++) {
    u32 idx;
    CHECK(xskring_prod_reserve(&r, 3, &idx) == 3);
    for (u32 i = 0; i < 3; i++)
      *xskring_addr_at(&r, idx + i) = 1000 + cycle * 3 + i;
    xskring_prod_submit(&r, 3);

    CHECK(xskring_cons_peek(&r, 3, &idx) == 3);
    for (u32 i = 0; i < 3; i++)
      CHECK(*xskring_addr_at(&r, idx + i) == 1000 + cycle * 3 + i);
    xskring_cons_release(&r, 3);
  }
}

/* 5: u32 index overflow wraps correctly through free/avail arithmetic. */
static void test_xskring_index_overflow(void) {
  u32     prod = 0xfffffffeu, cons = 0xfffffffeu;
  u64     desc[8];
  xskring r = xskt_make(&prod, &cons, desc, 8);
  u32     idx;
  CHECK(xskring_prod_reserve(&r, 4, &idx) == 4 && idx == 0xfffffffeu);
  xskring_prod_submit(&r, 4);
  CHECK(prod == 2u); /* wrapped past 0xffffffff */

  CHECK(xskring_cons_peek(&r, 4, &idx) == 4 && idx == 0xfffffffeu);
  xskring_cons_release(&r, 4);
  CHECK(cons == 2u);
  CHECK(xskring_cons_peek(&r, 1, &idx) == 0);
}

/* Tiny fixed-seed LCG: no libc rand(), just a deterministic PRNG. */
static u32 xskt_lcg(u32* state) {
  *state = *state * 1103515245u + 12345u;
  return *state;
}

/* Soak test asserting the occupancy invariant: occupancy never exceeds
 * capacity, for either raw (unmasked) index difference. */
static void test_xskring_soak_invariant(void) {
  u32      prod = 0, cons = 0;
  xdp_desc desc[8];
  xskring  r     = xskt_make(&prod, &cons, desc, 8);
  u32      state = 42;
  for (int i = 0; i < 1000; i++) {
    u32 pick = xskt_lcg(&state) % 5;
    u32 idx;
    if (pick < 3) {
      u32 g = xskring_prod_reserve(&r, pick + 1, &idx);
      if (g) xskring_prod_submit(&r, g);
    } else {
      u32 g = xskring_cons_peek(&r, pick - 2, &idx);
      if (g) xskring_cons_release(&r, g);
    }
    CHECK(prod - cons <= 8);
  }
}

/* 7: addr_at / desc_at hit the exact slot offsets in the raw arrays. */
static void test_xskring_accessors(void) {
  u32     prod = 0, cons = 0;
  u64     udesc[4]         = {0, 0, 0, 0};
  xskring ur               = xskt_make(&prod, &cons, udesc, 4);
  *xskring_addr_at(&ur, 2) = 0xdeadbeefu;
  CHECK(udesc[2] == 0xdeadbeefu);

  xdp_desc ddesc[4];
  for (usz i = 0; i < 4; i++) {
    ddesc[i].addr    = 0;
    ddesc[i].len     = 0;
    ddesc[i].options = 0;
  }
  xskring   dr = xskt_make(&prod, &cons, ddesc, 4);
  xdp_desc* d  = xskring_desc_at(&dr, 1);
  d->addr      = 7;
  d->len       = 9;
  d->options   = 11;
  CHECK(ddesc[1].addr == 7 && ddesc[1].len == 9 && ddesc[1].options == 11);
  /* mask wraps a raw index past size back to the same slot */
  CHECK(xskring_desc_at(&dr, 1 + 4) == &ddesc[1]);
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
