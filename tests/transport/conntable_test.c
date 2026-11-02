#include "test.h"

/* RFC 9000 5.1/5.2: route inbound datagrams to one of several live connection
 * slots by Destination Connection ID. Covers insert/find/remove and the
 * capacity/duplicate/oversized-CID edge cases. */
void test_conntable(void) {
  conntable t[4];
  conntable_init(t, 4);

  const u8 cid_a[] = {0xAA, 0xAA};
  const u8 cid_b[] = {0xBB, 0xBB, 0xBB};

  /* empty table: nothing found */
  CHECK(conntable_find(t, 4, cid_a, 2) == -1);

  int ia = conntable_insert(t, 4, cid_a, 2);
  CHECK(ia >= 0);
  CHECK(conntable_find(t, 4, cid_a, 2) == ia);
  /* different CID, same length prefix: no match */
  CHECK(conntable_find(t, 4, cid_b, 3) == -1);

  int ib = conntable_insert(t, 4, cid_b, 3);
  CHECK(ib >= 0);
  CHECK(ib != ia);
  CHECK(conntable_find(t, 4, cid_b, 3) == ib);

  /* remove frees the slot; find no longer matches */
  conntable_remove(t, 4, ia);
  CHECK(conntable_find(t, 4, cid_a, 2) == -1);
  /* the other connection is unaffected */
  CHECK(conntable_find(t, 4, cid_b, 3) == ib);

  /* the freed slot can be reused */
  int ia2 = conntable_insert(t, 4, cid_a, 2);
  CHECK(ia2 == ia);

  /* fill remaining capacity (ia2, ib already live: 2 of 4), then overflow */
  const u8 cid_c[] = {0xCC};
  const u8 cid_d[] = {0xDD};
  const u8 cid_e[] = {0xEE};
  int      ic      = conntable_insert(t, 4, cid_c, 1);
  CHECK(ic >= 0);
  CHECK(conntable_insert(t, 4, cid_d, 1) >= 0);  /* last free slot */
  CHECK(conntable_insert(t, 4, cid_e, 1) == -1); /* table full */

  /* oversized CID is rejected regardless of free slots */
  conntable_remove(t, 4, ic);
  u8 too_long[WIRED_MAX_CID_LEN + 1] = {0};
  CHECK(conntable_insert(t, 4, too_long, WIRED_MAX_CID_LEN + 1) == -1);

  /* rekey adds a slot's new CID alongside the old one (RFC 9000 5.1: several
   * CIDs may route to the same connection; the old DCID must keep routing so
   * a client Initial retransmitted before it has seen the new SCID -- e.g.
   * because the first flight was lost -- still reaches this same slot
   * instead of spawning a duplicate connection, RFC 9000 7.2/17.2.2). */
  const u8 cid_f[] = {0xF0, 0xF1, 0xF2, 0xF3};
  CHECK(conntable_rekey(t, 4, ib, cid_f, 4) == 1);
  CHECK(conntable_find(t, 4, cid_b, 3) == ib); /* old key still routes */
  CHECK(conntable_find(t, 4, cid_f, 4) == ib); /* new key routes too */

  /* rekey rejects an oversized CID and leaves both keys untouched */
  CHECK(conntable_rekey(t, 4, ib, too_long, WIRED_MAX_CID_LEN + 1) == 0);
  CHECK(conntable_find(t, 4, cid_b, 3) == ib);
  CHECK(conntable_find(t, 4, cid_f, 4) == ib);

  /* removing the slot un-routes both its CIDs */
  conntable_remove(t, 4, ib);
  CHECK(conntable_find(t, 4, cid_b, 3) == -1);
  CHECK(conntable_find(t, 4, cid_f, 4) == -1);

  /* rekey rejects an out-of-range index */
  CHECK(conntable_rekey(t, 4, -1, cid_f, 4) == 0);
  CHECK(conntable_rekey(t, 4, 4, cid_f, 4) == 0);
}

#define CONNTABLE_T_CAP 64

/* CID number k of slot s: 3 per slot, 8 bytes, distinct by (s, k). */
static void conntable_t_cid(u8 out[8], int s, int k) {
  for (int j = 0; j < 8; j++) {
    out[j] = (u8)(s * 3 + k + j * 0x11);
  }
}

/* Fill every slot with a primary + alt (rekey) + alt2: 3 CIDs per slot, the
 * index's worst-case load, so probe chains and collisions are certain. */
static void conntable_t_fill(conntable* t) {
  u8 c[8];
  conntable_init(t, CONNTABLE_T_CAP);
  for (int s = 0; s < CONNTABLE_T_CAP; s++) {
    conntable_t_cid(c, s, 0);
    CHECK(conntable_insert(t, CONNTABLE_T_CAP, c, 8) == s);
    conntable_t_cid(c, s, 1);
    CHECK(conntable_rekey(t, CONNTABLE_T_CAP, s, c, 8) == 1);
    conntable_t_cid(c, s, 2);
    CHECK(conntable_set_alt2(t, CONNTABLE_T_CAP, s, c, 8) == 1);
  }
}

/* 1 if every CID of slot s routes to want (s itself, or -1 once removed). */
static int conntable_t_routes(const conntable* t, int s, int want) {
  u8  c[8];
  int ok = 1;
  for (int k = 0; k < 3; k++) {
    conntable_t_cid(c, s, k);
    ok = ok && conntable_find(t, CONNTABLE_T_CAP, c, 8) == want;
  }
  return ok;
}

static void conntable_t_edges(void);

/* #199: the hashed index routes all 3 CIDs of every slot at full capacity,
 * and stays consistent through remove (the CIDs further down a removed
 * entry's probe chain still route), CID retirement (set_cid) and alt2
 * replacement. */
void test_conntable_hash(void) {
  static conntable t[CONNTABLE_T_CAP];
  conntable_t_fill(t);
  int all = 1;
  for (int s = 0; s < CONNTABLE_T_CAP; s++) {
    all = all && conntable_t_routes(t, s, s);
  }
  CHECK(all);
  u8 c[8];
  conntable_t_cid(c, CONNTABLE_T_CAP, 0); /* never inserted */
  CHECK(conntable_find(t, CONNTABLE_T_CAP, c, 8) == -1);
  CHECK(conntable_insert(t, CONNTABLE_T_CAP, c, 8) == -1); /* full */

  for (int s = 0; s < CONNTABLE_T_CAP; s += 2) {
    conntable_remove(t, CONNTABLE_T_CAP, s);
  }
  all = 1;
  for (int s = 0; s < CONNTABLE_T_CAP; s++) {
    all = all && conntable_t_routes(t, s, (s & 1) ? s : -1);
  }
  CHECK(all);

  /* RFC 9000 5.1.2: a retired primary stops routing, its replacement routes */
  u8 old[8];
  u8 nu[8] = {0xFE, 0xED, 0, 0, 0, 0, 0, 1};
  conntable_t_cid(old, 1, 1); /* primary after rekey */
  CHECK(conntable_set_cid(t, CONNTABLE_T_CAP, 1, nu, 8) == 1);
  CHECK(conntable_find(t, CONNTABLE_T_CAP, old, 8) == -1);
  CHECK(conntable_find(t, CONNTABLE_T_CAP, nu, 8) == 1);

  /* a replaced alt2 stops routing */
  conntable_t_cid(old, 3, 2);
  nu[7] = 3;
  CHECK(conntable_set_alt2(t, CONNTABLE_T_CAP, 3, nu, 8) == 1);
  CHECK(conntable_find(t, CONNTABLE_T_CAP, old, 8) == -1);
  CHECK(conntable_find(t, CONNTABLE_T_CAP, nu, 8) == 3);

  /* a freed slot is reused and its new CID routes */
  conntable_t_cid(c, CONNTABLE_T_CAP + 1, 0);
  CHECK(conntable_insert(t, CONNTABLE_T_CAP, c, 8) == 0);
  CHECK(conntable_find(t, CONNTABLE_T_CAP, c, 8) == 0);
  conntable_t_edges();
}

/* Up to n CIDs (conntable_t_cid(.., 100 + j, 0)) whose home bucket in a
 * cap-4 table is b, written to out; returns how many were found. */
static int conntable_t_homed(const conntable* t, usz b, u8 out[][8], int n) {
  int got = 0;
  for (int j = 0; j < 4096 && got < n; j++) {
    conntable_t_cid(out[got], 100 + j, 0);
    got += conntable_home(t, wired_span_of(out[got], 8), 4 * CONNTABLE_HB) == b;
  }
  return got;
}

/* #199: CIDs sharing one home bucket all route, and removing the head of the
 * probe chain keeps the rest routing. */
static void conntable_t_collide(void) {
  conntable t[4];
  u8        c[3][8];
  conntable_init(t, 4);
  CHECK(conntable_t_homed(t, 5, c, 3) == 3);
  for (int i = 0; i < 3; i++) {
    CHECK(conntable_insert(t, 4, c[i], 8) == i);
  }
  CHECK(conntable_find(t, 4, c[2], 8) == 2);
  conntable_remove(t, 4, 0);
  CHECK(conntable_find(t, 4, c[0], 8) == -1);
  CHECK(conntable_find(t, 4, c[1], 8) == 1);
  CHECK(conntable_find(t, 4, c[2], 8) == 2);
}

/* A chain starting at the last bucket wraps to bucket 0. */
static void conntable_t_wrap(void) {
  conntable t[4];
  u8        c[2][8];
  usz       last = 4 * CONNTABLE_HB - 1;
  conntable_init(t, 4);
  CHECK(conntable_t_homed(t, last, c, 2) == 2);
  CHECK(conntable_insert(t, 4, c[0], 8) == 0);
  CHECK(conntable_insert(t, 4, c[1], 8) == 1);
  CHECK(*conntable_bucket(t, last) == 1);
  CHECK(*conntable_bucket(t, 0) == 2);
  CHECK(conntable_find(t, 4, c[1], 8) == 1);
}

/* Reusing slot 0 drops all 3 CIDs of its previous connection. */
static void conntable_t_reuse(void) {
  static conntable t[CONNTABLE_T_CAP];
  u8               c[8];
  conntable_t_fill(t);
  conntable_remove(t, CONNTABLE_T_CAP, 0);
  conntable_t_cid(c, CONNTABLE_T_CAP + 2, 0);
  CHECK(conntable_insert(t, CONNTABLE_T_CAP, c, 8) == 0);
  CHECK(conntable_t_routes(t, 0, -1));
  CHECK(conntable_find(t, CONNTABLE_T_CAP, c, 8) == 0);
}

/* 1 if any of 16 CIDs gets a different home under seeds a and b. */
static int conntable_t_seed_moves(conntable* t, u32 a, u32 b) {
  u8  c[8];
  int moved = 0;
  for (int j = 0; j < 16; j++) {
    conntable_t_cid(c, j, 0);
    conntable_seed(t, CONNTABLE_T_CAP, a);
    usz ha = conntable_home(t, wired_span_of(c, 8), CONNTABLE_T_CAP * 4);
    conntable_seed(t, CONNTABLE_T_CAP, b);
    moved |= ha != conntable_home(t, wired_span_of(c, 8), CONNTABLE_T_CAP * 4);
  }
  return moved;
}

/* #199 review: the per-table seed moves the buckets (a client cannot
 * precompute collisions) and a reseed keeps every CID routing. */
static void conntable_t_seeded(void) {
  static conntable t[CONNTABLE_T_CAP];
  conntable_t_fill(t);
  CHECK(conntable_t_seed_moves(t, 1, 0x9E3779B9u));
  int all = 1;
  for (int s = 0; s < CONNTABLE_T_CAP; s++) {
    all = all && conntable_t_routes(t, s, s);
  }
  CHECK(all);
}

static void conntable_t_edges(void) {
  conntable_t_collide();
  conntable_t_wrap();
  conntable_t_reuse();
  conntable_t_seeded();
}
