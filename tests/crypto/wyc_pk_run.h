#ifndef WYC_PK_RUN_H
#define WYC_PK_RUN_H

#include "test.h"
#include "vectors/wycheproof/wyc_vec.h"

/* Shared Wycheproof driver. A per-primitive runner returns one of
 * WYC_PK_REJECT / WYC_PK_ACCEPT / WYC_PK_BROKEN (accepted with a wrong output
 * or an undecodable vector: a failure for every result class). Expected results
 * come only from the Wycheproof JSON (valid / invalid / acceptable). */

#define WYC_PK_REJECT 0
#define WYC_PK_ACCEPT 1
#define WYC_PK_BROKEN 2
#define WYC_PK_MAXFAIL 32

typedef int (*wyc_pk_fn)(const wyc_case* c);

typedef struct {
  const char* prim;
  const char* file;
  u32         added, valid_ok, inv_rej, acc, acc_acc, acc_rej, fail;
  u32         bad_id[WYC_PK_MAXFAIL];
  const char* bad_flags[WYC_PK_MAXFAIL];
} wyc_pk_tally;

/* Is verdict v the Wycheproof-expected outcome for c->result? */
static int wyc_pk_expected(const wyc_case* c, int v) {
  if (v == WYC_PK_BROKEN) return 0;
  if (c->result == WYC_ACCEPTABLE) return 1;
  return v == (c->result == WYC_VALID);
}

static void wyc_pk_fail(wyc_pk_tally* t, const wyc_case* c) {
  if (t->fail < WYC_PK_MAXFAIL) {
    t->bad_id[t->fail]    = c->tc_id;
    t->bad_flags[t->fail] = c->flags;
  }
  t->fail++;
  wired_test_fails++;
  printf("FAIL %s tcId %u flags=%s\n", t->file, c->tc_id, c->flags);
}

static void wyc_pk_acceptable(wyc_pk_tally* t, const wyc_case* c, int v) {
  t->acc++;
  t->acc_acc += (u32)(v == WYC_PK_ACCEPT);
  t->acc_rej += (u32)(v == WYC_PK_REJECT);
  printf(
      "wyc %s tcId %u acceptable: %s\n", t->file, c->tc_id,
      v == WYC_PK_ACCEPT ? "accepted" : "rejected");
}

static void wyc_pk_one(wyc_pk_tally* t, const wyc_case* c, int v) {
  t->added++;
  if (!wyc_pk_expected(c, v)) return wyc_pk_fail(t, c);
  if (c->result == WYC_ACCEPTABLE) return wyc_pk_acceptable(t, c, v);
  t->valid_ok += (u32)(c->result == WYC_VALID);
  t->inv_rej += (u32)(c->result == WYC_INVALID);
}

static void wyc_pk_summary(const wyc_pk_tally* t) {
  printf(
      "wyc %s: added %u valid_ok %u invalid_rejected %u acceptable %u "
      "(accepted %u rejected %u) fail %u skip 0 failed=[",
      t->prim, t->added, t->valid_ok, t->inv_rej, t->acc, t->acc_acc,
      t->acc_rej, t->fail);
  for (u32 i = 0; i < t->fail && i < WYC_PK_MAXFAIL; i++)
    printf("%s%u:%s", i ? "," : "", t->bad_id[i], t->bad_flags[i]);
  printf("]\n");
}

/* Run every case of one Wycheproof file; cases are identified by tcId. */
static void wyc_pk_all(
    wyc_pk_tally* t, const wyc_case* cs, u32 n, wyc_pk_fn run) {
  for (u32 i = 0; i < n; i++) wyc_pk_one(t, &cs[i], run(&cs[i]));
  wyc_pk_summary(t);
}

/* Every result=invalid case carrying flag must be rejected. */
static inline void wyc_pk_flag_rejected(
    const char*     name,
    const wyc_case* cs,
    u32             n,
    wyc_pk_fn       run,
    const char*     flag) {
  u32 cnt = 0, bad = 0;
  for (u32 i = 0; i < n; i++) {
    int hit = cs[i].result == WYC_INVALID && wyc_has_flag(&cs[i], flag);
    int ok  = !hit || run(&cs[i]) == WYC_PK_REJECT;
    cnt += (u32)hit;
    bad += (u32)!ok;
    if (!ok) printf("FAIL %s tcId %u flags=%s\n", name, cs[i].tc_id, flag);
  }
  wired_test_fails += (int)bad;
  printf("wyc %s: cases %u fail %u\n", name, cnt, bad);
}

#endif
