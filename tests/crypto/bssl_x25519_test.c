#include "test.h"
#include "vectors/boringssl/bssl_vec.h"
#include "vectors/boringssl/x25519_test.h"
#include "vectors/boringssl/x25519_test_cc_vectors.h"

/* BoringSSL crypto/curve25519/x25519_test.cc (pinned dd73e69a): its inline
 * vectors (x25519_test_cc_vectors.txt) and the Wycheproof FileTest file
 * x25519_test.txt that its Wycheproof test reads. */

typedef struct {
  u8 a[32], b[32], exp[32], out[32];
} bssl_x_case;

static int bssl_x_same(const u8* a, const u8* b) {
  u8 d = 0;
  for (usz i = 0; i < 32; i++) d |= (u8)(a[i] ^ b[i]);
  return d == 0;
}

static int bssl_x_hex(
    const bssl_attr* at, const bssl_case* c, const char* k, u8* o) {
  return bssl_bytes(bssl_get(at, c, k), o, 32) == 32;
}

static int bssl_x_has(const char* s, const char* sub) {
  for (; *s; s++) {
    const char *p = s, *q = sub;
    while (*q && *p == *q) p++, q++;
    if (!*q) return 1;
  }
  return 0;
}

/* BoringSSL Wycheproof rule: valid -> success; acceptable -> success unless
 * the flags list ZeroSharedSecret (not in its accepted-flag list); invalid
 * -> failure. The shared value is compared in every case. */
static int bssl_x_expect(const char* result, const char* flags) {
  if (bssl_streq(result, "valid")) return 1;
  if (bssl_streq(result, "invalid")) return 0;
  return !bssl_x_has(flags, "ZeroSharedSecret");
}

static int bssl_x_wyche(const bssl_case* c) {
  const bssl_attr* at = bssl_x25519_test_attrs;
  bssl_x_case      v;
  const char*      res = bssl_get(at, c, "result");
  const char*      fl  = bssl_get(at, c, "flags");
  int              ok  = bssl_x_hex(at, c, "private", v.a);
  ok                   = bssl_x_hex(at, c, "public", v.b) && ok;
  ok                   = bssl_x_hex(at, c, "shared", v.exp) && ok;
  if (!ok || !res || !fl) return 0;
  ok = wired_x25519(v.out, v.a, v.b) == bssl_x_expect(res, fl);
  return bssl_x_same(v.out, v.exp) && ok;
}

static int bssl_x_iter(const bssl_x_case* v) {
  u8 s[32], p[32], o[32];
  for (usz i = 0; i < 32; i++) s[i] = v->a[i], p[i] = v->b[i];
  int ok = 1;
  for (u32 i = 0; i < 1000; i++) {
    ok = wired_x25519(o, s, p) && ok;
    for (usz j = 0; j < 32; j++) p[j] = s[j], s[j] = o[j];
  }
  return ok && bssl_x_same(s, v->exp);
}

/* op = mult | base | iter, see x25519_test_cc_vectors.txt. */
static int bssl_x_inline(const bssl_case* c) {
  const bssl_attr* at = bssl_x25519_test_cc_vectors_attrs;
  const char*      op = bssl_get(at, c, "op");
  bssl_x_case      v;
  int              ret = bssl_get(at, c, "ret")[0] == '1';
  int              ok =
      bssl_x_hex(at, c, "scalar", v.a) && bssl_x_hex(at, c, "expected", v.exp);
  if (bssl_streq(op, "base"))
    return ok && wired_x25519_base(v.out, v.a) && bssl_x_same(v.out, v.exp);
  ok = bssl_x_hex(at, c, "point", v.b) && ok;
  if (bssl_streq(op, "iter")) return ok && bssl_x_iter(&v);
  ok = (wired_x25519(v.out, v.a, v.b) == ret) && ok;
  return ok && bssl_x_same(v.out, v.exp);
}

static u32 bssl_x_pass, bssl_x_fail;

static void bssl_x_tally(const char* file, const bssl_case* c, int ok) {
  CHECK(ok);
  if (!ok)
    printf(
        "FAIL %s:%u-%u\n", file, (unsigned)c->line_first,
        (unsigned)c->line_last);
  bssl_x_pass += (u32)ok;
  bssl_x_fail += (u32)!ok;
}

void test_bssl_x25519(void) {
  u32 ni = (u32)(sizeof bssl_x25519_test_cc_vectors_cases / sizeof(bssl_case));
  u32 nw = (u32)(sizeof bssl_x25519_test_cases / sizeof(bssl_case));
  /* x25519_test.cc inline vectors (TestVector, SmallOrder, Iterated) */
  for (u32 i = 0; i < ni; i++)
    bssl_x_tally(
        "x25519_test.cc", &bssl_x25519_test_cc_vectors_cases[i],
        bssl_x_inline(&bssl_x25519_test_cc_vectors_cases[i]));
  /* third_party/wycheproof_testvectors/x25519_test.txt */
  for (u32 i = 0; i < nw; i++)
    bssl_x_tally(
        "x25519_test.txt", &bssl_x25519_test_cases[i],
        bssl_x_wyche(&bssl_x25519_test_cases[i]));
  /* skip 1: DISABLED_IteratedLarge (1,000,000 iterations) */
  printf(
      "bssl x25519: added %u pass %u fail %u skip 1\n", (unsigned)(ni + nw),
      (unsigned)bssl_x_pass, (unsigned)bssl_x_fail);
}
