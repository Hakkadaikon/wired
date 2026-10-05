#include "test.h"
#include "vectors/boringssl/bssl_vec.h"
#include "vectors/boringssl/ed25519_tests.h"

/* BoringSSL crypto/curve25519/ed25519_tests.txt (pinned dd73e69a): every
 * case is a deterministic RFC 8032 5.1 vector (PRIV = seed || pub). */

#define BSSL_ED_MSG                                        \
  1024 /* longest message in the vector file is 1023 bytes \
        */

typedef struct {
  u8  priv[64], pub[32], sig[64], msg[BSSL_ED_MSG];
  ssz priv_n, pub_n, sig_n, msg_n;
} bssl_ed_case;

static int bssl_ed_load(const bssl_case* c, bssl_ed_case* v) {
  const bssl_attr* a = bssl_ed25519_tests_attrs;
  v->priv_n = bssl_bytes(bssl_get(a, c, "PRIV"), v->priv, sizeof v->priv);
  v->pub_n  = bssl_bytes(bssl_get(a, c, "PUB"), v->pub, sizeof v->pub);
  v->sig_n  = bssl_bytes(bssl_get(a, c, "SIG"), v->sig, sizeof v->sig);
  v->msg_n  = bssl_bytes(bssl_get(a, c, "MESSAGE"), v->msg, sizeof v->msg);
  return v->priv_n == 64 && v->pub_n == 32 && v->sig_n == 64 && v->msg_n >= 0;
}

static int bssl_ed_same(const u8* a, const u8* b, usz n) {
  u8 d = 0;
  for (usz i = 0; i < n; i++) d |= (u8)(a[i] ^ b[i]);
  return d == 0;
}

/* keygen + sign + verify; returns 1 when every check held. */
static int bssl_ed_run(const bssl_ed_case* v) {
  u8  pub[32], sig[64];
  int ok = ed25519_keypair(v->priv, pub) && bssl_ed_same(pub, v->pub, 32);
  ok     = ed25519_sign(v->priv, v->msg, (usz)v->msg_n, sig) && ok;
  ok     = bssl_ed_same(sig, v->sig, 64) && ok;
  return ed25519_verify(v->sig, v->msg, (usz)v->msg_n, v->pub) && ok;
}

static int bssl_ed_case_ok(const bssl_case* c) {
  static bssl_ed_case v;
  if (!bssl_ed_load(c, &v)) return 0;
  return bssl_ed_run(&v);
}

void test_bssl_ed25519(void) {
  u32 n    = (u32)(sizeof bssl_ed25519_tests_cases / sizeof(bssl_case));
  u32 pass = 0, fail = 0;
  /* ed25519_tests.txt */
  for (u32 i = 0; i < n; i++) {
    const bssl_case* c  = &bssl_ed25519_tests_cases[i];
    int              ok = bssl_ed_case_ok(c);
    CHECK(ok);
    if (!ok)
      printf(
          "FAIL ed25519_tests.txt:%u-%u\n", (unsigned)c->line_first,
          (unsigned)c->line_last);
    pass += (u32)ok;
    fail += (u32)!ok;
  }
  printf(
      "bssl ed25519: added %u pass %u fail %u skip 0\n", (unsigned)n,
      (unsigned)pass, (unsigned)fail);
}
