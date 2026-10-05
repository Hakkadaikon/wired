#ifndef WYC_RSA_RUN_H
#define WYC_RSA_RUN_H

#include "crypto/asymmetric/rsa/rsa_pss_verify.h"
#include "crypto/asymmetric/rsa/rsa_verify.h"
#include "crypto/symmetric/hash/hash/sha256.h"
#include "crypto/symmetric/hash/hash/sha384.h"
#include "crypto/symmetric/hash/hash/sha512.h"
#include "test.h"
#include "vectors/wycheproof/wyc_vec.h"

/* Shared Wycheproof RSA signature driver. Every case is identified by tcId;
 * the expected result is the JSON's "result", never wired's. Cases whose
 * group exponent is not 65537 cannot be expressed by wired's verifiers (e is
 * pinned to F4 by design): valid ones are SKIP, never pass. */

#define WYC_RSA_BUF 1024
#define WYC_RSA_MAXFAIL 64

typedef int (*wyc_rsa_verify_fn)(const rsa_pub*, wired_span, wired_span);

typedef struct {
  const char*       file;
  const bssl_attr*  attrs;
  const wyc_case*   cases;
  usz               n;
  wyc_rsa_verify_fn verify;
  const char*       only_flag; /* 0: all cases; else invalid cases with it */
} wyc_rsa_run;

enum {
  WYC_R_FAIL,
  WYC_R_VALID,
  WYC_R_INVALID,
  WYC_R_ACC_Y,
  WYC_R_ACC_N,
  WYC_R_SKIP
};

typedef struct {
  u8 n[WYC_RSA_BUF], e[16], sig[WYC_RSA_BUF], msg[WYC_RSA_BUF];
  u8 dig[SHA512_DIGEST];
} wyc_rsa_buf;

static usz wyc_rsa_hash(const char* sha, const u8* m, usz n, u8* out) {
  if (bssl_streq(sha, "SHA-256")) {
    wired_sha256(m, n, out);
    return 32;
  }
  if (bssl_streq(sha, "SHA-384")) {
    sha384(m, n, out);
    return 48;
  }
  if (bssl_streq(sha, "SHA-512")) {
    sha512(m, n, out);
    return 64;
  }
  return 0;
}

/* Decoded group key / sig / digest, or 0 on a malformed vector. */
static int wyc_rsa_load(
    wyc_rsa_buf*       b,
    const wyc_rsa_run* r,
    const wyc_case*    c,
    rsa_pub*           pub,
    wired_span*        sig,
    wired_span*        dig) {
  ssz nl = bssl_bytes(
      wyc_get(r->attrs, c, "g.publicKey.modulus"), b->n, WYC_RSA_BUF);
  ssz el = bssl_bytes(
      wyc_get(r->attrs, c, "g.publicKey.publicExponent"), b->e, sizeof b->e);
  ssz sl = bssl_bytes(wyc_get(r->attrs, c, "sig"), b->sig, WYC_RSA_BUF);
  ssz ml = bssl_bytes(wyc_get(r->attrs, c, "msg"), b->msg, WYC_RSA_BUF);
  usz dl = wyc_rsa_hash(
      wyc_get(r->attrs, c, "g.sha"), b->msg, (usz)(ml < 0 ? 0 : ml), b->dig);
  if (nl < 0 || el < 0 || sl < 0 || ml < 0 || !dl) return 0;
  usz lead = 0; /* wired's rsa_pub takes the minimal big-endian modulus */
  while (lead < (usz)nl - 1 && !b->n[lead]) lead++;
  pub->n = wired_span_of(b->n + lead, (usz)nl - lead);
  pub->e = wired_span_of(b->e, (usz)el);
  *sig   = wired_span_of(b->sig, (usz)sl);
  *dig   = wired_span_of(b->dig, dl);
  return 1;
}

static int wyc_rsa_class(const wyc_case* c, int got, int f4) {
  if (c->result == WYC_ACCEPTABLE) return got ? WYC_R_ACC_Y : WYC_R_ACC_N;
  if (c->result == WYC_INVALID) return got ? WYC_R_FAIL : WYC_R_INVALID;
  if (!f4) return WYC_R_SKIP; /* e != 65537 unsupported */
  return got ? WYC_R_VALID : WYC_R_FAIL;
}

static int wyc_rsa_one(
    wyc_rsa_buf* b, const wyc_rsa_run* r, const wyc_case* c) {
  rsa_pub    pub;
  wired_span sig, dig;
  if (!wyc_rsa_load(b, r, c, &pub, &sig, &dig)) return WYC_R_FAIL;
  int got = r->verify(&pub, sig, dig);
  return wyc_rsa_class(c, got, rsa_e_is_f4(pub.e.p, pub.e.n));
}

typedef struct {
  u32         tc[WYC_RSA_MAXFAIL];
  const char* fl[WYC_RSA_MAXFAIL];
  u32         count[6], added, nfail;
} wyc_rsa_tally;

static void wyc_rsa_note(
    wyc_rsa_tally* t, const wyc_rsa_run* r, const wyc_case* c, int res) {
  t->added++;
  t->count[res]++;
  if (res == WYC_R_ACC_Y || res == WYC_R_ACC_N)
    printf(
        "wyc %s tcId %u acceptable: %s\n", r->file, c->tc_id,
        res == WYC_R_ACC_Y ? "accepted" : "rejected");
  if (res != WYC_R_FAIL) return;
  printf("FAIL %s tcId %u flags=%s\n", r->file, c->tc_id, c->flags);
  if (t->nfail < WYC_RSA_MAXFAIL) {
    t->tc[t->nfail] = c->tc_id;
    t->fl[t->nfail] = c->flags;
  }
  t->nfail++;
  wired_test_fails++;
}

static int wyc_rsa_selected(const wyc_rsa_run* r, const wyc_case* c) {
  if (!r->only_flag) return 1;
  return c->result == WYC_INVALID && wyc_has_flag(c, r->only_flag);
}

static void wyc_rsa_summary(const wyc_rsa_run* r, const wyc_rsa_tally* t) {
  printf(
      "wyc %s: added %u valid_ok %u invalid_rejected %u acceptable %u fail %u "
      "skip %u failed=[",
      r->file, t->added, t->count[WYC_R_VALID], t->count[WYC_R_INVALID],
      t->count[WYC_R_ACC_Y] + t->count[WYC_R_ACC_N], t->nfail,
      t->count[WYC_R_SKIP]);
  for (u32 i = 0; i < t->nfail && i < WYC_RSA_MAXFAIL; i++)
    printf("%s%u:%s", i ? "," : "", t->tc[i], t->fl[i]);
  printf("]\n");
}

/* Cases are the entries of the generated header for r->file's JSON. */
static void wyc_rsa_loop(const wyc_rsa_run* r) {
  static wyc_rsa_buf   b;
  static wyc_rsa_tally t;
  wyc_rsa_tally        z = {{0}, {0}, {0}, 0, 0};
  t                      = z;
  for (usz i = 0; i < r->n; i++)
    if (wyc_rsa_selected(r, &r->cases[i]))
      wyc_rsa_note(&t, r, &r->cases[i], wyc_rsa_one(&b, r, &r->cases[i]));
  wyc_rsa_summary(r, &t);
}

#endif
