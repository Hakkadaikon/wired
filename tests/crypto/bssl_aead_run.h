#ifndef BSSL_AEAD_RUN_H
#define BSSL_AEAD_RUN_H

#include "test.h"
#include "vectors/boringssl/bssl_vec.h"

/* Shared BoringSSL FileTest AEAD driver (KEY/NONCE/IN/AD/CT/TAG). Expected
 * values come only from the vector file. A tag that is not 16 bytes
 * (truncated) and a FAILS case are fed to open(), which must reject them.
 * A nonce that is not 12 bytes is a valid case for BoringSSL that wired's
 * API cannot express at all (it takes a 96-bit nonce only): it is counted
 * as SKIP, not as a pass, and listed in tests/vectors/boringssl/README.md. */

#define BSSL_BUF 1024
#define BSSL_NONCE 12
#define BSSL_TAG 16

typedef usz (*bssl_seal_fn)(
    const u8* key, const u8* nonce, wired_span aad, wired_span pt, u8* out);
typedef int (*bssl_open_fn)(
    const u8* key, const u8* nonce, wired_span aad, wired_span ct, u8* pt);

typedef struct {
  u8  key[64], nonce[BSSL_BUF], in[BSSL_BUF], ad[BSSL_BUF], ct[BSSL_BUF];
  u8  tag[BSSL_BUF], sealed[BSSL_BUF + BSSL_TAG], pt[BSSL_BUF + BSSL_TAG];
  ssz kl, nl, il, al, cl, tl;
} bssl_in;

typedef struct {
  const char*      file;
  const bssl_attr* attrs;
  bssl_seal_fn     seal;
  bssl_open_fn     open;
  usz              keylen;
  int              pass, fail, skip;
} bssl_run;

static int bssl_load(bssl_in* v, const bssl_attr* a, const bssl_case* c) {
  v->kl = bssl_bytes(bssl_get(a, c, "KEY"), v->key, sizeof v->key);
  v->nl = bssl_bytes(bssl_get(a, c, "NONCE"), v->nonce, BSSL_BUF);
  v->il = bssl_bytes(bssl_get(a, c, "IN"), v->in, BSSL_BUF);
  v->al = bssl_bytes(bssl_get(a, c, "AD"), v->ad, BSSL_BUF);
  v->cl = bssl_bytes(bssl_get(a, c, "CT"), v->ct, BSSL_BUF);
  v->tl = bssl_bytes(bssl_get(a, c, "TAG"), v->tag, BSSL_BUF);
  return v->kl >= 0 && v->nl >= 0 && v->il >= 0 && v->al >= 0 && v->cl >= 0 &&
         v->tl >= 0;
}

static int bssl_same(const u8* a, const u8* b, usz n) {
  u8 d = 0;
  for (usz i = 0; i < n; i++) d |= (u8)(a[i] ^ b[i]);
  return d == 0;
}

/* Shape wired's API cannot carry (nonce/tag length): must be rejected. */
static int bssl_unrepresentable(const bssl_in* v) {
  return v->nl != BSSL_NONCE || v->tl != BSSL_TAG;
}

/* Truncated/odd-length tag or FAILS: open(CT||TAG) must fail. */
static int bssl_rejects(const bssl_run* r, bssl_in* v) {
  for (ssz i = 0; i < v->tl; i++) v->ct[v->cl + i] = v->tag[i];
  return !r->open(
      v->key, v->nonce, wired_span_of(v->ad, (usz)v->al),
      wired_span_of(v->ct, (usz)(v->cl + v->tl)), v->pt);
}

static int bssl_roundtrip(const bssl_run* r, bssl_in* v) {
  wired_span ad = wired_span_of(v->ad, (usz)v->al);
  usz        n  = r->seal(
      v->key, v->nonce, ad, wired_span_of(v->in, (usz)v->il), v->sealed);
  int ok = n == (usz)(v->cl + BSSL_TAG) &&
           bssl_same(v->sealed, v->ct, (usz)v->cl) &&
           bssl_same(v->sealed + v->cl, v->tag, BSSL_TAG);
  ok = ok && r->open(v->key, v->nonce, ad, wired_span_of(v->sealed, n), v->pt);
  return ok && bssl_same(v->pt, v->in, (usz)v->il);
}

#define BSSL_SKIP 2

/* 1 pass, 0 fail, BSSL_SKIP for a nonce wired's API cannot take. */
static int bssl_one(const bssl_run* r, bssl_in* v, const bssl_case* c) {
  if (!bssl_load(v, r->attrs, c) || (usz)v->kl != r->keylen) return 0;
  if (v->nl != BSSL_NONCE) return BSSL_SKIP;
  if (bssl_get(r->attrs, c, "FAILS")) return bssl_rejects(r, v);
  if (bssl_unrepresentable(v)) return bssl_rejects(r, v);
  return bssl_roundtrip(r, v);
}

static void bssl_loop(bssl_run* r, const bssl_case* cs, usz n) {
  static bssl_in v;
  for (usz i = 0; i < n; i++) {
    int res = bssl_one(r, &v, &cs[i]);
    if (res == 0)
      printf("FAIL %s:%u-%u\n", r->file, cs[i].line_first, cs[i].line_last);
    r->pass += res == 1;
    r->fail += res == 0;
    r->skip += res == BSSL_SKIP;
    wired_test_fails += res == 0;
  }
  printf(
      "bssl %s: added %u pass %d fail %d skip %d\n", r->file, (u32)n, r->pass,
      r->fail, r->skip);
}

#endif
