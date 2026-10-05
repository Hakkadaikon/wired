#ifndef WYC_RUN_H
#define WYC_RUN_H

#include "common/bytes/util/ct.h"
#include "test.h"
#include "vectors/wycheproof/wyc_vec.h"

/* Shared Wycheproof driver. Every case is identified by its tcId; expected
 * bytes come only from the Wycheproof JSON (via the generated .h). A case
 * function returns WYC_OK (accepted, and for a valid case the output equals
 * the expected value), WYC_REJ (rejected or output mismatch), WYC_SKIP
 * (wired's API cannot express the case) or WYC_BAD (vector unreadable). */

#define WYC_OK 1
#define WYC_REJ 0
#define WYC_SKIP 2
#define WYC_BAD 3
#define WYC_BUF 16384
#define WYC_MAXFAIL 64

typedef int (*wyc_fn)(const bssl_attr*, const wyc_case*);

typedef struct {
  const char* file;
  const char* prim;
  u32         added, valid_ok, inv_rej, acc_acc, acc_rej, fail, skip, nfail;
  u32         fail_id[WYC_MAXFAIL];
  const char* fail_flags[WYC_MAXFAIL];
} wyc_stats;

static inline u32 wyc_num(const char* s) {
  u32 v = 0;
  for (; s && *s >= '0' && *s <= '9'; s++) v = v * 10 + (u32)(*s - '0');
  return v;
}

/* 1 if two byte strings are equal (constant time, same length). */
static inline int wyc_eq(const u8* a, const u8* b, usz n) {
  return ct_diffn(a, b, n) == 0;
}

static inline void wyc_failed(wyc_stats* s, const wyc_case* c) {
  if (s->nfail < WYC_MAXFAIL) {
    s->fail_id[s->nfail]    = c->tc_id;
    s->fail_flags[s->nfail] = c->flags;
  }
  s->nfail++;
  s->fail++;
  wired_test_fails++;
  printf("FAIL %s tcId %u flags=%s\n", s->file, c->tc_id, c->flags);
}

static inline void wyc_tally_valid(wyc_stats* s, const wyc_case* c, int o) {
  if (o == WYC_OK)
    s->valid_ok++;
  else
    wyc_failed(s, c);
}

static inline void wyc_tally_invalid(wyc_stats* s, const wyc_case* c, int o) {
  if (o == WYC_REJ)
    s->inv_rej++;
  else
    wyc_failed(s, c);
}

static inline void wyc_tally_acceptable(
    wyc_stats* s, const wyc_case* c, int o) {
  printf(
      "wyc %s tcId %u acceptable: %s\n", s->file, c->tc_id,
      o == WYC_OK ? "accepted" : "rejected");
  s->acc_acc += o == WYC_OK;
  s->acc_rej += o != WYC_OK;
}

static inline void wyc_tally(wyc_stats* s, const wyc_case* c, int o) {
  static void (*const by_result[])(wyc_stats*, const wyc_case*, int) = {
      wyc_tally_valid, wyc_tally_invalid, wyc_tally_acceptable};
  s->added++;
  if (o == WYC_SKIP)
    s->skip++;
  else if (o == WYC_BAD)
    wyc_failed(s, c);
  else
    by_result[c->result](s, c, o);
}

/* Run every case of one Wycheproof JSON file (each identified by tcId). */
static inline void wyc_loop(
    wyc_stats* s, const bssl_attr* a, const wyc_case* cs, usz n, wyc_fn fn) {
  for (usz i = 0; i < n; i++) wyc_tally(s, &cs[i], fn(a, &cs[i]));
  printf(
      "wyc %s: added %u valid_ok %u invalid_rejected %u acceptable %u "
      "(accepted %u rejected %u) fail %u skip %u failed=[",
      s->prim, s->added, s->valid_ok, s->inv_rej, s->acc_acc + s->acc_rej,
      s->acc_acc, s->acc_rej, s->fail, s->skip);
  for (u32 i = 0; i < s->nfail && i < WYC_MAXFAIL; i++)
    printf("%s%u:%s", i ? "," : "", s->fail_id[i], s->fail_flags[i]);
  printf("]\n");
}

/* Every invalid case carrying `flag` must be rejected. */
static inline void wyc_flag_loop(
    const char*      file,
    const char*      flag,
    const bssl_attr* a,
    const wyc_case*  cs,
    usz              n,
    wyc_fn           fn) {
  u32 seen = 0, rej = 0;
  for (usz i = 0; i < n; i++) {
    int hit = cs[i].result == WYC_INVALID && wyc_has_flag(&cs[i], flag);
    int ok  = !hit || fn(a, &cs[i]) == WYC_REJ;
    seen += hit;
    rej += hit && ok;
    if (ok) continue;
    wired_test_fails++;
    printf("FAIL %s tcId %u flags=%s\n", file, cs[i].tc_id, cs[i].flags);
  }
  printf(
      "wyc %s flag %s: invalid_cases %u rejected %u fail %u\n", file, flag,
      seen, rej, seen - rej);
}

/* ---- AEAD (96-bit nonce, 128-bit tag) ---- */

typedef usz (*wyc_seal_fn)(
    const u8* key, const u8* nonce, wired_span aad, wired_span pt, u8* out);
typedef int (*wyc_open_fn)(
    const u8* key, const u8* nonce, wired_span aad, wired_span ct, u8* pt);

typedef struct {
  wyc_seal_fn seal;
  wyc_open_fn open;
  u32         keybits;
} wyc_aead_ops;

typedef struct {
  u8  key[64], iv[WYC_BUF], aad[WYC_BUF], msg[WYC_BUF], ct[WYC_BUF + 16];
  u8  tag[WYC_BUF], out[WYC_BUF + 16];
  ssz kl, il, al, ml, cl, tl;
} wyc_aead_in;

static inline int wyc_aead_load(
    wyc_aead_in* v, const bssl_attr* a, const wyc_case* c) {
  v->kl = bssl_bytes(wyc_get(a, c, "key"), v->key, sizeof v->key);
  v->il = bssl_bytes(wyc_get(a, c, "iv"), v->iv, WYC_BUF);
  v->al = bssl_bytes(wyc_get(a, c, "aad"), v->aad, WYC_BUF);
  v->ml = bssl_bytes(wyc_get(a, c, "msg"), v->msg, WYC_BUF);
  v->cl = bssl_bytes(wyc_get(a, c, "ct"), v->ct, WYC_BUF);
  v->tl = bssl_bytes(wyc_get(a, c, "tag"), v->tag, WYC_BUF);
  return v->kl >= 0 && v->il >= 0 && v->al >= 0 && v->ml >= 0 && v->cl >= 0 &&
         v->tl >= 0;
}

static inline int wyc_aead_expressible(
    const wyc_aead_ops* o, const wyc_aead_in* v) {
  return o && (u32)v->kl * 8 == o->keybits && v->il == 12 && v->tl == 16;
}

/* valid: open(ct||tag) must succeed with msg, and seal(msg) must equal
 * ct||tag. Other results: report whether open() accepts. */
static inline int wyc_aead_check(
    const wyc_aead_ops* o, wyc_aead_in* v, const wyc_case* c) {
  wired_span ad = wired_span_of(v->aad, (usz)v->al);
  usz        n  = (usz)(v->cl + 16);
  for (ssz i = 0; i < 16; i++) v->ct[v->cl + i] = v->tag[i];
  int acc = o->open(v->key, v->iv, ad, wired_span_of(v->ct, n), v->out);
  if (c->result != WYC_VALID) return acc ? WYC_OK : WYC_REJ;
  int good = acc && wyc_eq(v->out, v->msg, (usz)v->ml);
  good     = good &&
             o->seal(
                 v->key, v->iv, ad, wired_span_of(v->msg, (usz)v->ml), v->out) == n;
  return good && wyc_eq(v->out, v->ct, n) ? WYC_OK : WYC_REJ;
}

static inline int wyc_aead_case(
    const wyc_aead_ops* o, const bssl_attr* a, const wyc_case* c) {
  static wyc_aead_in v;
  if (!wyc_aead_load(&v, a, c)) return WYC_BAD;
  if (wyc_aead_expressible(o, &v)) return wyc_aead_check(o, &v, c);
  return c->result == WYC_INVALID ? WYC_REJ : WYC_SKIP;
}

#endif
