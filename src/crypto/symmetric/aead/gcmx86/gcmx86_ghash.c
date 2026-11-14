#include "crypto/symmetric/aead/gcmx86/gcmx86_impl.h"

/** A GHASH in progress (SP 800-38D 6.4): the accumulator and up to four
 * blocks not yet folded into it. */
typedef struct {
  gcmx86_v y;    /**< accumulator Y */
  gcmx86_v b[4]; /**< waiting blocks, as GHASH operands */
  usz      n;    /**< how many wait */
} gcmx86_gh;

static gcmx86_v gcmx86_gh_fold4(const gcmx86* x, gcmx86_v y, const u8* p);
static void     gcmx86_gh_fold(const gcmx86* x, gcmx86_gh* g);
static void     gcmx86_gh_push(const gcmx86* x, gcmx86_gh* g, gcmx86_v blk);
static usz      gcmx86_gh_lead(const gcmx86* x, gcmx86_gh* g, wired_span in);
static usz      gcmx86_gh_bulk(
    const gcmx86* x, gcmx86_gh* g, wired_span in, usz off);
static void gcmx86_gh_rest(
    const gcmx86* x, gcmx86_gh* g, wired_span in, usz off);
static void     gcmx86_gh_absorb(const gcmx86* x, gcmx86_gh* g, wired_span in);
static gcmx86_v gcmx86_gh_lens(usz aad_n, usz ct_n);
static gcmx86_v gcmx86_gh_done(const gcmx86* x, gcmx86_gh* g);

/* Four whole blocks at p in one reduction:
 * Y' = (Y ^ X1) * H^4 ^ X2 * H^3 ^ X3 * H^2 ^ X4 * H.
 * The four 256-bit carry-less products are added before the one shift and
 * reduction. Both are linear over GF(2), so the sum reduces to what four
 * chained Y = (Y ^ X) * H steps give, and the four multiplies no longer
 * wait on each other. */
static gcmx86_v gcmx86_gh_fold4(const gcmx86* x, gcmx86_v y, const u8* p) {
  gcmx86_v lo, hi, l, h;
  gcmx86_clmul256(
      y ^ gcmx86_rev(gcmx86_load(p)), gcmx86_load(x->hp[3]), &lo, &hi);
  for (usz i = 1; i < 4; i++) {
    gcmx86_clmul256(
        gcmx86_rev(gcmx86_load(p + 16 * i)), gcmx86_load(x->hp[3 - i]), &l, &h);
    lo ^= l;
    hi ^= h;
  }
  gcmx86_shl1_256(&lo, &hi);
  return gcmx86_reduce(lo, hi);
}

/* The same fold for the n (1..4) waiting blocks: the first meets H^n. */
static void gcmx86_gh_fold(const gcmx86* x, gcmx86_gh* g) {
  gcmx86_v lo = {0}, hi = {0}, l, h;
  g->b[0] ^= g->y;
  for (usz i = 0; i < g->n; i++) {
    gcmx86_clmul256(g->b[i], gcmx86_load(x->hp[g->n - 1 - i]), &l, &h);
    lo ^= l;
    hi ^= h;
  }
  gcmx86_shl1_256(&lo, &hi);
  g->y = gcmx86_reduce(lo, hi);
  g->n = 0;
}

/* One more block waits; four are folded at once. */
static void gcmx86_gh_push(const gcmx86* x, gcmx86_gh* g, gcmx86_v blk) {
  g->b[g->n++] = blk;
  if (g->n == 4) {
    gcmx86_gh_fold(x, g);
  }
}

/* Whole blocks of in while earlier ones still wait: they join those. */
static usz gcmx86_gh_lead(const gcmx86* x, gcmx86_gh* g, wired_span in) {
  usz off = 0;
  for (; g->n && off + 16 <= in.n; off += 16) {
    gcmx86_gh_push(x, g, gcmx86_rev(gcmx86_load(in.p + off)));
  }
  return off;
}

/* With none waiting, every 64 bytes fold straight from in. */
static usz gcmx86_gh_bulk(
    const gcmx86* x, gcmx86_gh* g, wired_span in, usz off) {
  if (g->n) {
    return off;
  }
  for (; off + 64 <= in.n; off += 64) {
    g->y = gcmx86_gh_fold4(x, g->y, in.p + off);
  }
  return off;
}

/* The whole blocks left (fewer than four), then the zero-padded tail. */
static void gcmx86_gh_rest(
    const gcmx86* x, gcmx86_gh* g, wired_span in, usz off) {
  for (; off + 16 <= in.n; off += 16) {
    gcmx86_gh_push(x, g, gcmx86_rev(gcmx86_load(in.p + off)));
  }
  if (off < in.n) {
    gcmx86_gh_push(x, g, gcmx86_load_rev(in.p + off, in.n - off));
  }
}

/* Absorb in, zero-padded to a block multiple. Every branch here depends
 * on lengths only, never on the bytes. */
static void gcmx86_gh_absorb(const gcmx86* x, gcmx86_gh* g, wired_span in) {
  usz off = gcmx86_gh_lead(x, g, in);
  off     = gcmx86_gh_bulk(x, g, in, off);
  gcmx86_gh_rest(x, g, in, off);
}

/* The length block [len(A)]64 || [len(C)]64 in bits (SP 800-38D 7.1) as a
 * GHASH operand: byte-reversed, the ciphertext length is the low half. */
static gcmx86_v gcmx86_gh_lens(usz aad_n, usz ct_n) {
  u64      a = (u64)aad_n * 8, c = (u64)ct_n * 8;
  gcmx86_w w = {(u32)c, (u32)(c >> 32), (u32)a, (u32)(a >> 32)};
  return (gcmx86_v)w;
}

/* Fold what still waits; the accumulator is the GHASH value. */
static gcmx86_v gcmx86_gh_done(const gcmx86* x, gcmx86_gh* g) {
  if (g->n) {
    gcmx86_gh_fold(x, g);
  }
  return g->y;
}

/* tag = GHASH(H; aad, ct, len block) ^ E(K, J0) (SP 800-38D 7.1). The
 * AAD, the ciphertext and the length block share the four-block folds, so
 * a short packet pays for a reduction per four blocks too. */
void gcmx86_tag(
    const gcmx86* x,
    const u8      j0[16],
    wired_span    aad,
    wired_span    ct,
    u8            tag[16]) {
  gcmx86_gh g = {{0}, {{0}}, 0};
  gcmx86_gh_absorb(x, &g, aad);
  gcmx86_gh_absorb(x, &g, ct);
  gcmx86_gh_push(x, &g, gcmx86_gh_lens(aad.n, ct.n));
  gcmx86_store(
      tag, gcmx86_rev(gcmx86_gh_done(x, &g)) ^ gcmx86_aes(x, gcmx86_load(j0)));
}
