#include "crypto/asymmetric/ecc/p256sign/sign.h"

#include "crypto/asymmetric/ecc/p256/p256_point.h"
#include "crypto/asymmetric/ecc/p256fixed/p256fixed.h"
#include "crypto/asymmetric/ecc/p256sign/rfc6979.h"

/* FIPS 186-4 Section 6.3. */

/* Counts fixed-base multiplies so a test can pin "one signature, one mul_g"
 * (the RFC 6979 suitability pass must not be recomputed by the signer). */
static usz ps_mulg_count;

/* r = (k*G).x mod n, via the fixed-base G table. Returns 1 if r != 0. */
static int ps_compute_r(p256_fe r, const u8 kb[32]) {
  p256_fe x, y;
  ps_mulg_count++;
  if (!quic_p256fixed_mul_g(x, y, kb)) return 0;
  quic_fp_reduce_n(r, x);
  return !quic_fp_is_zero(r);
}

/* s = k^-1 * sum mod n, with sum = (e + r*d) mod n from the caller. */
static void ps_compute_s(p256_fe s, const u8 kb[32], const p256_fe sum) {
  p256_fe k, kinv;
  quic_fp_from_be(k, kb);
  quic_mont_inv(kinv, k, &quic_p256_mont_n); /* k^-1 mod n, fast Montgomery */
  quic_fp_mul_n(s, (quic_fpab){kinv, sum});
}

/* Low-S (RFC 6979 / BoringSSL): replace s with min(s, n - s) so s <= n/2. */
static void ps_low_s(p256_fe s) {
  p256_fe ns;
  quic_fp_sub(ns, (quic_fpab){quic_p256_n, s}, quic_p256_n);
  if (quic_fp_lt(ns, s)) quic_fp_set(s, ns);
}

/* Context threaded through the RFC 6979 candidate callback: the digest and
 * private key in, plus the r, s of the accepted candidate out, so the signer
 * reuses them instead of paying the fixed-base multiply twice. */
typedef struct {
  const u8* hash;
  const u8* priv;
  p256_fe   rv;
  p256_fe   sv;
} ps_ctx;

/* RFC 6979 Section 3.4 / FIPS 186-4 6.3: a candidate k is suitable only if it
 * yields both r != 0 and s != 0; otherwise the generation loop must draw a
 * new k. Stores r, s in the context for the caller to reuse. */
static int ps_k_suitable(const u8 kb[32], void* vctx) {
  ps_ctx* c = (ps_ctx*)vctx;
  p256_fe e, eh, d, rd, sum;
  if (!ps_compute_r(c->rv, kb)) return 0;
  quic_fp_from_be(eh, c->hash);
  quic_fp_reduce_n(e, eh);
  quic_fp_from_be(d, c->priv);
  quic_fp_reduce_n(d, d); /* quic_fp_mul_n needs both operands < n */
  quic_fp_mul_n(rd, (quic_fpab){c->rv, d});
  quic_fp_add(sum, (quic_fpab){e, rd}, quic_p256_n);
  ps_compute_s(c->sv, kb, sum);
  return !quic_fp_is_zero(c->sv);
}

int quic_p256sign_sign(
    const u8 priv[32], const u8 hash[32], u8 r[32], u8 s[32]) {
  u8     kb[32];
  ps_ctx ctx = {hash, priv, {0}, {0}};
  quic_p256sign_k_retry(priv, hash, kb, ps_k_suitable, &ctx);
  ps_low_s(ctx.sv);
  quic_fp_to_be(r, ctx.rv);
  quic_fp_to_be(s, ctx.sv);
  return 1;
}
