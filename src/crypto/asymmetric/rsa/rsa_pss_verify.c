#include "crypto/asymmetric/rsa/rsa_pss_verify.h"

#include "crypto/asymmetric/bignum/modexp.h"
#include "crypto/asymmetric/rsa/pss.h"
#include "crypto/asymmetric/rsa/rsa_verify.h"

#define RSA_PSS_MAX ((usz)BN_LIMBS * 8)

/* Significant bits in a nonzero octet (1..8). */
static usz rsa_byte_bits(u8 b) {
  usz n = 8;
  while ((b & 0x80) == 0) {
    b <<= 1;
    n--;
  }
  return n;
}

/* Index of the first nonzero octet, or n_len if all zero. */
static usz rsa_first_nonzero(const u8* n, usz n_len) {
  usz i = 0;
  while (i < n_len && n[i] == 0) i++;
  return i;
}

/* Bit length of a big-endian integer n[0..n_len). 0 if n is zero. */
static usz rsa_modbits(const u8* n, usz n_len) {
  usz i = rsa_first_nonzero(n, n_len);
  if (i == n_len) return 0;
  return (n_len - i - 1) * 8 + rsa_byte_bits(n[i]);
}

/* e = 65537 (RFC 8017 common public exponent). */
static void pss_e_f4(bn* e) {
  for (usz i = 0; i < BN_LIMBS; i++) e->v[i] = 0;
  e->v[0] = 65537;
}

/* Reject inputs that cannot yield a valid SHA-256 saltLen-32 PSS signature. */
static int rsa_sizes_bad(usz n_len, usz sig_len, usz hash_len) {
  if (n_len > RSA_PSS_MAX || hash_len != 32) return 1;
  return sig_len != n_len;
}

/* Sizes acceptable and the exponent is the supported F4. */
static int pss_inputs_ok(const rsa_pub* pub, usz sig_len, usz hash_len) {
  if (rsa_sizes_bad(pub->n.n, sig_len, hash_len)) return 0;
  return rsa_e_is_f4(pub->e.p, pub->e.n);
}

/* RFC 8017 8.1.2 step 1 and steps 2-3: reject s >= n, else m = s^e mod n and
 * EM = I2OSP(m, emLen). Returns 1 on success, 0 if the signature is out of
 * range. */
static int rsa_recover_em(wired_span n, wired_span sig, wired_mspan em) {
  bn bn_n, bn_s, bn_e, m;
  bn_from_be(&bn_n, n.p, n.n);
  bn_from_be(&bn_s, sig.p, sig.n);
  if (bn_cmp(&bn_s, &bn_n) >= 0) return 0;
  pss_e_f4(&bn_e);
  bn_modexp(&m, &bn_s, (bn_expmod){&bn_e, &bn_n});
  bn_to_be(&m, em.p, em.n);
  return 1;
}

/* RFC 8017 8.1.2 step 1 note: emBits = modBits - 1 (0 for a zero modulus). */
static usz rsa_em_bits(const u8* n, usz n_len) {
  usz mod_bits = rsa_modbits(n, n_len);
  return mod_bits ? mod_bits - 1 : 0;
}

int rsa_pss_verify(const rsa_pub* pub, wired_span sig, wired_span mhash) {
  if (!pss_inputs_ok(pub, sig.n, mhash.n)) return 0;
  usz em_bits = rsa_em_bits(pub->n.p, pub->n.n);
  usz em_len  = (em_bits + 7) / 8;
  u8  em[RSA_PSS_MAX];
  return rsa_recover_em(pub->n, sig, (wired_mspan){em, em_len}) &&
         emsa_pss_verify((wired_span){em, em_len}, em_bits, mhash);
}
