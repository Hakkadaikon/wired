#include "crypto/asymmetric/rsa/rsa_pss_verify.h"

#include "crypto/asymmetric/bignum/modexp.h"
#include "crypto/asymmetric/rsa/pss.h"
#include "crypto/asymmetric/rsa/rsa_verify.h"

#define RSA_PSS_MAX ((usz)QUIC_BN_LIMBS * 8)

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
static void pss_e_f4(quic_bn* e) {
  for (usz i = 0; i < QUIC_BN_LIMBS; i++) e->v[i] = 0;
  e->v[0] = 65537;
}

/* Reject inputs that cannot yield a valid SHA-256 saltLen-32 PSS signature. */
static int rsa_sizes_bad(usz n_len, usz sig_len, usz hash_len) {
  if (n_len > RSA_PSS_MAX || hash_len != 32) return 1;
  return sig_len != n_len;
}

/* Sizes acceptable and the exponent is the supported F4. */
static int pss_inputs_ok(const quic_rsa_pub* pub, usz sig_len, usz hash_len) {
  if (rsa_sizes_bad(pub->n.n, sig_len, hash_len)) return 0;
  return quic_rsa_e_is_f4(pub->e.p, pub->e.n);
}

/* RFC 8017 8.1.2 step 1 and steps 2-3: reject s >= n, else m = s^e mod n and
 * EM = I2OSP(m, emLen). Returns 1 on success, 0 if the signature is out of
 * range. */
static int rsa_recover_em(quic_span n, quic_span sig, quic_mspan em) {
  quic_bn bn_n, bn_s, bn_e, m;
  quic_bn_from_be(&bn_n, n.p, n.n);
  quic_bn_from_be(&bn_s, sig.p, sig.n);
  if (quic_bn_cmp(&bn_s, &bn_n) >= 0) return 0;
  pss_e_f4(&bn_e);
  quic_bn_modexp(&m, &bn_s, (quic_bn_expmod){&bn_e, &bn_n});
  quic_bn_to_be(&m, em.p, em.n);
  return 1;
}

/* RFC 8017 8.1.2 step 1 note: emBits = modBits - 1 (0 for a zero modulus). */
static usz rsa_em_bits(const u8* n, usz n_len) {
  usz mod_bits = rsa_modbits(n, n_len);
  return mod_bits ? mod_bits - 1 : 0;
}

int quic_rsa_pss_verify(
    const quic_rsa_pub* pub, quic_span sig, quic_span mhash) {
  if (!pss_inputs_ok(pub, sig.n, mhash.n)) return 0;
  usz em_bits = rsa_em_bits(pub->n.p, pub->n.n);
  usz em_len  = (em_bits + 7) / 8;
  u8  em[RSA_PSS_MAX];
  return rsa_recover_em(pub->n, sig, (quic_mspan){em, em_len}) &&
         quic_emsa_pss_verify((quic_span){em, em_len}, em_bits, mhash);
}
