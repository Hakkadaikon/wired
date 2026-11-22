#include "crypto/asymmetric/rsa/rsa_pss_verify.h"

#include "crypto/asymmetric/bignum/modexp.h"
#include "crypto/asymmetric/rsa/pss.h"
#include "crypto/asymmetric/rsa/rsa_verify.h"
#include "crypto/symmetric/hash/hash/sha256.h"

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
  while (i < n_len && n[i] == 0) {
    i++;
  }
  return i;
}

/* Bit length of a big-endian integer n[0..n_len). 0 if n is zero. */
static usz rsa_modbits(const u8* n, usz n_len) {
  usz i = rsa_first_nonzero(n, n_len);
  if (i == n_len) {
    return 0;
  }
  return (n_len - i - 1) * 8 + rsa_byte_bits(n[i]);
}

/* e = 65537 (RFC 8017 common public exponent). */
static void pss_e_f4(bn* e) {
  for (usz i = 0; i < BN_LIMBS; i++) {
    e->v[i] = 0;
  }
  e->v[0] = 65537;
}

/* The modulus fits, s is k octets (RFC 8017 8.1.2 step 1) and the exponent
 * is the supported F4. The digest sizes are emsa_pss_verify's to judge. */
static int pss_inputs_ok(const rsa_pub* pub, usz sig_len) {
  if (pub->n.n > RSA_PSS_MAX || sig_len != pub->n.n) {
    return 0;
  }
  return rsa_e_is_f4(pub->e.p, pub->e.n);
}

/* 1 if the n octets at p are all zero. */
static int rsa_zero_prefix(const u8* p, usz n) {
  u8 d = 0;
  for (usz i = 0; i < n; i++) {
    d |= p[i];
  }
  return d == 0;
}

/* RFC 8017 8.1.2 step 1 and steps 2-3: reject s >= n, else m = s^e mod n
 * into buf (n.n octets) and EM = I2OSP(m, emLen) = its low em_len octets.
 * Returns 0 if the signature is out of range or m needs more than emLen
 * octets ("integer too large", 9.1.2 note / step 2c): with modBits = 1 mod 8,
 * emLen = k - 1 and m can still reach 2^(8 emLen). */
static int rsa_recover_em(wired_span n, wired_span sig, u8* buf, usz em_len) {
  bn bn_n, bn_s, bn_e, m;
  bn_from_be(&bn_n, n.p, n.n);
  bn_from_be(&bn_s, sig.p, sig.n);
  if (bn_cmp(&bn_s, &bn_n) >= 0) {
    return 0;
  }
  pss_e_f4(&bn_e);
  bn_modexp(&m, &bn_s, (bn_expmod){&bn_e, &bn_n});
  bn_to_be(&m, buf, n.n);
  return rsa_zero_prefix(buf, n.n - em_len);
}

/* RFC 8017 8.1.2 step 1 note: emBits = modBits - 1 (0 for a zero modulus). */
static usz rsa_em_bits(const u8* n, usz n_len) {
  usz mod_bits = rsa_modbits(n, n_len);
  return mod_bits ? mod_bits - 1 : 0;
}

int rsa_pss_verify_cfg(
    const rsa_pub*     pub,
    wired_span         sig,
    wired_span         mhash,
    const rsa_pss_cfg* cfg) {
  if (!pss_inputs_ok(pub, sig.n)) {
    return 0;
  }
  usz em_bits = rsa_em_bits(pub->n.p, pub->n.n);
  usz em_len  = (em_bits + 7) / 8;
  u8  buf[RSA_PSS_MAX];
  return rsa_recover_em(pub->n, sig, buf, em_len) &&
         emsa_pss_verify(
             (wired_span){buf + pub->n.n - em_len, em_len}, em_bits, mhash,
             cfg);
}

int rsa_pss_verify(const rsa_pub* pub, wired_span sig, wired_span mhash) {
  static const rsa_pss_cfg s256 = {{wired_sha256, 32}, 32};
  return rsa_pss_verify_cfg(pub, sig, mhash, &s256);
}
