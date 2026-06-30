#include "crypto/asymmetric/rsa/rsa_verify.h"

#include "crypto/asymmetric/bignum/modexp.h"

/* RFC 8017 9.2 Note 1. DigestInfo prefix for SHA-256. */
static const u8 sha256_prefix[19] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60,
                                     0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                                     0x01, 0x05, 0x00, 0x04, 0x20};

/* Write DigestInfo (SHA-256 prefix + hash) at em+off. */
static void put_digestinfo(u8 *em, usz off, const u8 *h, usz h_len) {
  for (usz i = 0; i < sizeof(sha256_prefix); i++)
    em[off + i] = sha256_prefix[i];
  for (usz i = 0; i < h_len; i++) em[off + sizeof(sha256_prefix) + i] = h[i];
}

/* RFC 8017 9.2. Build the expected EM = 0x00 01 FF..FF 00 DigestInfo H.
 * Returns 1 if it fits with PS>=8 octets, else 0. */
static int emsa_pkcs1(u8 *em, usz em_len, const u8 *h, usz h_len) {
  usz fixed = 3 + sizeof(sha256_prefix) + h_len; /* 00 01 ...00 prefix H */
  if (em_len < fixed + 8) return 0;
  usz ps_end = em_len - fixed + 2;
  em[0]      = 0x00;
  em[1]      = 0x01;
  for (usz i = 2; i < ps_end; i++) em[i] = 0xff;
  em[ps_end] = 0x00;
  put_digestinfo(em, ps_end + 1, h, h_len);
  return 1;
}

/* Constant-time equality over len octets. 1 if equal, else 0. */
static int ct_equal(const u8 *a, const u8 *b, usz len) {
  u8 d = 0;
  for (usz i = 0; i < len; i++) d |= a[i] ^ b[i];
  return d == 0;
}

/* e = 65537 (RFC 8017 common public exponent). */
static void rsa_e_f4(quic_bn *e) {
  for (usz i = 0; i < QUIC_BN_LIMBS; i++) e->v[i] = 0;
  e->v[0] = 65537;
}

/* Modulus length outside the supportable PKCS#1 v1.5 SHA-256 range. */
static int n_len_bad(usz n_len) {
  if (n_len > (usz)QUIC_BN_LIMBS * 8) return 1;
  return n_len < 11 + 19 + 32;
}

/* Reject inputs that cannot yield a valid PKCS#1 v1.5 SHA-256 signature. */
static int sizes_bad(usz n_len, usz sig_len, usz hash_len) {
  if (n_len_bad(n_len)) return 1;
  return sig_len != n_len || hash_len != 32;
}

/* RFC 8017 8.2.2 steps 2-4: m = s^e mod n, then EM compare. s,n already <
 * range. */
static int rsa_check(
    const quic_bn *bn_s,
    const quic_bn *bn_n,
    usz            n_len,
    const u8      *h,
    usz            h_len) {
  quic_bn bn_e, m;
  rsa_e_f4(&bn_e);
  quic_bn_modexp(&m, bn_s, &bn_e, bn_n);
  u8 got[QUIC_BN_LIMBS * 8], want[QUIC_BN_LIMBS * 8];
  quic_bn_to_be(&m, got, n_len);
  if (!emsa_pkcs1(want, n_len, h, h_len)) return 0;
  return ct_equal(got, want, n_len);
}

int quic_rsa_pkcs1_verify(
    const u8 *n,
    usz       n_len,
    const u8 *sig,
    usz       sig_len,
    const u8 *msg_hash,
    usz       hash_len) {
  if (sizes_bad(n_len, sig_len, hash_len)) return 0;
  quic_bn bn_n, bn_s;
  quic_bn_from_be(&bn_n, n, n_len);
  quic_bn_from_be(&bn_s, sig, sig_len);
  if (quic_bn_cmp(&bn_s, &bn_n) >= 0) return 0; /* RFC 8017 8.2.2 */
  return rsa_check(&bn_s, &bn_n, n_len, msg_hash, hash_len);
}
