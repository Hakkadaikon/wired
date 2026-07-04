#include "crypto/asymmetric/rsa/rsa_verify.h"

#include "crypto/asymmetric/bignum/modexp.h"

/* RFC 8017 9.2 Note 1. DigestInfo prefixes (all 19 octets) keyed by digest
 * length, which is unique per hash: 32 (SHA-256), 48 (SHA-384), 64
 * (SHA-512). */
#define RSA_DI_LEN 19
static const u8 rsa_di_sha256[RSA_DI_LEN] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
static const u8 rsa_di_sha384[RSA_DI_LEN] = {
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
static const u8 rsa_di_sha512[RSA_DI_LEN] = {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};

static const struct {
  usz       hash_len;
  const u8* prefix;
} rsa_di[] = {
    {32, rsa_di_sha256},
    {48, rsa_di_sha384},
    {64, rsa_di_sha512},
};

/* The DigestInfo prefix for a digest length, or 0 for an unsupported hash. */
static const u8* di_prefix(usz hash_len) {
  for (usz i = 0; i < sizeof(rsa_di) / sizeof(rsa_di[0]); i++)
    if (rsa_di[i].hash_len == hash_len) return rsa_di[i].prefix;
  return 0;
}

/* Write DigestInfo (prefix + hash) at out. */
static void put_digestinfo(u8* out, quic_span h) {
  const u8* prefix = di_prefix(h.n);
  for (usz i = 0; i < RSA_DI_LEN; i++) out[i] = prefix[i];
  for (usz i = 0; i < h.n; i++) out[RSA_DI_LEN + i] = h.p[i];
}

/* RFC 8017 9.2. Build the expected EM = 0x00 01 FF..FF 00 DigestInfo H.
 * Returns 1 if it fits with PS>=8 octets, else 0. */
static int emsa_pkcs1(u8* em, usz em_len, quic_span h) {
  usz fixed = 3 + RSA_DI_LEN + h.n; /* 00 01 ...00 prefix H */
  if (em_len < fixed + 8) return 0;
  usz ps_end = em_len - fixed + 2;
  em[0]      = 0x00;
  em[1]      = 0x01;
  for (usz i = 2; i < ps_end; i++) em[i] = 0xff;
  em[ps_end] = 0x00;
  put_digestinfo(em + ps_end + 1, h);
  return 1;
}

/* The value bytes of F4 = 65537. */
static int rsa_f4_val(const u8* e) {
  return e[0] == 0x01 && e[1] == 0x00 && e[2] == 0x01;
}

int quic_rsa_e_is_f4(const u8* e, usz e_len) {
  return e_len == 3 && rsa_f4_val(e);
}

/* Constant-time equality over len octets. 1 if equal, else 0. */
static int ct_equal(const u8* a, const u8* b, usz len) {
  u8 d = 0;
  for (usz i = 0; i < len; i++) d |= a[i] ^ b[i];
  return d == 0;
}

/* e = 65537 (RFC 8017 common public exponent). */
static void rsa_e_f4(quic_bn* e) {
  for (usz i = 0; i < QUIC_BN_LIMBS; i++) e->v[i] = 0;
  e->v[0] = 65537;
}

/* Modulus length outside the supportable PKCS#1 v1.5 range for this hash. */
static int n_len_bad(usz n_len, usz hash_len) {
  if (n_len > (usz)QUIC_BN_LIMBS * 8) return 1;
  return n_len < 11 + RSA_DI_LEN + hash_len;
}

/* Reject inputs that cannot yield a valid PKCS#1 v1.5 signature. */
static int sizes_bad(usz n_len, usz sig_len, usz hash_len) {
  if (di_prefix(hash_len) == 0) return 1;
  if (n_len_bad(n_len, hash_len)) return 1;
  return sig_len != n_len;
}

/* Sizes acceptable and the exponent is the supported F4. */
static int rsa_inputs_ok(const quic_rsa_pub* pub, usz sig_len, usz hash_len) {
  if (sizes_bad(pub->n.n, sig_len, hash_len)) return 0;
  return quic_rsa_e_is_f4(pub->e.p, pub->e.n);
}

/* Signature and modulus as bignums, plus the modulus octet length. */
typedef struct {
  quic_bn bn_s;
  quic_bn bn_n;
  usz     n_len;
} rsav_sn;

/* RFC 8017 8.2.2 steps 2-4: m = s^e mod n, then EM compare. s,n already <
 * range. */
static int rsa_check(const rsav_sn* c, quic_span h) {
  quic_bn bn_e, m;
  rsa_e_f4(&bn_e);
  quic_bn_modexp(&m, &c->bn_s, (quic_bn_expmod){&bn_e, &c->bn_n});
  u8 got[QUIC_BN_LIMBS * 8], want[QUIC_BN_LIMBS * 8];
  quic_bn_to_be(&m, got, c->n_len);
  if (!emsa_pkcs1(want, c->n_len, h)) return 0;
  return ct_equal(got, want, c->n_len);
}

int quic_rsa_pkcs1_verify(
    const quic_rsa_pub* pub, quic_span sig, quic_span msg_hash) {
  if (!rsa_inputs_ok(pub, sig.n, msg_hash.n)) return 0;
  rsav_sn c;
  c.n_len = pub->n.n;
  quic_bn_from_be(&c.bn_n, pub->n.p, pub->n.n);
  quic_bn_from_be(&c.bn_s, sig.p, sig.n);
  if (quic_bn_cmp(&c.bn_s, &c.bn_n) >= 0) return 0; /* RFC 8017 8.2.2 */
  return rsa_check(&c, msg_hash);
}
