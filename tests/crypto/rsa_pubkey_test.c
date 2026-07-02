#include "crypto/pki/encoding/x509/rsa_pubkey.h"

#include "test.h"

/* DER length octets (short or long form up to two length bytes). */
static usz rpk_len(u8 *out, usz len) {
  if (len < 128) {
    out[0] = (u8)len;
    return 1;
  }
  if (len < 256) {
    out[0] = 0x81;
    out[1] = (u8)len;
    return 2;
  }
  out[0] = 0x82;
  out[1] = (u8)(len >> 8);
  out[2] = (u8)len;
  return 3;
}

/* One INTEGER TLV. */
static usz rpk_int(u8 *out, const u8 *v, usz len) {
  usz o  = 1;
  out[0] = 0x02;
  o += rpk_len(out + o, len);
  for (usz i = 0; i < len; i++) out[o + i] = v[i];
  return o + len;
}

/* The BIT STRING value of an rsaEncryption subjectPublicKey holding
 * RSAPublicKey { n, e } (RFC 8017 A.1.1). Returns the total length. */
static usz rpk_key(u8 *out, const u8 *nv, usz nl, const u8 *ev, usz el) {
  u8  body[600];
  usz blen, o = 2;
  blen = rpk_int(body, nv, nl);
  blen += rpk_int(body + blen, ev, el);
  out[0] = 0x00; /* BIT STRING unused bits */
  out[1] = 0x30;
  o += rpk_len(out + o, blen);
  for (usz i = 0; i < blen; i++) out[o + i] = body[i];
  return o + blen;
}

/* A canonical odd modulus of `len` value bytes with the top bit set, so the
 * INTEGER carries a 0x00 sign pad. Returns the content length (len + 1). */
static usz rpk_padded_n(u8 *out, usz len) {
  out[0] = 0x00; /* sign pad */
  out[1] = 0xc1;
  for (usz i = 2; i < len; i++) out[i] = 0xaa;
  out[len] = 0x01; /* odd */
  return len + 1;
}

/* A key with a valid 2048-bit modulus and the given exponent. */
static usz rpk_key_e(u8 *key, const u8 *ev, usz el) {
  u8  nv[257];
  usz nl = rpk_padded_n(nv, 256);
  return rpk_key(key, nv, nl, ev, el);
}

static const u8 rpk_e_f4[3] = {0x01, 0x00, 0x01};

/* A 2048-bit canonical odd n (sign pad stripped) and e=65537 are accepted
 * with correct views. */
static void test_rsa_pubkey_extract(void) {
  u8        key[600];
  quic_span n, e;
  usz       klen = rpk_key_e(key, rpk_e_f4, sizeof(rpk_e_f4));
  CHECK(quic_x509_rsa_pubkey(quic_span_of(key, klen), &n, &e) == 1);
  CHECK(n.n == 256 && n.p[0] == 0xc1 && n.p[255] == 0x01); /* pad stripped */
  CHECK(e.n == 3 && e.p[0] == 0x01 && e.p[2] == 0x01);
}

/* RFC 8017 3.1 floor: a 2040-bit modulus is rejected, 2048 bits accepted. */
static void test_rsa_pubkey_min_n(void) {
  u8        nv[257], key[600];
  quic_span n, e;
  usz       klen;
  klen = rpk_key(key, nv, rpk_padded_n(nv, 255), rpk_e_f4, sizeof(rpk_e_f4));
  CHECK(quic_x509_rsa_pubkey(quic_span_of(key, klen), &n, &e) == 0);
  klen = rpk_key(key, nv, rpk_padded_n(nv, 256), rpk_e_f4, sizeof(rpk_e_f4));
  CHECK(quic_x509_rsa_pubkey(quic_span_of(key, klen), &n, &e) == 1);
}

/* An even modulus cannot be a product of odd primes: rejected. */
static void test_rsa_pubkey_even_n(void) {
  u8        nv[257], key[600];
  quic_span n, e;
  usz       klen, nl;
  nl      = rpk_padded_n(nv, 256);
  nv[256] = 0x02; /* even low octet */
  klen    = rpk_key(key, nv, nl, rpk_e_f4, sizeof(rpk_e_f4));
  CHECK(quic_x509_rsa_pubkey(quic_span_of(key, klen), &n, &e) == 0);
}

/* X.690 8.3.2: a redundant leading zero (still zero after the one sign pad)
 * is rejected. */
static void test_rsa_pubkey_noncanon_n(void) {
  u8        nv[259], key[600];
  quic_span n, e;
  usz       klen, nl;
  nl    = rpk_padded_n(nv + 1, 256) + 1;
  nv[0] = 0x00; /* second leading zero */
  klen  = rpk_key(key, nv, nl, rpk_e_f4, sizeof(rpk_e_f4));
  CHECK(quic_x509_rsa_pubkey(quic_span_of(key, klen), &n, &e) == 0);
}

/* e=1 is below the RFC 8017 minimum of 3; e=3 is the boundary accept. */
static void test_rsa_pubkey_e_min(void) {
  u8        key[600];
  const u8  e1[1] = {0x01}, e3[1] = {0x03};
  quic_span n, e;
  usz       klen;
  klen = rpk_key_e(key, e1, 1);
  CHECK(quic_x509_rsa_pubkey(quic_span_of(key, klen), &n, &e) == 0);
  klen = rpk_key_e(key, e3, 1);
  CHECK(quic_x509_rsa_pubkey(quic_span_of(key, klen), &n, &e) == 1);
}

/* An even exponent (65536) is rejected. */
static void test_rsa_pubkey_even_e(void) {
  u8        key[600];
  const u8  ev[3] = {0x01, 0x00, 0x00};
  quic_span n, e;
  usz       klen = rpk_key_e(key, ev, sizeof(ev));
  CHECK(quic_x509_rsa_pubkey(quic_span_of(key, klen), &n, &e) == 0);
}

/* e up to 8 octets (< 2^64) is accepted; 9 octets is rejected. */
static void test_rsa_pubkey_e_max(void) {
  u8        key[600];
  const u8  e8[8] = {0x01, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x01};
  const u8  e9[9] = {0x01, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x01};
  quic_span n, e;
  usz       klen;
  klen = rpk_key_e(key, e8, sizeof(e8));
  CHECK(quic_x509_rsa_pubkey(quic_span_of(key, klen), &n, &e) == 1);
  klen = rpk_key_e(key, e9, sizeof(e9));
  CHECK(quic_x509_rsa_pubkey(quic_span_of(key, klen), &n, &e) == 0);
}

/* A BIT STRING that does not lead with the 0x00 unused-bits octet is rejected.
 */
static void test_rsa_pubkey_bad_prefix(void) {
  const u8  key[] = {0x01, 0x30, 0x03, 0x02, 0x01, 0x01};
  quic_span n, e;
  CHECK(quic_x509_rsa_pubkey(quic_span_of(key, sizeof(key)), &n, &e) == 0);
}

/* A SEQUENCE with only one INTEGER has no publicExponent. */
static void test_rsa_pubkey_missing_e(void) {
  const u8  key[] = {0x00, 0x30, 0x03, 0x02, 0x01, 0x05};
  quic_span n, e;
  CHECK(quic_x509_rsa_pubkey(quic_span_of(key, sizeof(key)), &n, &e) == 0);
}

void test_rsa_pubkey(void) {
  test_rsa_pubkey_extract();
  test_rsa_pubkey_min_n();
  test_rsa_pubkey_even_n();
  test_rsa_pubkey_noncanon_n();
  test_rsa_pubkey_e_min();
  test_rsa_pubkey_even_e();
  test_rsa_pubkey_e_max();
  test_rsa_pubkey_bad_prefix();
  test_rsa_pubkey_missing_e();
}
