#include "crypto/pki/cert/p256cert/p256cert.h"

#include "crypto/asymmetric/ecc/p256/ecdsa_verify.h"
#include "crypto/asymmetric/ecc/p256/p256_field.h"
#include "crypto/asymmetric/ecc/p256/p256_point.h"
#include "crypto/pki/cert/p256cert/spki.h"
#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/asn1/derseq.h"
#include "crypto/pki/encoding/x509/ec_pubkey.h"
#include "crypto/pki/encoding/x509/san.h"
#include "crypto/pki/encoding/x509/spki.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "crypto/symmetric/hash/hash/sha256.h"
#include "test.h"

/* ecdsa-with-SHA256 OID, expected as the cert signatureAlgorithm. */
static const u8 pc_oid_ecdsa_sha256[] = {0x2a, 0x86, 0x48, 0xce,
                                         0x3d, 0x04, 0x03, 0x02};

/* Derive the affine public key Q = priv * G as big-endian (x, y). */
static void pc_pubkey(const u8 priv[32], u8 x[32], u8 y[32]) {
  ec_point q;
  quic_ec_mul(&q, priv, &quic_p256_g);
  quic_fp_to_be(x, q.x);
  quic_fp_to_be(y, q.y);
}

/* Build a self-signed cert from priv/x/y into cert, returning its length. */
static usz pc_build(
    const u8 priv[32], const u8 x[32], const u8 y[32], u8 *cert, usz cap) {
  quic_p256cert_key k = {priv, x, y};
  quic_obuf         o = quic_obuf_of(cert, cap);
  CHECK(quic_p256cert_build(&k, &o) == 1);
  return o.len;
}

/* Right-align a DER INTEGER value (sans/with 0x00 pad, <=32 octets) into b[32].
 */
static void pc_be32(u8 b[32], quic_span v) {
  const u8 *p = v.p;
  usz       n = v.n;
  for (usz i = 0; i < 32; i++) b[i] = 0;
  if (n > 32) {
    p += n - 32;
    n = 32;
  } /* drop a leading 0x00 sign pad */
  for (usz i = 0; i < n; i++) b[32 - n + i] = p[i];
}

/* SEC1 C.5. Decode ECDSA-Sig-Value SEQUENCE{ INTEGER r, INTEGER s } -> r, s. */
static int pc_sig_rs(quic_span der, u8 r[32], u8 s[32]) {
  u8          tag;
  quic_span   seq, rv, sv;
  quic_derseq c;
  if (!quic_der_seq(der, &seq)) return 0;
  quic_derseq_init(&c, seq);
  if (!quic_derseq_next(&c, &tag, &rv)) return 0;
  if (!quic_derseq_next(&c, &tag, &sv)) return 0;
  pc_be32(r, rv);
  pc_be32(s, sv);
  return 1;
}

/* RFC 5280 4.1.2.7. Split a standalone SPKI into algorithm OID and key bits. */
static int pc_split_spki(quic_span spki, quic_span *oid, quic_span *key) {
  u8          tag;
  quic_span   seq, alg;
  quic_derseq c, a;
  if (!quic_der_seq(spki, &seq)) return 0;
  quic_derseq_init(&c, seq);
  if (!quic_derseq_next(&c, &tag, &alg)) return 0;
  if (!quic_derseq_next(&c, &tag, key)) return 0;
  quic_derseq_init(&a, alg);
  return quic_derseq_next(&a, &tag, oid);
}

/* RFC 5480 2.2. The built SPKI round-trips back to the input (x, y). */
static void test_spki_roundtrip(void) {
  u8 priv[32], x[32], y[32];
  for (usz i = 0; i < 32; i++) priv[i] = (u8)(0x10 + i);
  pc_pubkey(priv, x, y);

  u8        spki[128];
  quic_obuf o = quic_obuf_of(spki, sizeof(spki));
  CHECK(quic_p256cert_spki(x, y, &o) == 1);

  quic_span oid, key;
  CHECK(pc_split_spki(quic_span_of(spki, o.len), &oid, &key) == 1);
  CHECK(quic_x509_is_ec(oid) == 1);

  u8 rx[32], ry[32];
  CHECK(quic_x509_ec_pubkey(key, rx, ry) == 1);
  for (usz i = 0; i < 32; i++) CHECK(rx[i] == x[i] && ry[i] == y[i]);
}

/* RFC 5280 4.1. The cert parses; sig_alg is ecdsa-with-SHA256. */
static void test_p256cert_parse(void) {
  u8 priv[32], x[32], y[32];
  for (usz i = 0; i < 32; i++) priv[i] = (u8)(0x40 + i);
  pc_pubkey(priv, x, y);

  u8  cert[1024];
  usz clen = pc_build(priv, x, y, cert, sizeof(cert));

  quic_x509 c;
  CHECK(quic_x509_parse(quic_span_of(cert, clen), &c) == 1);
  CHECK(c.sig_alg_oid.n == sizeof(pc_oid_ecdsa_sha256));
  for (usz i = 0; i < c.sig_alg_oid.n; i++)
    CHECK(c.sig_alg_oid.p[i] == pc_oid_ecdsa_sha256[i]);
}

/* SEC1. The SPKI inside the cert carries secp256r1 and the input key. */
static void test_cert_spki_key(void) {
  u8 priv[32], x[32], y[32];
  for (usz i = 0; i < 32; i++) priv[i] = (u8)(0x40 + i);
  pc_pubkey(priv, x, y);

  u8        cert[1024];
  usz       clen = pc_build(priv, x, y, cert, sizeof(cert));
  quic_x509 c;
  CHECK(quic_x509_parse(quic_span_of(cert, clen), &c) == 1);

  quic_span oid, key;
  CHECK(quic_x509_public_key(c.tbs, &oid, &key) == 1);
  CHECK(quic_x509_is_ec(oid) == 1);

  u8 rx[32], ry[32];
  CHECK(quic_x509_ec_pubkey(key, rx, ry) == 1);
  for (usz i = 0; i < 32; i++) CHECK(rx[i] == x[i] && ry[i] == y[i]);
}

/* RFC 5280 4.1.1.3 / FIPS 186-4 6.4. The cert verifies its own signature. */
static void test_cert_selfsigned(void) {
  u8 priv[32], x[32], y[32];
  for (usz i = 0; i < 32; i++) priv[i] = (u8)(0x40 + i);
  pc_pubkey(priv, x, y);

  u8        cert[1024];
  usz       clen = pc_build(priv, x, y, cert, sizeof(cert));
  quic_x509 c;
  CHECK(quic_x509_parse(quic_span_of(cert, clen), &c) == 1);

  /* signatureValue BIT STRING: 0x00 unused-bits then ECDSA-Sig-Value DER. */
  CHECK(c.sig.n > 1 && c.sig.p[0] == 0x00);
  u8 r[32], s[32];
  CHECK(pc_sig_rs(quic_span_of(c.sig.p + 1, c.sig.n - 1), r, s) == 1);

  u8 hash[32];
  quic_sha256(c.tbs.p, c.tbs.n, hash);
  CHECK(quic_ecdsa_p256_verify(x, y, r, s, hash) == 1);

  /* A flipped TBS byte must break verification. */
  u8 saved = c.tbs.p[0];
  ((u8 *)c.tbs.p)[0] ^= 0xff;
  quic_sha256(c.tbs.p, c.tbs.n, hash);
  CHECK(quic_ecdsa_p256_verify(x, y, r, s, hash) == 0);
  ((u8 *)c.tbs.p)[0] = saved;
}

/* RFC 5280 4.2.1.6. The cert carries a SubjectAltName dNSName "localhost",
 * the name modern TLS stacks (BoringSSL/curl) check; a foreign host fails. */
static void test_cert_san_localhost(void) {
  u8 priv[32], x[32], y[32];
  for (usz i = 0; i < 32; i++) priv[i] = (u8)(0x40 + i);
  pc_pubkey(priv, x, y);

  u8        cert[1024];
  usz       clen = pc_build(priv, x, y, cert, sizeof(cert));
  quic_x509 c;
  CHECK(quic_x509_parse(quic_span_of(cert, clen), &c) == 1);

  CHECK(
      quic_x509_san_matches(c.tbs, quic_span_of((const u8 *)"localhost", 9)) ==
      1);
  CHECK(
      quic_x509_san_matches(
          c.tbs, quic_span_of((const u8 *)"example.com", 11)) == 0);
}

void test_p256cert(void) {
  test_spki_roundtrip();
  test_p256cert_parse();
  test_cert_spki_key();
  test_cert_selfsigned();
  test_cert_san_localhost();
}
