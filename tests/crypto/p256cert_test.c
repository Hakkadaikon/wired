#include "crypto/pki/cert/p256cert/p256cert.h"

#include "common/platform/clock/clock.h"
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
    const u8 priv[32], const u8 x[32], const u8 y[32], u8* cert, usz cap) {
  quic_p256cert_key k = {priv, x, y, 0, 0};
  quic_obuf         o = quic_obuf_of(cert, cap);
  CHECK(quic_p256cert_build(&k, &o) == 1);
  return o.len;
}

/* Right-align a DER INTEGER value (sans/with 0x00 pad, <=32 octets) into b[32].
 */
static void pc_be32(u8 b[32], quic_span v) {
  const u8* p = v.p;
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
static int pc_split_spki(quic_span spki, quic_span* oid, quic_span* key) {
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
  ((u8*)c.tbs.p)[0] ^= 0xff;
  quic_sha256(c.tbs.p, c.tbs.n, hash);
  CHECK(quic_ecdsa_p256_verify(x, y, r, s, hash) == 0);
  ((u8*)c.tbs.p)[0] = saved;
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
      quic_x509_san_matches(c.tbs, quic_span_of((const u8*)"localhost", 9)) ==
      1);
  CHECK(
      quic_x509_san_matches(
          c.tbs, quic_span_of((const u8*)"example.com", 11)) == 0);
}

/* id-ce-subjectAltName = 2.5.29.17 (RFC 5280 4.2.1.6), mirroring san.c's own
 * copy -- this test reaches for the raw extnValue bytes directly since
 * quic_x509_san_matches only checks dNSName entries, not iPAddress. */
static const u8 pct_oid_san[] = {0x55, 0x1d, 0x11};

/* 1 if der[i..i+6) is the GeneralName TLV for iPAddress [7] IMPLICIT OCTET
 * STRING (tag 0x87, RFC 5280 4.2.1.6) carrying exactly ip[4]. */
static int pc_ipv4_tlv_at(const u8* p, const u8 ip[4]) {
  if (p[0] != 0x87 || p[1] != 4) return 0;
  for (usz j = 0; j < 4; j++)
    if (p[2 + j] != ip[j]) return 0;
  return 1;
}

/* 1 if der contains, anywhere, the fixed-length iPAddress TLV for ip[4]. A
 * substring scan is fine here: the TLV's tag byte cannot appear as a false
 * match inside the fixed-shape dNSName entry this same GeneralNames
 * SEQUENCE also carries. */
static int pc_has_san_ipv4(quic_span der, const u8 ip[4]) {
  if (der.n < 6) return 0;
  for (usz i = 0; i + 6 <= der.n; i++)
    if (pc_ipv4_tlv_at(der.p + i, ip)) return 1;
  return 0;
}

/* san_ipv4 omitted (0): the SAN extension carries only dNSName, unchanged
 * from before this field existed (regression guard). */
static void test_cert_san_ipv4_omitted(void) {
  u8 priv[32], x[32], y[32];
  for (usz i = 0; i < 32; i++) priv[i] = (u8)(0x50 + i);
  pc_pubkey(priv, x, y);

  u8                cert[1024];
  quic_p256cert_key k = {priv, x, y, 0, 0};
  quic_obuf         o = quic_obuf_of(cert, sizeof(cert));
  CHECK(quic_p256cert_build(&k, &o) == 1);

  quic_x509 c;
  quic_span san;
  CHECK(quic_x509_parse(quic_span_of(cert, o.len), &c) == 1);
  CHECK(quic_x509_find_ext(c.tbs, quic_span_of(pct_oid_san, 3), &san) == 1);
  {
    const u8 zero_ip[4] = {0, 0, 0, 0};
    CHECK(pc_has_san_ipv4(san, zero_ip) == 0);
  }
}

/* RFC 5280 4.2.1.6: san_ipv4 given adds an iPAddress GeneralName alongside
 * dNSName=localhost -- the entry a browser checks when validating a
 * WebTransport connection to a bare IP literal (draft-ietf-webtrans-http3-15
 * serverCertificateHashes pinning still enforces hostname validation). */
static void test_cert_san_ipv4_present(void) {
  u8 priv[32], x[32], y[32];
  for (usz i = 0; i < 32; i++) priv[i] = (u8)(0x60 + i);
  pc_pubkey(priv, x, y);

  const u8          ip[4] = {160, 251, 55, 132};
  u8                cert[1024];
  quic_p256cert_key k = {priv, x, y, ip, 0};
  quic_obuf         o = quic_obuf_of(cert, sizeof(cert));
  CHECK(quic_p256cert_build(&k, &o) == 1);

  quic_x509 c;
  quic_span san;
  CHECK(quic_x509_parse(quic_span_of(cert, o.len), &c) == 1);
  CHECK(quic_x509_find_ext(c.tbs, quic_span_of(pct_oid_san, 3), &san) == 1);
  CHECK(pc_has_san_ipv4(san, ip) == 1);
  /* dNSName=localhost is still there too -- san_ipv4 adds, does not
   * replace */
  CHECK(
      quic_x509_san_matches(c.tbs, quic_span_of((const u8*)"localhost", 9)) ==
      1);
}

/* W3C WebTransport serverCertificateHashes rejects a cert whose validity
 * window exceeds 14 days -- now_secs given anchors notBefore = now_secs and
 * notAfter = now_secs + 14 days exactly, not the pre-existing 2020-2030
 * window. */
static void test_cert_now_secs_14day_window(void) {
  u8 priv[32], x[32], y[32];
  for (usz i = 0; i < 32; i++) priv[i] = (u8)(0x70 + i);
  pc_pubkey(priv, x, y);

  const u64         now        = 1782988200ULL; /* 2026-07-02T10:30:00Z */
  const u64         fourteen_d = 14ULL * 86400ULL;
  u8                cert[1024];
  quic_p256cert_key k = {priv, x, y, 0, now};
  quic_obuf         o = quic_obuf_of(cert, sizeof(cert));
  CHECK(quic_p256cert_build(&k, &o) == 1);

  quic_x509 c;
  CHECK(quic_x509_parse(quic_span_of(cert, o.len), &c) == 1);

  /* quic_x509_validity_ok takes YYYYMMDDHHMMSS, not raw epoch seconds --
   * round every probe through the same converter the cert builder used. */
  {
    u64 nb   = quic_clock_epoch_to_ymdhms(now);
    u64 na   = quic_clock_epoch_to_ymdhms(now + fourteen_d);
    u64 nb_m = quic_clock_epoch_to_ymdhms(now - 1);
    u64 na_p = quic_clock_epoch_to_ymdhms(now + fourteen_d + 1);
    /* inside the window */
    CHECK(quic_x509_validity_ok(c.tbs, nb) == 1);
    CHECK(quic_x509_validity_ok(c.tbs, na) == 1);
    /* one second outside either edge */
    CHECK(quic_x509_validity_ok(c.tbs, nb_m) == 0);
    CHECK(quic_x509_validity_ok(c.tbs, na_p) == 0);
  }
  /* the fixed 2020-2030 window (no now_secs) would have accepted this --
   * confirms the window actually narrowed, not just shifted. */
  CHECK(quic_x509_validity_ok(c.tbs, 20280101000000ULL) == 0);
}

/* now_secs = 0 (the default/test sentinel) keeps the pre-existing fixed
 * 2020-2030 window -- a regression guard against breaking callers that pass
 * a zero-initialized quic_p256cert_key. */
static void test_cert_now_secs_zero_keeps_fixed_window(void) {
  u8 priv[32], x[32], y[32];
  for (usz i = 0; i < 32; i++) priv[i] = (u8)(0x80 + i);
  pc_pubkey(priv, x, y);

  u8                cert[1024];
  quic_p256cert_key k = {priv, x, y, 0, 0};
  quic_obuf         o = quic_obuf_of(cert, sizeof(cert));
  CHECK(quic_p256cert_build(&k, &o) == 1);

  quic_x509 c;
  CHECK(quic_x509_parse(quic_span_of(cert, o.len), &c) == 1);
  CHECK(quic_x509_validity_ok(c.tbs, 20200101000000ULL) == 1);
  CHECK(quic_x509_validity_ok(c.tbs, 20300101000000ULL) == 1);
}

void test_p256cert(void) {
  test_spki_roundtrip();
  test_p256cert_parse();
  test_cert_spki_key();
  test_cert_selfsigned();
  test_cert_san_localhost();
  test_cert_san_ipv4_omitted();
  test_cert_san_ipv4_present();
  test_cert_now_secs_14day_window();
  test_cert_now_secs_zero_keeps_fixed_window();
}
