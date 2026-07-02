#include "crypto/pki/cert/selfcert/selfcert.h"

#include "crypto/asymmetric/ecc/ed25519/ed25519.h"
#include "crypto/pki/cert/selfcert/derenc.h"
#include "crypto/pki/cert/selfcert/tbs.h"
#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/encoding/x509/spki.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "test.h"

/* X.690 8.1. der_tlv emits a well-formed TLV that der_read parses back. */
static void test_der_tlv_roundtrip(void) {
  u8        out[8];
  quic_obuf o   = quic_obuf_of(out, sizeof(out));
  const u8  v[] = {0xaa, 0xbb};
  CHECK(quic_selfcert_der_tlv(QUIC_DER_INTEGER, quic_span_of(v, 2), &o) == 1);
  CHECK(o.len == 4 && out[0] == 0x02 && out[1] == 0x02);

  quic_der_tlv t;
  CHECK(quic_der_read(quic_span_of(out, o.len), &t) == 1);
  CHECK(
      t.tag == 0x02 && t.val.n == 2 && t.val.p[0] == 0xaa &&
      t.val.p[1] == 0xbb);
}

/* X.690 8.1.3.5. A 200-octet value uses the 0x81 long form. */
static void test_der_tlv_longform(void) {
  u8        big[200] = {0};
  u8        out[210];
  quic_obuf o = quic_obuf_of(out, sizeof(out));
  CHECK(
      quic_selfcert_der_tlv(
          QUIC_DER_OCTET_STRING, quic_span_of(big, 200), &o) == 1);
  CHECK(out[1] == 0x81 && out[2] == 200 && o.len == 203);
}

/* der_tlv refuses to overflow the caller buffer. */
static void test_der_tlv_overflow(void) {
  u8        out[3];
  quic_obuf o   = quic_obuf_of(out, sizeof(out));
  const u8  v[] = {1, 2, 3, 4};
  CHECK(quic_selfcert_der_tlv(QUIC_DER_INTEGER, quic_span_of(v, 4), &o) == 0);
}

/* RFC 8410 4. The built SPKI exposes the same 32-byte Ed25519 key. */
static void test_tbs_spki_key(void) {
  u8 pub[32];
  u8 seed[32];
  for (usz i = 0; i < 32; i++) seed[i] = (u8)i;
  CHECK(quic_ed25519_keypair(seed, pub) == 1);

  u8        tbs[512];
  quic_obuf to = quic_obuf_of(tbs, sizeof(tbs));
  CHECK(quic_selfcert_tbs(pub, &to) == 1);

  quic_span oid, key;
  CHECK(quic_x509_public_key(quic_span_of(tbs, to.len), &oid, &key) == 1);
  /* BIT STRING value: 0x00 unused-bits prefix then the 32-byte key. */
  CHECK(key.n == 33 && key.p[0] == 0x00);
  for (usz i = 0; i < 32; i++) CHECK(key.p[1 + i] == pub[i]);
}

/* RFC 5280 4.1.1.3. Parse the cert back and verify its own signature. */
static void test_build_selfsigned(void) {
  u8 seed[32];
  for (usz i = 0; i < 32; i++) seed[i] = (u8)(0x40 + i);
  u8 pub[32];
  quic_ed25519_keypair(seed, pub);

  u8        cert[1024];
  quic_obuf co = quic_obuf_of(cert, sizeof(cert));
  CHECK(quic_selfcert_build(seed, &co) == 1);

  quic_x509 c;
  CHECK(quic_x509_parse(quic_span_of(cert, co.len), &c) == 1);

  quic_span oid, key;
  CHECK(quic_x509_public_key(c.tbs, &oid, &key) == 1);
  CHECK(key.n == 33);
  for (usz i = 0; i < 32; i++) CHECK(key.p[1 + i] == pub[i]);

  /* signatureValue BIT STRING: 0x00 prefix then the 64-byte signature. */
  CHECK(c.sig.n == 65 && c.sig.p[0] == 0x00);
  CHECK(quic_ed25519_verify(c.sig.p + 1, c.tbs.p, c.tbs.n, key.p + 1) == 1);

  /* A flipped TBS byte must break verification. */
  u8 bad = c.tbs.p[0];
  ((u8 *)c.tbs.p)[0] ^= 0xff;
  CHECK(quic_ed25519_verify(c.sig.p + 1, c.tbs.p, c.tbs.n, key.p + 1) == 0);
  ((u8 *)c.tbs.p)[0] = bad;
}

void test_selfcert(void) {
  test_der_tlv_roundtrip();
  test_der_tlv_longform();
  test_der_tlv_overflow();
  test_tbs_spki_key();
  test_build_selfsigned();
}
