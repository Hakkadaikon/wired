#include "test.h"

/* A Certificate message with an empty context and one entry round-trips:
 * the end-entity cert_data is extracted. */
static void test_cert_parse(void) {
  /* context len 0; list (3-byte len) of one entry:
   * cert_data (3-byte len = 4) "ABCD"; extensions (2-byte len 0). */
  u8  m[32];
  usz k  = 0;
  m[k++] = 0; /* context length 0 */
  m[k++] = 0;
  m[k++] = 0;
  m[k++] = 9; /* certificate_list length = 9 */
  m[k++] = 0;
  m[k++] = 0;
  m[k++] = 4; /* cert_data length 4 */
  m[k++] = 'A';
  m[k++] = 'B';
  m[k++] = 'C';
  m[k++] = 'D';
  m[k++] = 0;
  m[k++] = 0; /* extensions length 0 */

  quic_span           ctx;
  quic_tls_cert_entry first;
  CHECK(quic_tls_cert_parse(quic_span_of(m, k), &ctx, &first) == 1);
  CHECK(ctx.n == 0 && first.cert_len == 4);
  CHECK(first.cert_data[0] == 'A' && first.cert_data[3] == 'D');

  CHECK(
      quic_tls_cert_parse(quic_span_of(m, k - 1), &ctx, &first) ==
      0); /* short */
}

/* CertificateVerify yields the scheme and the signature view. */
static void test_certverify_parse(void) {
  /* scheme 0x0807 (ed25519); signature (2-byte len = 3) {0x11,0x22,0x33}. */
  u8        m[8] = {0x08, 0x07, 0x00, 0x03, 0x11, 0x22, 0x33, 0x00};
  u16       scheme;
  quic_span sig;
  CHECK(quic_tls_certverify_parse(quic_span_of(m, 7), &scheme, &sig) == 1);
  CHECK(scheme == 0x0807 && sig.n == 3);
  CHECK(sig.p[0] == 0x11 && sig.p[2] == 0x33);

  CHECK(
      quic_tls_certverify_parse(quic_span_of(m, 5), &scheme, &sig) ==
      0); /* short */
}

/* The Ed25519 CertificateVerify wrapper rejects a wrong-length signature and
 * a signature that does not verify. (A positive case needs a real keypair;
 * the underlying Ed25519 verify is covered by RFC 8032 vectors.) */
static void test_certverify_ed25519(void) {
  u8 th[32], pk[32], sig[QUIC_ED25519_SIG];
  for (usz i = 0; i < 32; i++) {
    th[i] = (u8)i;
    pk[i] = (u8)(i + 1);
  }
  for (usz i = 0; i < QUIC_ED25519_SIG; i++) sig[i] = 0;

  CHECK(
      quic_tls_certverify_ed25519(quic_span_of(sig, 32), th, pk) ==
      0); /* wrong length */
  CHECK(
      quic_tls_certverify_ed25519(
          quic_span_of(sig, QUIC_ED25519_SIG), th, pk) == 0);

  /* the signed content is deterministic and well-formed */
  u8 c1[130], c2[130];
  build_signed(th, c1);
  build_signed(th, c2);
  CHECK(c1[0] == 0x20 && c1[63] == 0x20 && c1[64] == 'T' && c1[97] == 0x00);
  for (usz i = 0; i < 130; i++) CHECK(c1[i] == c2[i]);
}

void test_cert(void) {
  test_cert_parse();
  test_certverify_parse();
  test_certverify_ed25519();
}
