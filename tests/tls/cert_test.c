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

  wired_span     ctx;
  tls_cert_entry first;
  CHECK(tls_cert_parse(wired_span_of(m, k), &ctx, &first) == 1);
  CHECK(ctx.n == 0 && first.cert_len == 4);
  CHECK(first.cert_data[0] == 'A' && first.cert_data[3] == 'D');

  CHECK(tls_cert_parse(wired_span_of(m, k - 1), &ctx, &first) == 0); /* short */
}

/* CertificateVerify yields the scheme and the signature view. */
static void test_certverify_parse(void) {
  /* scheme 0x0807 (ed25519); signature (2-byte len = 3) {0x11,0x22,0x33}. */
  u8         m[8] = {0x08, 0x07, 0x00, 0x03, 0x11, 0x22, 0x33, 0x00};
  u16        scheme;
  wired_span sig;
  CHECK(tls_certverify_parse(wired_span_of(m, 7), &scheme, &sig) == 1);
  CHECK(scheme == 0x0807 && sig.n == 3);
  CHECK(sig.p[0] == 0x11 && sig.p[2] == 0x33);

  CHECK(
      tls_certverify_parse(wired_span_of(m, 5), &scheme, &sig) ==
      0); /* short */
}

void test_cert(void) {
  test_cert_parse();
  test_certverify_parse();
}
