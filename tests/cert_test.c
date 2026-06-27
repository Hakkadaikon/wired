#include "test.h"
#include "tls/cert.c"

/* A Certificate message with an empty context and one entry round-trips:
 * the end-entity cert_data is extracted. */
static void test_cert_parse(void)
{
    /* context len 0; list (3-byte len) of one entry:
     * cert_data (3-byte len = 4) "ABCD"; extensions (2-byte len 0). */
    u8 m[32];
    usz k = 0;
    m[k++] = 0;                       /* context length 0 */
    m[k++] = 0; m[k++] = 0; m[k++] = 9; /* certificate_list length = 9 */
    m[k++] = 0; m[k++] = 0; m[k++] = 4; /* cert_data length 4 */
    m[k++] = 'A'; m[k++] = 'B'; m[k++] = 'C'; m[k++] = 'D';
    m[k++] = 0; m[k++] = 0;           /* extensions length 0 */

    const u8 *ctx;
    u32 ctx_len;
    quic_tls_cert_entry first;
    CHECK(quic_tls_cert_parse(m, k, &ctx, &ctx_len, &first) == 1);
    CHECK(ctx_len == 0 && first.cert_len == 4);
    CHECK(first.cert_data[0] == 'A' && first.cert_data[3] == 'D');

    CHECK(quic_tls_cert_parse(m, k - 1, &ctx, &ctx_len, &first) == 0); /* short */
}

/* CertificateVerify yields the scheme and the signature view. */
static void test_certverify_parse(void)
{
    /* scheme 0x0807 (ed25519); signature (2-byte len = 3) {0x11,0x22,0x33}. */
    u8 m[8] = {0x08, 0x07, 0x00, 0x03, 0x11, 0x22, 0x33, 0x00};
    u16 scheme, sig_len;
    const u8 *sig;
    CHECK(quic_tls_certverify_parse(m, 7, &scheme, &sig, &sig_len) == 1);
    CHECK(scheme == 0x0807 && sig_len == 3);
    CHECK(sig[0] == 0x11 && sig[2] == 0x33);

    CHECK(quic_tls_certverify_parse(m, 5, &scheme, &sig, &sig_len) == 0); /* short */
}

void test_cert(void)
{
    test_cert_parse();
    test_certverify_parse();
}
