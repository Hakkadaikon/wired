#include "test.h"
#include "tls/handshake/core/tls/certverify.h"
#include "x509_golden.h"

/* RFC 8446 4.4.3. An unknown SignatureScheme is rejected outright. */
static void test_certverify_bad_scheme(void)
{
    u8 th[32], sig[64];
    for (usz i = 0; i < 32; i++) th[i] = (u8)i;
    for (usz i = 0; i < 64; i++) sig[i] = 0;
    CHECK(quic_tls_verify_cert_signature(0x0000, quic_x509_golden,
          sizeof(quic_x509_golden), sig, sizeof(sig), th) == 0);
    CHECK(quic_tls_verify_cert_signature(0xffff, quic_x509_golden,
          sizeof(quic_x509_golden), sig, sizeof(sig), th) == 0);
}

/* The golden cert is EC; a bogus ECDSA signature over the transcript fails
 * verification rather than crashing, exercising the ecdsa_p256 branch. */
static void test_certverify_ecdsa_bogus(void)
{
    u8 th[32];
    /* ECDSA-Sig-Value SEQUENCE { INTEGER 1, INTEGER 1 }: well-formed DER,
     * wrong signature. */
    const u8 sig[] = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};
    for (usz i = 0; i < 32; i++) th[i] = (u8)i;
    CHECK(quic_tls_verify_cert_signature(QUIC_TLS_SCHEME_ECDSA_P256,
          quic_x509_golden, sizeof(quic_x509_golden),
          sig, sizeof(sig), th) == 0);
}

/* A malformed ECDSA signature (not a SEQUENCE) is rejected before verify. */
static void test_certverify_ecdsa_malformed(void)
{
    u8 th[32];
    const u8 sig[] = {0x02, 0x01, 0x01}; /* a bare INTEGER, not the SEQUENCE */
    for (usz i = 0; i < 32; i++) th[i] = (u8)i;
    CHECK(quic_tls_verify_cert_signature(QUIC_TLS_SCHEME_ECDSA_P256,
          quic_x509_golden, sizeof(quic_x509_golden),
          sig, sizeof(sig), th) == 0);
}

void test_certverify(void)
{
    test_certverify_bad_scheme();
    test_certverify_ecdsa_bogus();
    test_certverify_ecdsa_malformed();
}
