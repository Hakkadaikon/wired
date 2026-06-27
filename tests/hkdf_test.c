#include "test.h"

/* hex_eq compares len bytes of got against a hex string. */
static int hex_eq(const u8 *got, const char *hex, usz len)
{
    for (usz i = 0; i < len; i++) {
        u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
        u8 b = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                    (lo <= '9' ? lo - '0' : lo - 'a' + 10));
        if (got[i] != b) return 0;
    }
    return 1;
}

/* RFC 5869 Appendix A.1 (SHA-256). */
static void test_hkdf_rfc5869(void)
{
    u8 ikm[22], salt[13], info[10], prk[32], okm[42];
    for (usz i = 0; i < 22; i++) ikm[i] = 0x0b;
    for (usz i = 0; i < 13; i++) salt[i] = (u8)i;
    for (usz i = 0; i < 10; i++) info[i] = (u8)(0xf0 + i);

    quic_hkdf_extract(salt, 13, ikm, 22, prk);
    CHECK(hex_eq(prk,
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", 32));

    CHECK(quic_hkdf_expand(prk, info, 10, okm, 42));
    CHECK(hex_eq(okm,
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865", 42));
}

/* Expand-Label wraps Expand with the tls13 label struct; check it produces
 * a stable, correctly-sized output (exercised end-to-end by the QUIC
 * Initial vectors later). */
static void test_hkdf_expand_label(void)
{
    u8 prk[32], a[16], b[16];
    for (usz i = 0; i < 32; i++) prk[i] = (u8)i;
    CHECK(quic_hkdf_expand_label(prk, "quic key", 8, 0, 0, a, 16));
    CHECK(quic_hkdf_expand_label(prk, "quic key", 8, 0, 0, b, 16));
    for (usz i = 0; i < 16; i++) CHECK(a[i] == b[i]); /* deterministic */
    /* a different label gives different output */
    CHECK(quic_hkdf_expand_label(prk, "quic iv", 7, 0, 0, b, 16));
    int differ = 0;
    for (usz i = 0; i < 16; i++) differ |= (a[i] != b[i]);
    CHECK(differ);
}

void test_hkdf(void)
{
    test_hkdf_rfc5869();
    test_hkdf_expand_label();
}
