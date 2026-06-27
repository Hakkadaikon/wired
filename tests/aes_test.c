#include "test.h"

/* hb parses a 32-char hex string into 16 bytes. */
static void hb(const char *hex, u8 out[16])
{
    for (usz i = 0; i < 16; i++) {
        u8 hi = hex[i * 2], lo = hex[i * 2 + 1];
        out[i] = (u8)(((hi <= '9' ? hi - '0' : hi - 'a' + 10) << 4) |
                      (lo <= '9' ? lo - '0' : lo - 'a' + 10));
    }
}

/* FIPS 197 Appendix B / C.1 known-answer test. */
static void test_aes_fips197(void)
{
    u8 key[16], in[16], out[16], want[16];
    quic_aes128 a;
    hb("2b7e151628aed2a6abf7158809cf4f3c", key);
    hb("3243f6a8885a308d313198a2e0370734", in);
    hb("3925841d02dc09fbdc118597196a0b32", want);
    quic_aes128_init(&a, key);
    quic_aes128_encrypt(&a, in, out);
    for (usz i = 0; i < 16; i++) CHECK(out[i] == want[i]);
}

/* FIPS 197 Appendix C.1: all-from-the-spec vector. */
static void test_aes_appendix_c(void)
{
    u8 key[16], in[16], out[16], want[16];
    quic_aes128 a;
    hb("000102030405060708090a0b0c0d0e0f", key);
    hb("00112233445566778899aabbccddeeff", in);
    hb("69c4e0d86a7b0430d8cdb78070b4c55a", want);
    quic_aes128_init(&a, key);
    quic_aes128_encrypt(&a, in, out);
    for (usz i = 0; i < 16; i++) CHECK(out[i] == want[i]);
}

void test_aes(void)
{
    test_aes_fips197();
    test_aes_appendix_c();
}
