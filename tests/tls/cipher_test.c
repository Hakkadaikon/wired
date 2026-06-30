#include "test.h"

static void test_cipher_supported(void)
{
    CHECK(quic_cipher_supported(QUIC_TLS_AES_128_GCM_SHA256) == 1);
    CHECK(quic_cipher_supported(QUIC_TLS_CHACHA20_POLY1305_SHA256) == 1);
    CHECK(quic_cipher_supported(QUIC_TLS_AES_256_GCM_SHA384) == 0);
    CHECK(quic_cipher_supported(0x0000) == 0);
}

static void test_cipher_select_prefers_aes128(void)
{
    /* CHACHA offered first, AES_128 second: AES_128 still wins. */
    const u8 offered[] = {0x13, 0x03, 0x13, 0x01};
    u16 chosen = 0;
    CHECK(quic_cipher_select(offered, 2, &chosen) == 1);
    CHECK(chosen == QUIC_TLS_AES_128_GCM_SHA256);
}

static void test_cipher_select_falls_back(void)
{
    /* Unsupported 256-GCM then CHACHA: CHACHA chosen. */
    const u8 offered[] = {0x13, 0x02, 0x13, 0x03};
    u16 chosen = 0;
    CHECK(quic_cipher_select(offered, 2, &chosen) == 1);
    CHECK(chosen == QUIC_TLS_CHACHA20_POLY1305_SHA256);
}

static void test_cipher_select_none(void)
{
    const u8 offered[] = {0x13, 0x02, 0x00, 0x00};
    u16 chosen = 0xffff;
    CHECK(quic_cipher_select(offered, 2, &chosen) == 0);
    CHECK(chosen == 0xffff);
}

void test_cipher(void)
{
    test_cipher_supported();
    test_cipher_select_prefers_aes128();
    test_cipher_select_falls_back();
    test_cipher_select_none();
}
