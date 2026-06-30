#include "test.h"

void test_aead_suite(void)
{
    u8 key[32], iv[12], aad[7], pt[20], ct[40], out[20];
    for (usz i = 0; i < 32; i++) key[i] = (u8)(0x40 + i);
    for (usz i = 0; i < 12; i++) iv[i] = (u8)(0x10 + i);
    for (usz i = 0; i < 7; i++) aad[i] = (u8)(0xa0 + i);
    for (usz i = 0; i < 20; i++) pt[i] = (u8)i;

    /* RFC 9001 5.3 AES suite: matches the fixed GCM pipeline directly. */
    usz n = quic_aead_suite_seal(QUIC_TLS_AES_128_GCM_SHA256, key, iv, 2,
                                 aad, 7, pt, 20, ct);
    CHECK(n == 20 + 16);
    quic_aes128 a;
    quic_aes128_init(&a, key);
    u8 nonce[12], want[20], wtag[16];
    for (usz i = 0; i < 12; i++) nonce[i] = iv[i];
    nonce[11] ^= 2;
    quic_gcm_seal(&a, nonce, aad, 7, pt, 20, want, wtag);
    for (usz i = 0; i < 20; i++) CHECK(ct[i] == want[i]);
    for (usz i = 0; i < 16; i++) CHECK(ct[20 + i] == wtag[i]);

    /* AES seal -> open round-trips. */
    CHECK(quic_aead_suite_open(QUIC_TLS_AES_128_GCM_SHA256, key, iv, 2,
                               aad, 7, ct, 20, out) == 20);
    for (usz i = 0; i < 20; i++) CHECK(out[i] == pt[i]);

    /* RFC 9001 5.3 ChaCha suite: seal -> open round-trips. */
    n = quic_aead_suite_seal(QUIC_TLS_CHACHA20_POLY1305_SHA256, key, iv, 5,
                             aad, 7, pt, 20, ct);
    CHECK(n == 20 + 16);
    CHECK(quic_aead_suite_open(QUIC_TLS_CHACHA20_POLY1305_SHA256, key, iv, 5,
                               aad, 7, ct, 20, out) == 20);
    for (usz i = 0; i < 20; i++) CHECK(out[i] == pt[i]);

    /* Tampered tag fails authentication. */
    ct[20] ^= 0xff;
    CHECK(quic_aead_suite_open(QUIC_TLS_CHACHA20_POLY1305_SHA256, key, iv, 5,
                               aad, 7, ct, 20, out) == 0);

    /* Unknown suite seals/opens nothing. */
    CHECK(quic_aead_suite_seal(0x0000, key, iv, 2, aad, 7, pt, 20, ct) == 0);
    CHECK(quic_aead_suite_open(0x0000, key, iv, 2, aad, 7, ct, 20, out) == 0);
}
