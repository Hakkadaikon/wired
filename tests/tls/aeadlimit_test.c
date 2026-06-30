#include "test.h"

/* RFC 9001 6.6: limits are 2^23 (AES-GCM) and 2^62 (ChaCha20). */
void test_aeadlimit(void)
{
    u64 g = QUIC_AEAD_LIMIT_AESGCM;
    CHECK(!quic_aead_needs_update(g - 1, 0)); /* one below: still ok */
    CHECK(quic_aead_needs_update(g, 0));      /* at limit: must update */
    CHECK(quic_aead_needs_update(g + 1, 0));

    u64 c = QUIC_AEAD_LIMIT_CHACHA;
    CHECK(!quic_aead_needs_update(c - 1, 1));
    CHECK(quic_aead_needs_update(c, 1));

    /* the AES-GCM limit is well below the ChaCha20 one */
    CHECK(!quic_aead_needs_update(g, 1));
}
