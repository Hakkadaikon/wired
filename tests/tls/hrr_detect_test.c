#include "test.h"
#include "tls/handshake/core/hrr/hrr_detect.h"
#include "tls/handshake/core/hrr/hrr_build.h"
#include "tls/handshake/roles/shbuild/shbuild.h"
#include "tls/handshake/core/tls/handshake.h"

/* RFC 8446 4.1.4: a built HRR is recognised by its random sentinel. */
static void test_hrr_detect_true(void)
{
    u8 out[256];
    usz len = 0;
    CHECK(quic_hrr_build(QUIC_GROUP_X25519, 0, 0, out, sizeof out, &len) == 1);
    CHECK(quic_hrr_is_hello_retry(out, len) == 1);
}

/* An ordinary ServerHello (non-sentinel random) is not an HRR. */
static void test_hrr_detect_false(void)
{
    u8 random[32], pub[32], out[256];
    usz len = 0;
    for (int i = 0; i < 32; i++) { random[i] = (u8)i; pub[i] = (u8)(0x40 + i); }
    CHECK(quic_shbuild_server_hello(random, (void *)0, 0, 0x1301, pub,
                                    out, sizeof out, &len) == 1);
    CHECK(quic_hrr_is_hello_retry(out, len) == 0);
}

/* A message too short to hold the random returns 0, not a read overrun. */
static void test_hrr_detect_truncated(void)
{
    u8 buf[10] = {0x02};
    CHECK(quic_hrr_is_hello_retry(buf, 10) == 0);
    CHECK(quic_hrr_is_hello_retry(buf, 0) == 0);
}

void test_hrr_detect(void)
{
    test_hrr_detect_true();
    test_hrr_detect_false();
    test_hrr_detect_truncated();
}
