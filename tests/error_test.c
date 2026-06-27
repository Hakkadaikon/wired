#include "test.h"

static void test_error_crypto(void)
{
    /* alert 0x2a (decode_error) -> CRYPTO_ERROR 0x012a -> alert back */
    u64 code = quic_err_crypto(0x2a);
    CHECK(code == 0x012a);
    CHECK(quic_err_is_crypto(code) == 1);
    CHECK(quic_err_alert(code) == 0x2a);
    /* boundaries of the CRYPTO_ERROR range */
    CHECK(quic_err_is_crypto(0x0100) == 1);
    CHECK(quic_err_is_crypto(0x01ff) == 1);
    CHECK(quic_err_is_crypto(0x00ff) == 0);
    CHECK(quic_err_is_crypto(0x0200) == 0);
}

static void test_error_transport(void)
{
    /* a transport code is not in the CRYPTO range */
    CHECK(quic_err_is_crypto(QUIC_ERR_PROTOCOL_VIOLATION) == 0);
    CHECK(QUIC_ERR_NO_ERROR == 0x00 && QUIC_ERR_NO_VIABLE_PATH == 0x10);
}

void test_error(void)
{
    test_error_crypto();
    test_error_transport();
}
