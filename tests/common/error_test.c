#include "test.h"

static void test_error_crypto(void) {
  /* alert 0x2a (decode_error) -> CRYPTO_ERROR 0x012a -> alert back */
  u64 code = err_crypto(0x2a);
  CHECK(code == 0x012a);
  CHECK(err_is_crypto(code) == 1);
  CHECK(err_alert(code) == 0x2a);
  /* boundaries of the CRYPTO_ERROR range */
  CHECK(err_is_crypto(0x0100) == 1);
  CHECK(err_is_crypto(0x01ff) == 1);
  CHECK(err_is_crypto(0x00ff) == 0);
  CHECK(err_is_crypto(0x0200) == 0);
}

static void test_error_transport(void) {
  /* a transport code is not in the CRYPTO range */
  CHECK(err_is_crypto(ERR_PROTOCOL_VIOLATION) == 0);
  CHECK(ERR_NO_ERROR == 0x00 && ERR_NO_VIABLE_PATH == 0x10);
}

void test_error(void) {
  test_error_crypto();
  test_error_transport();
}
