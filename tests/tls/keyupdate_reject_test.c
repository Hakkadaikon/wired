#include "test.h"

/* RFC 9001 6: QUIC never carries a TLS KeyUpdate message; receiving one is
 * rejected with 0x010a (unexpected_message). */
static void test_keyupdate_reject_detects_type(void) {
  CHECK(tls_keyupdate_is_forbidden(HS_KEY_UPDATE));
  CHECK(tls_keyupdate_is_forbidden(24));
}

/* Every other handshake message type used by this SDK is unaffected. */
static void test_keyupdate_reject_allows_others(void) {
  CHECK(!tls_keyupdate_is_forbidden(HS_CLIENT_HELLO));
  CHECK(!tls_keyupdate_is_forbidden(HS_SERVER_HELLO));
  CHECK(!tls_keyupdate_is_forbidden(HS_ENCRYPTED_EXT));
  CHECK(!tls_keyupdate_is_forbidden(HS_FINISHED));
}

/* The close code is CRYPTO_ERROR | unexpected_message == 0x0100 | 0x0a. */
static void test_keyupdate_reject_code(void) {
  CHECK(tls_keyupdate_reject_code() == 0x010a);
}

void test_keyupdate_reject(void) {
  test_keyupdate_reject_detects_type();
  test_keyupdate_reject_allows_others();
  test_keyupdate_reject_code();
}
