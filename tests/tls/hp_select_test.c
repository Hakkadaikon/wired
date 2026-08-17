#include "test.h"

static void test_hp_select_is_chacha(void) {
  CHECK(hp_is_chacha(QUIC_TLS_CHACHA20_POLY1305_SHA256) == 1);
  CHECK(hp_is_chacha(QUIC_TLS_AES_128_GCM_SHA256) == 0);
}

static void test_hp_select_key_len(void) {
  CHECK(hp_key_len(QUIC_TLS_AES_128_GCM_SHA256) == 16);
  CHECK(hp_key_len(QUIC_TLS_CHACHA20_POLY1305_SHA256) == 32);
  CHECK(hp_key_len(QUIC_TLS_AES_256_GCM_SHA384) == 0);
}

void test_hp_select(void) {
  test_hp_select_is_chacha();
  test_hp_select_key_len();
}
