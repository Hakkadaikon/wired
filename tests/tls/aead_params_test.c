#include "test.h"

static void test_aead_params_key_len(void) {
  CHECK(aead_key_len(QUIC_TLS_AES_128_GCM_SHA256) == 16);
  CHECK(aead_key_len(QUIC_TLS_CHACHA20_POLY1305_SHA256) == 32);
  CHECK(aead_key_len(QUIC_TLS_AES_256_GCM_SHA384) == 0);
}

static void test_aead_params_tag_len(void) {
  CHECK(aead_tag_len(QUIC_TLS_AES_128_GCM_SHA256) == 16);
  CHECK(aead_tag_len(QUIC_TLS_CHACHA20_POLY1305_SHA256) == 16);
  CHECK(aead_tag_len(QUIC_TLS_AES_256_GCM_SHA384) == 0);
}

static void test_aead_params_is_chacha(void) {
  CHECK(aead_is_chacha(QUIC_TLS_CHACHA20_POLY1305_SHA256) == 1);
  CHECK(aead_is_chacha(QUIC_TLS_AES_128_GCM_SHA256) == 0);
}

void test_aead_params(void) {
  test_aead_params_key_len();
  test_aead_params_tag_len();
  test_aead_params_is_chacha();
}
