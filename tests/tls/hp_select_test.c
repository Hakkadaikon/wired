#include "test.h"

static void test_hp_select_key_len(void) {
  CHECK(hp_key_len(TLS_AES_128_GCM_SHA256) == 16);
  CHECK(hp_key_len(TLS_CHACHA20_POLY1305_SHA256) == 32);
  CHECK(hp_key_len(TLS_AES_256_GCM_SHA384) == 32);
  CHECK(hp_key_len(0x0000) == 0);
}

void test_hp_select(void) { test_hp_select_key_len(); }
