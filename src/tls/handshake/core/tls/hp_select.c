#include "tls/handshake/core/tls/hp_select.h"

#include "tls/handshake/core/tls/cipher.h"

int hp_is_chacha(u16 suite) { return suite == TLS_CHACHA20_POLY1305_SHA256; }

usz hp_key_len(u16 suite) {
  if (suite == TLS_AES_128_GCM_SHA256) return 16;
  if (suite == TLS_CHACHA20_POLY1305_SHA256) return 32;
  return 0;
}
