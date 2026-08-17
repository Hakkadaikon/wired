#include "tls/handshake/core/tls/aead_params.h"

#include "tls/handshake/core/tls/cipher.h"

usz aead_key_len(u16 suite) {
  if (suite == QUIC_TLS_AES_128_GCM_SHA256) return 16;
  if (suite == QUIC_TLS_CHACHA20_POLY1305_SHA256) return 32;
  return 0;
}

usz aead_tag_len(u16 suite) { return cipher_supported(suite) ? 16 : 0; }

int aead_is_chacha(u16 suite) {
  return suite == QUIC_TLS_CHACHA20_POLY1305_SHA256;
}
