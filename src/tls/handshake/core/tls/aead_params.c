#include "tls/handshake/core/tls/aead_params.h"

#include "tls/handshake/core/tls/cipher.h"

/* RFC 8446 B.4 / RFC 9001 5.3: AEAD key length per suite. */
static const struct {
  u16 suite;
  u8  key_len;
} aead_params_tab[] = {
    {TLS_AES_128_GCM_SHA256, 16},
    {TLS_AES_256_GCM_SHA384, 32},
    {TLS_CHACHA20_POLY1305_SHA256, 32},
};

usz aead_key_len(u16 suite) {
  for (usz i = 0; i < sizeof aead_params_tab / sizeof *aead_params_tab; i++)
    if (aead_params_tab[i].suite == suite) return aead_params_tab[i].key_len;
  return 0;
}

usz aead_tag_len(u16 suite) { return aead_key_len(suite) ? 16 : 0; }

int aead_is_chacha(u16 suite) { return suite == TLS_CHACHA20_POLY1305_SHA256; }
