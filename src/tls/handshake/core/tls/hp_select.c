#include "tls/handshake/core/tls/hp_select.h"

#include "tls/handshake/core/tls/aead_params.h"
#include "tls/handshake/core/tls/cipher.h"

int hp_is_chacha(u16 suite) { return suite == TLS_CHACHA20_POLY1305_SHA256; }

/* RFC 9001 5.4.3/5.4.4: the HP key is as long as the AEAD key. */
usz hp_key_len(u16 suite) { return aead_key_len(suite); }
