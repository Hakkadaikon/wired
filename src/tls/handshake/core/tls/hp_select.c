#include "tls/handshake/core/tls/hp_select.h"
#include "tls/handshake/core/tls/cipher.h"

int quic_hp_is_chacha(u16 suite)
{
    return suite == QUIC_TLS_CHACHA20_POLY1305_SHA256;
}

usz quic_hp_key_len(u16 suite)
{
    if (suite == QUIC_TLS_AES_128_GCM_SHA256) return 16;
    if (suite == QUIC_TLS_CHACHA20_POLY1305_SHA256) return 32;
    return 0;
}
