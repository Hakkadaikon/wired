#include "tls/handshake/core/tls/cipher.h"

int quic_cipher_supported(u16 suite)
{
    return suite == QUIC_TLS_AES_128_GCM_SHA256 ||
           suite == QUIC_TLS_CHACHA20_POLY1305_SHA256;
}

/* Fold one offered suite into the running choice. Records the first supported
 * suite, then upgrades to the top-priority one (AES_128_GCM_SHA256). */
/* Whether s should replace the current pick: the first supported one, or the
 * top-priority AES_128_GCM_SHA256 (RFC 8446 B.4). */
static int prefer(u16 s, int found)
{
    return !found || s == QUIC_TLS_AES_128_GCM_SHA256;
}

static void fold(u16 s, u16 *chosen, int *found)
{
    if (!quic_cipher_supported(s)) return;
    if (prefer(s, *found)) *chosen = s;
    *found = 1;
}

int quic_cipher_select(const u8 *offered, usz n_pairs, u16 *chosen)
{
    int found = 0;
    for (usz i = 0; i < n_pairs; i++)
        fold((u16)((offered[2 * i] << 8) | offered[2 * i + 1]), chosen, &found);
    return found;
}
