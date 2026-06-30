#include "tls/keys/keyupdate/aeadlimit.h"

int quic_aead_needs_update(u64 packets_encrypted, int is_chacha)
{
    /* RFC 9001 6.6 */
    u64 limit = is_chacha ? QUIC_AEAD_LIMIT_CHACHA : QUIC_AEAD_LIMIT_AESGCM;
    return packets_encrypted >= limit;
}
