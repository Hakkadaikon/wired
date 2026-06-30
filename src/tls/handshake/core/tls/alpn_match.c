#include "tls/handshake/core/tls/alpn_match.h"

/* RFC 7301 3.2: byte-for-byte comparison of protocol names. */
int quic_tls_alpn_equal(const u8 *a, usz alen, const u8 *b, usz blen)
{
    u8 diff = 0;
    if (alen != blen) return 0;
    for (usz i = 0; i < alen; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

int quic_tls_alpn_is_h3(const u8 *proto, usz len)
{
    static const u8 h3[2] = {0x68, 0x33};
    return quic_tls_alpn_equal(proto, len, h3, 2);
}
