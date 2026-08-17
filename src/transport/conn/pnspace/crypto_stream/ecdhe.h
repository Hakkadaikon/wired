#ifndef QUIC_CRYPTO_STREAM_ECDHE_H
#define QUIC_CRYPTO_STREAM_ECDHE_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 4.1 / RFC 8446 7.4.2: the ECDHE shared secret for the TLS 1.3
 * handshake is computed over the negotiated group's key_share. Feed shared[]
 * to the key schedule's handshake-secret derivation. */

/* Largest key material any supported group needs: SEC1 uncompressed P-256
 * (RFC 8446 4.2.8.2 / SEC1 2.3.3) is the widest at 65 bytes; x25519 (RFC
 * 7748) uses only the first 32. */
#define QUIC_ECDHE_LEN 65

/* shared = X25519(my_priv, peer_pub), all 32-byte little-endian.
 * RFC 7748 6.1: returns 0 if the shared secret is all-zero (low-order peer
 * key); the caller MUST abort the handshake on 0. */
int crypto_stream_ecdhe(
    const u8 my_priv[QUIC_ECDHE_LEN],
    const u8 peer_pub[QUIC_ECDHE_LEN],
    u8       shared[QUIC_ECDHE_LEN]);

/* Same shared-secret computation, dispatched by the negotiated TLS group
 * (RFC 8446 4.2.7 NamedGroup): QUIC_GROUP_X25519 runs RFC 7748 X25519 on the
 * first 32 bytes of my_priv/peer_pub, writing a 32-byte shared secret.
 * QUIC_GROUP_SECP256R1 decodes peer_pub as a 65-byte SEC1 uncompressed P-256
 * point and runs RFC 8446 7.4.2 / SEC1 3.3.1 ECDH, writing a 32-byte shared
 * secret (the X coordinate). Returns 0 for an unrecognised group, a
 * low-order x25519 result, or an invalid P-256 peer point. */
int crypto_stream_ecdhe_group(
    u16      group,
    const u8 my_priv[QUIC_ECDHE_LEN],
    const u8 peer_pub[QUIC_ECDHE_LEN],
    u8       shared[QUIC_ECDHE_LEN]);

#endif
