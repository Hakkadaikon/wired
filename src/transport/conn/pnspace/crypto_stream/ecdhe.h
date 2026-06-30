#ifndef QUIC_CRYPTO_STREAM_ECDHE_H
#define QUIC_CRYPTO_STREAM_ECDHE_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 4.1 / RFC 8446 7.4.2: the ECDHE shared secret for the TLS 1.3
 * handshake is X25519(own private key, peer public key). Feed shared[] to the
 * key schedule's handshake-secret derivation. */

#define QUIC_ECDHE_LEN 32

/* shared = X25519(my_priv, peer_pub), all 32-byte little-endian. */
void quic_crypto_stream_ecdhe(const u8 my_priv[QUIC_ECDHE_LEN],
                              const u8 peer_pub[QUIC_ECDHE_LEN],
                              u8 shared[QUIC_ECDHE_LEN]);

#endif
