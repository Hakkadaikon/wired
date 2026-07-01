#include "transport/conn/pnspace/crypto_stream/ecdhe.h"

#include "tls/handshake/core/tls/x25519.h"

/* RFC 9001 4.1 */
int quic_crypto_stream_ecdhe(
    const u8 my_priv[QUIC_ECDHE_LEN],
    const u8 peer_pub[QUIC_ECDHE_LEN],
    u8       shared[QUIC_ECDHE_LEN]) {
  return quic_x25519(shared, my_priv, peer_pub);
}
