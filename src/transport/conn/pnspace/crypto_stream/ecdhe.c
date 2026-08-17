#include "transport/conn/pnspace/crypto_stream/ecdhe.h"

#include "crypto/asymmetric/ecc/p256/p256_ecdhe.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/x25519.h"

/* RFC 9001 4.1 */
int crypto_stream_ecdhe(
    const u8 my_priv[ECDHE_LEN],
    const u8 peer_pub[ECDHE_LEN],
    u8       shared[ECDHE_LEN]) {
  return wired_x25519(shared, my_priv, peer_pub);
}

/* RFC 8446 7.4.2 / SEC1 3.3.1: P-256 ECDH, peer_pub SEC1-decoded first. */
static int ecdh_p256(
    const u8 my_priv[ECDHE_LEN],
    const u8 peer_pub[ECDHE_LEN],
    u8       shared[ECDHE_LEN]) {
  return p256_ecdh(shared, my_priv, peer_pub);
}

int crypto_stream_ecdhe_group(
    u16      group,
    const u8 my_priv[ECDHE_LEN],
    const u8 peer_pub[ECDHE_LEN],
    u8       shared[ECDHE_LEN]) {
  if (group == GROUP_X25519)
    return crypto_stream_ecdhe(my_priv, peer_pub, shared);
  if (group == GROUP_SECP256R1) return ecdh_p256(my_priv, peer_pub, shared);
  return 0;
}
