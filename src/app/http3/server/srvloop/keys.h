#ifndef QUIC_SRVLOOP_KEYS_H
#define QUIC_SRVLOOP_KEYS_H

#include "crypto/symmetric/aead/aes/aes.h"
#include "tls/handshake/roles/server/server.h"

/* RFC 9001 5.1 directionality. The server seals with its own-direction key and
 * opens with the peer-direction key, at the protected levels (Handshake,
 * 1-RTT). Both helpers fetch the directional keys from the server's schedule
 * and derive the matching header-protection cipher. Returns 1 if the required
 * key is derived, 0 otherwise (no key -> no seal/open).
 *
 *   level             seal (own)    open (peer)
 *   QUIC_LEVEL_HANDSHAKE  SERVER_HS     CLIENT_HS
 *   QUIC_LEVEL_ONERTT     SERVER_AP     CLIENT_AP
 */

/* The directional key material a seal/open needs: the AEAD keys and the
 * header-protection cipher derived from them. */
typedef struct {
  const quic_initial_keys *keys;
  quic_aes128               hp;
} quic_srvloop_dirkeys;

int quic_srvloop_seal_keys(
    const quic_server *s, int level, quic_srvloop_dirkeys *out);

int quic_srvloop_open_keys(
    const quic_server *s, int level, quic_srvloop_dirkeys *out);

#endif
