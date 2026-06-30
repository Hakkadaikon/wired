#include "app/http3/server/srvloop/keys.h"

#include "crypto/kdf/keys/keyset.h"
#include "tls/keys/schedule_drive/keyschedule.h"

/* RFC 9001 5.1: own-direction `which` for sealing, indexed by level-1 (only the
 * protected levels Handshake=1, 1-RTT=2 have a direction; Initial is shared).
 */
static int seal_which(int level) {
  static const int own[] = {QUIC_KS_SERVER_HS, QUIC_KS_SERVER_AP};
  return own[level - QUIC_LEVEL_HANDSHAKE];
}

/* RFC 9001 5.1: peer-direction `which` for opening. */
static int open_which(int level) {
  static const int peer[] = {QUIC_KS_CLIENT_HS, QUIC_KS_CLIENT_AP};
  return peer[level - QUIC_LEVEL_HANDSHAKE];
}

/* Fetch the directional keys for `which` and build their HP cipher. */
static int fetch(
    const quic_server        *s,
    int                       which,
    const quic_initial_keys **keys,
    quic_aes128              *hp) {
  if (!quic_keysched_get(&s->sched, which, keys)) return 0;
  quic_aes128_init(hp, (*keys)->hp);
  return 1;
}

int quic_srvloop_seal_keys(
    const quic_server        *s,
    int                       level,
    const quic_initial_keys **keys,
    quic_aes128              *hp) {
  return fetch(s, seal_which(level), keys, hp);
}

int quic_srvloop_open_keys(
    const quic_server        *s,
    int                       level,
    const quic_initial_keys **keys,
    quic_aes128              *hp) {
  return fetch(s, open_which(level), keys, hp);
}
