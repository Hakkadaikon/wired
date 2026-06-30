#ifndef QUIC_TLSDRIVER_TLSDRIVER_H
#define QUIC_TLSDRIVER_TLSDRIVER_H

#include "common/platform/sys/syscall.h"
#include "crypto/kdf/keys/keyset.h"
#include "tls/handshake/core/tls/hsdriver.h"
#include "tls/keys/schedule_drive/keyschedule.h"
#include "transport/conn/pnspace/crypto_stream/crypto_rx.h"
#include "transport/conn/pnspace/crypto_stream/ecdhe.h"

/* RFC 9001 4 / RFC 8446 4: real-TLS handshake driver. Unlike the type-byte
 * driver, this carries actual ClientHello/ServerHello bytes in CRYPTO frames
 * and agrees on the ECDHE shared secret from the real x25519 key_shares.
 *
 * client_hello emits a real ClientHello (own key_share) as CRYPTO frame(s);
 * recv_crypto reassembles a peer's CRYPTO frames into the TLS message, takes
 * the peer key_share (ServerHello parse on the client, ClientHello key_share
 * on the server), computes X25519(own_priv, peer_pub), and feeds it to the
 * key schedule's handshake-secret derivation, installing Handshake keys.
 *
 * Orchestration only: every parse/derivation is delegated to the verified
 * components. */

#define QUIC_TLSDRIVER_CRYPTO_MAX 64

typedef struct {
  quic_crypto_rx rx;   /* CRYPTO frame reassembly */
  quic_hsdriver  hs;   /* handshake message order machine */
  quic_keysched  ks;   /* order-driven key schedule */
  quic_keyset    keys; /* installed per-level key sets */
  int            is_server;
  u8             my_priv[QUIC_ECDHE_LEN];
  u8             my_pub[QUIC_ECDHE_LEN];
  u8             shared[QUIC_ECDHE_LEN];
  int            hs_ready; /* 1 once the handshake secret is derived */
} quic_tlsdriver;

/* Hold the x25519 key pair and initialize the order machine, key schedule,
 * key set and CRYPTO reassembly. is_server selects the role. */
void quic_tlsdriver_init(
    quic_tlsdriver *d,
    const u8        my_priv[QUIC_ECDHE_LEN],
    const u8        my_pub[QUIC_ECDHE_LEN],
    int             is_server);

/* Build a real ClientHello carrying our key_share and emit it as CRYPTO
 * frame(s) into out (cap bytes), writing the encoded length to *out_len.
 * Returns 1 on success, 0 if it does not fit. */
int quic_tlsdriver_client_hello(
    quic_tlsdriver *d, u8 *out, usz cap, usz *out_len);

/* Feed one CRYPTO frame: reassemble it, and once a whole TLS message is
 * contiguous, take the peer key_share, compute the ECDHE shared secret and
 * advance the key schedule to the handshake secret (installing Handshake
 * keys). Returns 1 if the handshake secret is now derived, 0 otherwise. */
int quic_tlsdriver_recv_crypto(
    quic_tlsdriver *d, const u8 *crypto_frame, usz len);

/* Point *shared at the derived 32-byte ECDHE shared secret. Returns 1 if it
 * has been derived, 0 otherwise. */
int quic_tlsdriver_shared_secret(const quic_tlsdriver *d, const u8 **shared);

/* 1 once the handshake secret has been derived. */
int quic_tlsdriver_handshake_secret_ready(const quic_tlsdriver *d);

#endif
