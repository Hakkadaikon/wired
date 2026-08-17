#ifndef TLSDRIVER_TLSDRIVER_H
#define TLSDRIVER_TLSDRIVER_H

#include "common/bytes/span/span.h"
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

#define TLSDRIVER_CRYPTO_MAX 64

/** The real-TLS handshake driver's state: CRYPTO reassembly, the handshake
 * order machine, key schedule and installed keys, our ECDHE key pair and the
 * derived shared secret, the negotiated group, SNI, and the ClientHello
 * transcript needed to derive the handshake secret. */
typedef struct {
  crypto_rx rx;   /* CRYPTO frame reassembly */
  hsdriver  hs;   /* handshake message order machine */
  keysched  ks;   /* order-driven key schedule */
  keyset    keys; /* installed per-level key sets */
  int       is_server;
  u8        my_priv[ECDHE_LEN];
  u8        my_pub[ECDHE_LEN];
  u8        shared[ECDHE_LEN];
  /* RFC 8446 4.2.7 NamedGroup negotiated for this handshake's key_share;
   * GROUP_X25519 unless tlsdriver_set_group selects otherwise. */
  u16       group;
  int       hs_ready; /* 1 once the handshake secret is derived */
  const u8* sni;      /* ClientHello server_name, view (caller-owned) */
  usz       sni_len;  /* 0 omits the SNI extension */
  /** RFC 8446 4.4.1: the handshake-secret transcript hash is over every
   * handshake message seen so far, not just the most recent one -- a client
   * derives its handshake keys from ClientHello||ServerHello, a server from
   * the same two messages in the same order. tlsdriver_client_hello
   * copies the exact bytes it emits here so recv_crypto's ServerHello can be
   * appended to them (the client side of derive_handshake); the server side
   * (is_server=1) has no prior message of its own to prepend, so this stays
   * empty and its ClientHello-only transcript is already correct. */
  u8  transcript_ch[512];
  usz transcript_ch_len;
  /** RFC 9000 7.5: the transport error code from the most recent
   * tlsdriver_recv_crypto failure (e.g. CRYPTO_BUFFER_EXCEEDED), 0 if
   * the last call succeeded or none has been made. */
  u64 last_error;
} tlsdriver;

/* Hold the x25519 key pair and initialize the order machine, key schedule,
 * key set and CRYPTO reassembly. is_server selects the role. */
void tlsdriver_init(
    tlsdriver* d,
    const u8   my_priv[ECDHE_LEN],
    const u8   my_pub[ECDHE_LEN],
    int        is_server);

/* RFC 6066 3: set the server_name carried in our ClientHello. sni is a view;
 * the caller keeps it alive until the ClientHello is built. Never calling
 * this (or sni_len 0) omits the extension. */
void tlsdriver_set_sni(tlsdriver* d, const u8* sni, usz sni_len);

/* RFC 8446 4.2.7: select the NamedGroup for this handshake's key_share
 * (GROUP_X25519 or GROUP_SECP256R1). tlsdriver_init defaults
 * to GROUP_X25519; call this right after init, before building or
 * receiving any handshake message, to use secp256r1 instead. my_priv/my_pub
 * passed to init must already hold the matching key pair (32-byte x25519
 * scalar/point, or 32-byte P-256 scalar + 65-byte SEC1 uncompressed point). */
void tlsdriver_set_group(tlsdriver* d, u16 group);

/* Build the raw ClientHello bytes (zero random, our key_share, the configured
 * SNI) into out (cap bytes). Returns the length, 0 if it does not fit. */
usz tlsdriver_raw_client_hello(tlsdriver* d, u8* out, usz cap);

/* Build a real ClientHello carrying our key_share and emit it as CRYPTO
 * frame(s) into out, writing the encoded length to out->len. Returns 1 on
 * success, 0 if it does not fit. */
int tlsdriver_client_hello(tlsdriver* d, wired_obuf* out);

/* Feed one CRYPTO frame: reassemble it, and once a whole TLS message is
 * contiguous, take the peer key_share, compute the ECDHE shared secret and
 * advance the key schedule to the handshake secret (installing Handshake
 * keys). Returns 1 if the handshake secret is now derived, 0 otherwise. */
int tlsdriver_recv_crypto(tlsdriver* d, const u8* crypto_frame, usz len);

/* Point *shared at the derived 32-byte ECDHE shared secret. Returns 1 if it
 * has been derived, 0 otherwise. */
int tlsdriver_shared_secret(const tlsdriver* d, const u8** shared);

/* 1 once the handshake secret has been derived. */
int tlsdriver_handshake_secret_ready(const tlsdriver* d);

/* RFC 9000 7.5: the transport error code from the most recent
 * tlsdriver_recv_crypto failure, 0 if none. */
u64 tlsdriver_last_error(const tlsdriver* d);

#endif
