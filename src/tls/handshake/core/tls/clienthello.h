#ifndef QUIC_TLS_CLIENTHELLO_H
#define QUIC_TLS_CLIENTHELLO_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 8446 4.1.2 / RFC 9001 8.2: a complete TLS 1.3 ClientHello carrying
 * supported_versions, supported_groups, signature_algorithms, key_share, the
 * optional server_name and ALPN, and quic_transport_parameters. */

/** The 32-byte random, the 32-byte x25519 public key pub, an optional SNI
 * host (sni.n 0 to omit), and the QUIC transport parameters tp. */
typedef struct {
  const u8*  random; /* 32 bytes */
  const u8*  pub;    /* 32 bytes */
  wired_span sni;
  wired_span tp;
} clienthello_in;

/* Build the ClientHello into out from in. Returns the handshake message
 * length, or 0 if it does not fit. ALPN offers "h3". */
usz tls_client_hello(const clienthello_in* in, wired_obuf* out);

/** Same as clienthello_in, but the key_share's NamedGroup (RFC 8446
 * 4.2.7) and pub's length are explicit instead of the frozen x25519/32-byte
 * pair -- pub must point at pub_len bytes (32 for QUIC_GROUP_X25519, 65 for
 * QUIC_GROUP_SECP256R1). */
typedef struct {
  const u8*  random; /* 32 bytes */
  const u8*  pub;    /* pub_len bytes */
  wired_span sni;
  wired_span tp;
  u16        group;
  usz        pub_len;
} clienthello_group_in;

/* Build the ClientHello into out from in, offering in->group's key_share.
 * Returns the handshake message length, or 0 if it does not fit. ALPN
 * offers "h3". */
usz tls_client_hello_group(const clienthello_group_in* in, wired_obuf* out);

#endif
