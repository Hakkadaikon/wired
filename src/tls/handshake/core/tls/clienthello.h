#ifndef QUIC_TLS_CLIENTHELLO_H
#define QUIC_TLS_CLIENTHELLO_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 8446 4.1.2 / RFC 9001 8.2: a complete TLS 1.3 ClientHello carrying
 * supported_versions, supported_groups, signature_algorithms, key_share, the
 * optional server_name and ALPN, and quic_transport_parameters. */

/* The 32-byte random, the 32-byte x25519 public key pub, an optional SNI
 * host (sni.n 0 to omit), and the QUIC transport parameters tp. */
typedef struct {
  const u8 *random; /* 32 bytes */
  const u8 *pub;    /* 32 bytes */
  quic_span sni;
  quic_span tp;
} quic_clienthello_in;

/* Build the ClientHello into out from in. Returns the handshake message
 * length, or 0 if it does not fit. ALPN offers "h3". */
usz quic_tls_client_hello(const quic_clienthello_in *in, quic_obuf *out);

#endif
