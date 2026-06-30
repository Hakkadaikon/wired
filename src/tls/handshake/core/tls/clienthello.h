#ifndef QUIC_TLS_CLIENTHELLO_H
#define QUIC_TLS_CLIENTHELLO_H

#include "common/platform/sys/syscall.h"

/* RFC 8446 4.1.2 / RFC 9001 8.2: a complete TLS 1.3 ClientHello carrying
 * supported_versions, supported_groups, signature_algorithms, key_share, the
 * optional server_name and ALPN, and quic_transport_parameters. */

/* Build the ClientHello into buf (cap total) from the 32-byte random, the
 * 32-byte x25519 public key pub, an optional SNI host (sni_len 0 to omit), and
 * the QUIC transport parameters tp (tp_len bytes). Returns the handshake
 * message length, or 0 if it does not fit. ALPN offers "h3". */
usz quic_tls_client_hello(u8 *buf, usz cap, const u8 random[32],
                          const u8 pub[32], const u8 *sni, usz sni_len,
                          const u8 *tp, usz tp_len);

#endif
