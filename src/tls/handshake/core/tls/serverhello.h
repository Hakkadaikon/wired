#ifndef QUIC_TLS_SERVERHELLO_H
#define QUIC_TLS_SERVERHELLO_H

#include "common/platform/sys/syscall.h"

/* RFC 8446 4.1.3: parse a ServerHello handshake message. */

/* Parse the ServerHello at buf (n bytes, including the 4-byte handshake header)
 * and extract the server's 32-byte x25519 key_share public key into server_pub,
 * the negotiated cipher_suite into *cipher, and the selected TLS version (from
 * supported_versions) into *version. Returns 1 on success, 0 if truncated, the
 * message is not a ServerHello, or the key_share is absent/not x25519. */
int quic_tls_parse_server_hello(const u8 *buf, usz n, u8 server_pub[32],
                                u16 *cipher, u16 *version);

#endif
