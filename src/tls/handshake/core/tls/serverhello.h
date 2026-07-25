#ifndef QUIC_TLS_SERVERHELLO_H
#define QUIC_TLS_SERVERHELLO_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 8446 4.1.3: parse a ServerHello handshake message. */

/* Output of quic_tls_parse_server_hello: the negotiated cipher_suite and the
 * selected TLS version (from supported_versions). */
typedef struct {
  u16 cipher;
  u16 version;
} quic_serverhello_out;

/* Parse the ServerHello at buf (including the 4-byte handshake header) and
 * extract the server's 32-byte x25519 key_share public key into server_pub,
 * the negotiated cipher_suite and selected version into *out. Returns 1 on
 * success, 0 if truncated, the message is not a ServerHello, or the
 * key_share is absent/not x25519. */
int quic_tls_parse_server_hello(
    quic_span buf, u8 server_pub[32], quic_serverhello_out* out);

/* Same parse, but accepts either NamedGroup (RFC 8446 4.2.7): x25519 (32-byte
 * key) or secp256r1 (65-byte SEC1 uncompressed key, RFC 8446 4.2.8.2).
 * *group receives which one was found. server_pub must have room for 65
 * bytes -- the caller does not know the group in advance. Returns 1 on
 * success, 0 under the same conditions as quic_tls_parse_server_hello, or if
 * the key_share's group is recognised but neither of the two above. */
int quic_tls_parse_server_hello_group(
    quic_span buf, u8 server_pub[65], u16* group, quic_serverhello_out* out);

#endif
