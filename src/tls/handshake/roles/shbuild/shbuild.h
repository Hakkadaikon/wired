#ifndef QUIC_SHBUILD_H
#define QUIC_SHBUILD_H

#include "common/platform/sys/syscall.h"

/* RFC 8446 4.1.3: build a complete TLS 1.3 ServerHello handshake message
 * (msg_type 0x02 | length(3) | body) carrying supported_versions (the
 * selected_version 0x0304) and an x25519 key_share, so a TLS 1.3 client
 * accepts it. */

/* Build the ServerHello into out (cap total). random is the 32-byte
 * ServerHello.random; session_id (sid_len bytes, 0..32) is echoed back as
 * legacy_session_id_echo; cipher_suite is the negotiated suite; server_pub is
 * the 32-byte x25519 public key. On success writes the total message length to
 * *out_len and returns 1; returns 0 if it does not fit. */
int quic_shbuild_server_hello(const u8 random[32], const u8 *session_id,
                              u8 sid_len, u16 cipher_suite,
                              const u8 server_pub[32], u8 *out, usz cap,
                              usz *out_len);

#endif
