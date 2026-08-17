#ifndef QUIC_SHBUILD_H
#define QUIC_SHBUILD_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 8446 4.1.3: build a complete TLS 1.3 ServerHello handshake message
 * (msg_type 0x02 | length(3) | body) carrying supported_versions (the
 * selected_version 0x0304) and an x25519 key_share, so a TLS 1.3 client
 * accepts it. */

/* random is the 32-byte ServerHello.random; session_id (0..32 bytes) is
 * echoed back as legacy_session_id_echo; cipher_suite is the negotiated
 * suite; server_pub is the 32-byte x25519 public key. psk_accepted (RFC 8446
 * 4.1.3/4.2.11) adds the pre_shared_key extension carrying selected_identity
 * -- this SDK only ever offers/accepts a single PSK identity, so the index
 * is always 0. */
/** Inputs to shbuild_server_hello: the fixed x25519 ServerHello fields
 * (random, echoed session_id, negotiated cipher_suite, x25519 server_pub) and
 * whether a PSK identity was accepted. */
typedef struct {
  const u8*  random;
  wired_span session_id;
  u16        cipher_suite;
  const u8*  server_pub;
  int        psk_accepted;
} shbuild_in;

/* Build the ServerHello into out. On success writes the total message length
 * to out->len and returns 1; returns 0 if it does not fit. */
int shbuild_server_hello(const shbuild_in* in, wired_obuf* out);

/** Same as shbuild_in, but the key_share's NamedGroup (RFC 8446 4.2.7)
 * and server_pub's length are explicit instead of the frozen x25519/32-byte
 * pair -- server_pub must point at pub_len bytes (32 for QUIC_GROUP_X25519,
 * 65 for QUIC_GROUP_SECP256R1). */
typedef struct {
  const u8*  random;
  wired_span session_id;
  u16        cipher_suite;
  const u8*  server_pub;
  int        psk_accepted;
  u16        group;
  usz        pub_len;
} shbuild_group_in;

/* Build the ServerHello into out, replying with in->group's key_share. On
 * success writes the total message length to out->len and returns 1;
 * returns 0 if it does not fit. */
int shbuild_server_hello_group(const shbuild_group_in* in, wired_obuf* out);

#endif
