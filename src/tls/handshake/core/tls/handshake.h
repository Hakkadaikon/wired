#ifndef QUIC_TLS_HANDSHAKE_H
#define QUIC_TLS_HANDSHAKE_H

#include "common/platform/sys/syscall.h"

/* RFC 8446 TLS 1.3 handshake messages carried in QUIC CRYPTO frames.
 * Each message is: msg_type(1) length(3, big-endian) body. We build the
 * minimal ClientHello/ServerHello needed to drive a QUIC handshake with an
 * X25519 key_share, plus EncryptedExtensions and Finished. */

#define QUIC_HS_CLIENT_HELLO 1
#define QUIC_HS_SERVER_HELLO 2
#define QUIC_HS_ENCRYPTED_EXT 8
#define QUIC_HS_FINISHED     20

#define QUIC_TLS_AES128_GCM_SHA256 0x1301
#define QUIC_EXT_SUPPORTED_VERSIONS 43
#define QUIC_EXT_KEY_SHARE          51
#define QUIC_GROUP_X25519           0x001d

/* Write a handshake message header (type + 24-bit length) at out; returns
 * the offset where the body should start (4). The caller fills the body then
 * calls quic_hs_finish to patch the length. */
usz quic_hs_begin(u8 *out, usz cap, u8 msg_type);

/* Patch the 24-bit length field given the total message length (>=4). */
void quic_hs_finish(u8 *out, usz total);

/* Parse a handshake message header at buf (n bytes). Sets *type and *body_len
 * and returns the body offset (4), or 0 if truncated/inconsistent. */
usz quic_hs_parse(const u8 *buf, usz n, u8 *type, usz *body_len);

/* Build a minimal ClientHello/ServerHello carrying the 32-byte X25519 share
 * `pub` and the 32-byte random. Returns total message length, or 0. */
usz quic_hs_build_hello(u8 *out, usz cap, u8 msg_type,
                        const u8 random[32], const u8 pub[32]);

/* Extract the peer's 32-byte X25519 key_share from a ClientHello/ServerHello
 * body. Returns 1 on success, 0 if the key_share is absent/malformed. */
int quic_hs_peer_share(const u8 *body, usz body_len, u8 pub[32]);

#endif
