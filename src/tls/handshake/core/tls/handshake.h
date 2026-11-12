#ifndef TLS_HANDSHAKE_H
#define TLS_HANDSHAKE_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 8446 TLS 1.3 handshake messages carried in QUIC CRYPTO frames.
 * Each message is: msg_type(1) length(3, big-endian) body. */

#define HS_CLIENT_HELLO 1
#define HS_SERVER_HELLO 2
#define HS_ENCRYPTED_EXT 8
#define HS_FINISHED 20

#define TLS_AES128_GCM_SHA256 0x1301
#define EXT_SUPPORTED_VERSIONS 43
#define EXT_KEY_SHARE 51
#define GROUP_X25519 0x001d
#define GROUP_SECP256R1 0x0017

/* Write a handshake message header (type + 24-bit length) at out; returns
 * the offset where the body should start (4). The caller fills the body then
 * calls hs_finish to patch the length. */
usz hs_begin(u8* out, usz cap, u8 msg_type);

/* Patch the 24-bit length field given the total message length (>=4). */
void hs_finish(u8* out, usz total);

/* Parse a handshake message header at buf. Sets *type and *body_len and
 * returns the body offset (4), or 0 if truncated/inconsistent. */
usz hs_parse(wired_span buf, u8* type, usz* body_len);

#endif
