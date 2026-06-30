#ifndef QUIC_TLS_EXT_KEYSHARE_H
#define QUIC_TLS_EXT_KEYSHARE_H

#include "common/platform/sys/syscall.h"
#include "tls/handshake/core/tls/handshake.h"

/* RFC 8446 4.2.8: key_share, extension_type 0x0033 (QUIC_EXT_KEY_SHARE). The
 * ClientHello body is a 2-byte client_shares length followed by KeyShareEntry
 * (group(2) + key length(2) + key). We offer a single x25519 entry. */

/* Encode the full ClientHello key_share extension for the 32-byte x25519
 * public key pub: ext_type(2) ext_len(2) shares_len(2) group(2) ke_len(2) key.
 * Returns bytes written into buf (cap total), or 0 if it does not fit. */
usz quic_tls_ext_key_share(u8 *buf, usz cap, const u8 pub[32]);

/* Read the x25519 public key from a ServerHello key_share extension_data at buf
 * (n readable): group(2) + key length(2) + key. On success copies 32 bytes into
 * pub and returns 1; 0 if truncated, the group is not x25519, or the key length
 * is not 32. */
int quic_tls_ext_key_share_parse(const u8 *buf, usz n, u8 pub[32]);

/* Read the client x25519 key from a ClientHello key_share extension_data at buf
 * (n readable): a 2-byte client_shares length then a list of KeyShareEntry
 * (group(2) + key length(2) + key). curl/quiche offer several groups and
 * x25519 need not be first, so scan the list. On the first x25519 (group
 * 0x001d, key length 32) entry, copy 32 bytes into pub and return 1. Returns 0
 * if no x25519 entry is present or any length field overruns n (untrusted
 * input). secp256r1 ECDHE is not supported; curl sends x25519 by default. */
int quic_tls_ext_key_share_scan(const u8 *buf, usz n, u8 pub[32]);

#endif
