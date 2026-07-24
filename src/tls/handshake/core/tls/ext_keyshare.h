#ifndef QUIC_TLS_EXT_KEYSHARE_H
#define QUIC_TLS_EXT_KEYSHARE_H

#include "common/platform/sys/syscall.h"
#include "tls/handshake/core/tls/handshake.h"

/* RFC 8446 4.2.8: key_share, extension_type 0x0033 (QUIC_EXT_KEY_SHARE). The
 * ClientHello body is a 2-byte client_shares length followed by KeyShareEntry
 * (group(2) + key length(2) + key). Supported groups: x25519 (32-byte key,
 * RFC 7748) and secp256r1 (65-byte SEC1 uncompressed key, RFC 8446 4.2.8.2 /
 * SEC1 2.3.3). */

/* Encode the full ClientHello/ServerHello key_share extension for a single
 * KeyShareEntry: ext_type(2) ext_len(2) shares_len(2) group(2) ke_len(2)
 * pub[pub_len]. pub_len must match group (32 for x25519, 65 for
 * secp256r1). Returns bytes written into buf (cap total), or 0 if it does
 * not fit. */
usz quic_tls_ext_key_share(
    u8* buf, usz cap, u16 group, const u8* pub, usz pub_len);

/* Read a single KeyShareEntry (group(2) + key length(2) + key) from a
 * ServerHello key_share extension_data at buf (n readable). On success sets
 * *group, copies the key into pub (up to pub_cap bytes) and sets *pub_len to
 * the key length, then returns 1. Returns 0 if truncated, the group is not
 * recognised (x25519 or secp256r1), its key length does not match the
 * group's fixed length, or the key does not fit in pub_cap. */
int quic_tls_ext_key_share_parse(
    const u8* buf, usz n, u16* group, u8* pub, usz* pub_len, usz pub_cap);

/* Read the client key for `want_group` from a ClientHello key_share
 * extension_data at buf (n readable): a 2-byte client_shares length then a
 * list of KeyShareEntry (group(2) + key length(2) + key). curl/quiche offer
 * several groups and the wanted one need not be first, so scan the list. On
 * the first entry whose group equals want_group and whose key length matches
 * that group's fixed length, copy the key into pub (up to pub_cap bytes),
 * set *pub_len, and return 1. Returns 0 if no matching entry is present or
 * any length field overruns n (untrusted input). */
int quic_tls_ext_key_share_scan(
    const u8* buf, usz n, u16 want_group, u8* pub, usz* pub_len, usz pub_cap);

#endif
