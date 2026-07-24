#ifndef QUIC_HRR_BUILD_H
#define QUIC_HRR_BUILD_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 8446 4.1.4: HelloRetryRequest is a ServerHello (msg_type 0x02) whose
 * random is the fixed value SHA-256("HelloRetryRequest"). It carries
 * supported_versions (selected_version 0x0304), key_share (selected_group
 * only, no key exchange), and an optional cookie. */

/* The 32-byte HelloRetryRequest random sentinel (RFC 8446 4.1.3). */
extern const u8 quic_hrr_random[32];

/* Build a HelloRetryRequest into out: selected_group is the group the client
 * must retry with; cookie (may be empty) is echoed in a cookie extension.
 * On success writes the total message length to out->len and returns 1;
 * returns 0 if it does not fit. */
int quic_hrr_build(u16 selected_group, quic_span cookie, quic_obuf* out);

/* RFC 8446 4.4.1: after a HelloRetryRequest, ClientHello1 is replaced in the
 * transcript by a synthetic "message_hash" message: msg_type 254, a 3-byte
 * length equal to ch1_hash_len, and the raw bytes of Hash(ClientHello1).
 * Writes 4 + ch1_hash_len bytes to out (cap must be at least that) and
 * returns the length written, or 0 if it does not fit. */
usz quic_hrr_message_hash(
    const u8* ch1_hash, usz ch1_hash_len, u8* out, usz cap);

#endif
