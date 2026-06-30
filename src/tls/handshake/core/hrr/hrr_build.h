#ifndef QUIC_HRR_BUILD_H
#define QUIC_HRR_BUILD_H

#include "common/platform/sys/syscall.h"

/* RFC 8446 4.1.4: HelloRetryRequest is a ServerHello (msg_type 0x02) whose
 * random is the fixed value SHA-256("HelloRetryRequest"). It carries
 * supported_versions (selected_version 0x0304), key_share (selected_group
 * only, no key exchange), and an optional cookie. */

/* The 32-byte HelloRetryRequest random sentinel (RFC 8446 4.1.3). */
extern const u8 quic_hrr_random[32];

/* Build a HelloRetryRequest into out (cap total): selected_group is the group
 * the client must retry with; cookie (cookie_len bytes, may be 0/NULL) is
 * echoed in a cookie extension. On success writes the total message length to
 * *out_len and returns 1; returns 0 if it does not fit. */
int quic_hrr_build(u16 selected_group, const u8 *cookie, usz cookie_len,
                   u8 *out, usz cap, usz *out_len);

#endif
