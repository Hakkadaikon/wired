#ifndef QUIC_VERSMGR_V2SWITCH_H
#define QUIC_VERSMGR_V2SWITCH_H

#include "common/platform/sys/syscall.h"

/* RFC 9369 3: when the negotiated version is v2, the endpoint switches to v2
 * Initial salt and HKDF-Expand-Label prefix. */

/* 1 if version is QUIC v2 (0x6b3343cf), else 0. */
int quic_vers_is_v2(u32 version);

/* Point *salt at the 20-byte Initial salt for version and set *salt_len.
 * v1 (RFC 9001 5.2) and v2 (RFC 9369 3.3.1) differ. Returns 1 if known. */
int quic_vers_initial_salt(u32 version, const u8 **salt, usz *salt_len);

/* Point *prefix at the HKDF-Expand-Label prefix for version ("quic " v1,
 * "quicv2 " v2) and set *len. Returns 1 if known. */
int quic_vers_label_prefix(u32 version, const char **prefix, usz *len);

#endif
