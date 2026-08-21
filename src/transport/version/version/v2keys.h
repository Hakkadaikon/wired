#ifndef VERSION_V2KEYS_H
#define VERSION_V2KEYS_H

#include "common/platform/sys/syscall.h"
#include "transport/version/version/version.h"

/* RFC 9369 3.3: QUIC v2 uses a different Initial salt and HKDF-Expand-Label
 * prefix than v1. These pick the right constants for a given version. */

#define INITIAL_SALT_LEN 20

/* Point *salt at the 20-byte Initial salt for `version` and set *len.
 * v1 (RFC 9001 5.2) and v2 (RFC 9369 3.3.1) differ. Returns 1 if the version
 * is known (v1 or v2), 0 otherwise (and leaves the outputs untouched). */
int version_initial_salt(u32 version, const u8** salt, usz* len);

/* The HKDF-Expand-Label prefix for `version`: "quic " for v1, "quicv2 " for
 * v2 (RFC 9369 3.3.1). Sets *len to the prefix length. Returns 0 (and leaves
 * outputs untouched) for an unknown version. */
int version_label_prefix(u32 version, const char** prefix, usz* len);

/* Longest "<prefix><suffix>" label version_quic_label can build:
 * "quicv2 " (7) plus the longest suffix in use ("client in", 9). */
#define VERSION_LABEL_MAX 16

/* Build the full HKDF-Expand-Label label "<prefix><suffix>" for `version`
 * into buf (at least VERSION_LABEL_MAX bytes) and return its length. An
 * unknown version (including 0) falls back to the v1 "quic " prefix --
 * label building never fails, it degrades to the invariant construction. */
usz version_quic_label(u8* buf, u32 version, const char* suffix, usz sfx_len);

#endif
