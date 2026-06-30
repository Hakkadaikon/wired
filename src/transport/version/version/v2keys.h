#ifndef QUIC_VERSION_V2KEYS_H
#define QUIC_VERSION_V2KEYS_H

#include "common/platform/sys/syscall.h"
#include "transport/version/version/version.h"

/* RFC 9369 3.3: QUIC v2 uses a different Initial salt and HKDF-Expand-Label
 * prefix than v1. These pick the right constants for a given version. */

#define QUIC_INITIAL_SALT_LEN 20

/* Point *salt at the 20-byte Initial salt for `version` and set *len.
 * v1 (RFC 9001 5.2) and v2 (RFC 9369 3.3.1) differ. Returns 1 if the version
 * is known (v1 or v2), 0 otherwise (and leaves the outputs untouched). */
int quic_version_initial_salt(u32 version, const u8 **salt, usz *len);

/* The HKDF-Expand-Label prefix for `version`: "quic " for v1, "quicv2 " for
 * v2 (RFC 9369 3.3.1). Sets *len to the prefix length. Returns 0 (and leaves
 * outputs untouched) for an unknown version. */
int quic_version_label_prefix(u32 version, const char **prefix, usz *len);

#endif
