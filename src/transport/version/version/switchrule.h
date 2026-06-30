#ifndef QUIC_VERSION_SWITCHRULE_H
#define QUIC_VERSION_SWITCHRULE_H

#include "common/platform/sys/syscall.h"

/* RFC 9369 4.1: on a compatible version switch the Retry Integrity Tag and the
 * 0-RTT keys are derived with version-specific salts/labels, so a change of
 * version forces re-derivation. */

/* Returns 1 when the Retry Integrity Tag must be recomputed with the keys of
 * the negotiated version, i.e. whenever the version changed. */
int quic_version_retry_reencode(u32 from, u32 to);

/* Returns 1 when the 0-RTT keys negotiated under `original` may be kept after
 * switching to `negotiated`: only when the two versions are compatible. */
int quic_version_0rtt_keep(u32 original, u32 negotiated);

#endif
