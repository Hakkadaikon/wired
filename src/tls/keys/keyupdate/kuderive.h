#ifndef QUIC_KEYUPDATE_KUDERIVE_H
#define QUIC_KEYUPDATE_KUDERIVE_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 6.1: derive the next 1-RTT application traffic secret.
 * secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku", "", Hash.length).
 * RFC 9369 3.3.2: QUIC v2 uses the same process with label "quicv2 ku"
 * instead. `version` selects the label; an unknown version falls back to
 * the v1 label (mirrors quic_version_label_prefix's own fallback). */
void quic_ku_next_secret_v(u32 version, const u8 cur[32], u8 next[32]);

/* RFC 9001 6.1 only (QUIC v1 "quic ku" label). Kept for existing v1-only
 * call sites; equivalent to quic_ku_next_secret_v(QUIC_VERSION_1, ...). */
void quic_ku_next_secret(const u8 cur[32], u8 next[32]);

#endif
