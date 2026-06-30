#ifndef QUIC_KEYUPDATE_KUDERIVE_H
#define QUIC_KEYUPDATE_KUDERIVE_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 6.1: derive the next 1-RTT application traffic secret.
 * secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku", "", Hash.length). */
void quic_ku_next_secret(const u8 cur[32], u8 next[32]);

#endif
