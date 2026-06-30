#ifndef QUIC_KEYUPDATE_AEADLIMIT_H
#define QUIC_KEYUPDATE_AEADLIMIT_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 6.6 AEAD confidentiality limit. AES-GCM may protect at most
 * 2^23 packets with one key; AEAD_CHACHA20_POLY1305 is bounded only by the
 * 2^62 packet-number space. Once the encrypted-packet count reaches the
 * limit, a key update is mandatory before encrypting further. */

#define QUIC_AEAD_LIMIT_AESGCM  (1ULL << 23)
#define QUIC_AEAD_LIMIT_CHACHA  (1ULL << 62)

/* Returns 1 if packets_encrypted has reached the AEAD's limit (forcing a
 * key update), 0 otherwise. is_chacha selects the ChaCha20 limit. */
int quic_aead_needs_update(u64 packets_encrypted, int is_chacha);

#endif
