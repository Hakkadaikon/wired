#ifndef QUIC_TLS_RETRY_TAG_H
#define QUIC_TLS_RETRY_TAG_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 5.8 Retry Integrity Tag: AEAD_AES_128_GCM over the Retry
 * Pseudo-Packet (ODCID Length + ODCID + Retry packet without the tag) with a
 * fixed key and nonce, empty plaintext. The 16-byte authentication tag is the
 * integrity tag. */

#define QUIC_RETRY_TAG 16

/* Compute the Retry Integrity Tag. odcid is the Original Destination
 * Connection ID (the DCID of the client's first Initial); retry is the Retry
 * packet bytes excluding the trailing 16-byte tag. */
void quic_retry_tag(const u8 *odcid, usz odcid_len,
                    const u8 *retry, usz retry_len, u8 tag[QUIC_RETRY_TAG]);

/* Verify a received Retry packet's tag in constant time. retry_with_tag is
 * the full Retry packet (its last 16 bytes are the tag). Returns 1 if valid. */
int quic_retry_verify(const u8 *odcid, usz odcid_len,
                      const u8 *retry_with_tag, usz total_len);

#endif
