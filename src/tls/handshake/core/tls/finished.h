#ifndef QUIC_TLS_FINISHED_H
#define QUIC_TLS_FINISHED_H

#include "crypto/kdf/hkdf/hkdf.h"

/* RFC 8446 4.1.2 / 4.4.4: the Finished message proves possession of the
 * handshake traffic secret and authenticates the handshake transcript.
 * finished_key = HKDF-Expand-Label(base_key, "finished", "", Hash.length);
 * verify_data = HMAC(finished_key, Transcript-Hash). */

#define QUIC_TLS_VERIFY_DATA QUIC_SHA256_DIGEST

/* Compute the Finished verify_data from a base traffic secret and the
 * transcript hash. */
void quic_tls_finished_verify_data(const u8 base_key[QUIC_HKDF_PRK],
                                   const u8 transcript_hash[QUIC_SHA256_DIGEST],
                                   u8 out[QUIC_TLS_VERIFY_DATA]);

/* Verify a received Finished against the recomputed verify_data in constant
 * time. Returns 1 on a match. */
int quic_tls_finished_check(const u8 base_key[QUIC_HKDF_PRK],
                            const u8 transcript_hash[QUIC_SHA256_DIGEST],
                            const u8 received[QUIC_TLS_VERIFY_DATA]);

#endif
