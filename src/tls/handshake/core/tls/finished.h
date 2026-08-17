#ifndef TLS_FINISHED_H
#define TLS_FINISHED_H

#include "crypto/kdf/hkdf/hkdf.h"

/* RFC 8446 4.1.2 / 4.4.4: the Finished message proves possession of the
 * handshake traffic secret and authenticates the handshake transcript.
 * finished_key = HKDF-Expand-Label(base_key, "finished", "", Hash.length);
 * verify_data = HMAC(finished_key, Transcript-Hash). */

#define TLS_VERIFY_DATA SHA256_DIGEST

/* Compute the Finished verify_data from a base traffic secret and the
 * transcript hash. */
void tls_finished_verify_data(
    const u8 base_key[HKDF_PRK],
    const u8 transcript_hash[SHA256_DIGEST],
    u8       out[TLS_VERIFY_DATA]);

/* Verify a received Finished against the recomputed verify_data in constant
 * time. Returns 1 on a match. */
int tls_finished_check(
    const u8 base_key[HKDF_PRK],
    const u8 transcript_hash[SHA256_DIGEST],
    const u8 received[TLS_VERIFY_DATA]);

#endif
