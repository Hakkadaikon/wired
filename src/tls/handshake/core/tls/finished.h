#ifndef TLS_FINISHED_H
#define TLS_FINISHED_H

#include "crypto/kdf/hkdf/hkdf.h"

/* RFC 8446 4.1.2 / 4.4.4: the Finished message proves possession of the
 * handshake traffic secret and authenticates the handshake transcript.
 * finished_key = HKDF-Expand-Label(base_key, "finished", "", Hash.length);
 * verify_data = HMAC(finished_key, Transcript-Hash). */

/* verify_data length under SHA-256; a SHA-384 suite's is 48 (Hash.length,
 * tls_hash_of). */
#define TLS_VERIFY_DATA SHA256_DIGEST

/* Compute the SHA-256 Finished verify_data from a base traffic secret and the
 * transcript hash. */
void tls_finished_verify_data(
    const u8* base_key, const u8* transcript_hash, u8* out);

/* Verify a received SHA-256 Finished against the recomputed verify_data in
 * constant time. Returns 1 on a match. */
int tls_finished_check(
    const u8* base_key, const u8* transcript_hash, const u8* received);

/* Same as tls_finished_verify_data over suite's hash: base_key, the
 * transcript hash and out are all Hash.length bytes. */
void tls_finished_verify_data_suite(
    u16 suite, const u8* base_key, const u8* transcript_hash, u8* out);

/* Same as tls_finished_check over suite's hash. */
int tls_finished_check_suite(
    u16       suite,
    const u8* base_key,
    const u8* transcript_hash,
    const u8* received);

#endif
