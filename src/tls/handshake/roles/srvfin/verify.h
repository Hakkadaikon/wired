#ifndef QUIC_SRVFIN_VERIFY_H
#define QUIC_SRVFIN_VERIFY_H

#include "crypto/symmetric/hash/hash/sha256.h"
#include "crypto/kdf/hkdf/hkdf.h"

/* RFC 8446 4.4.4 / RFC 9001 4.1.2: server-side verification of the client's
 * Finished. Parses the received client Finished handshake message and checks
 * its verify_data against the value recomputed from the client handshake
 * traffic secret and the transcript hash up to (but not including) the client
 * Finished. Returns 1 on a match, 0 on any malformed message or mismatch. */
int quic_srvfin_verify_client_finished(
    const u8 *client_finished_msg, usz len,
    const u8 client_hs_traffic_secret[QUIC_HKDF_PRK],
    const u8 transcript_hash[QUIC_SHA256_DIGEST]);

#endif
