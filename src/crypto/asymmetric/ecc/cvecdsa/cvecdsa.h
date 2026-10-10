#ifndef CVECDSA_CVECDSA_H
#define CVECDSA_CVECDSA_H

#include "common/bytes/span/span.h"

/* RFC 8446 4.4.3: build the server CertificateVerify handshake message
 * (type 0x0f) signed with ECDSA P-256 / SHA-256, scheme
 * ecdsa_secp256r1_sha256 (0x0403). priv is the big-endian 32-byte private key;
 * transcript_hash is the handshake Transcript-Hash under the negotiated
 * suite's hash (32 or 48 bytes; the signature itself is always over SHA-256
 * of the signed content, RFC 8446 4.4.3). Writes
 * header + scheme(2) + signature<2> DER into out (cap total) and sets
 * *out_len. Returns 1, or 0 if it does not fit or signing fails. */
int cvecdsa_build(
    const u8   priv[32],
    wired_span transcript_hash,
    u8*        out,
    usz        cap,
    usz*       out_len);

#endif
