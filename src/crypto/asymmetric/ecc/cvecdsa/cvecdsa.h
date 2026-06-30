#ifndef QUIC_CVECDSA_CVECDSA_H
#define QUIC_CVECDSA_CVECDSA_H

#include "common/platform/sys/syscall.h"

/* RFC 8446 4.4.3: build the server CertificateVerify handshake message
 * (type 0x0f) signed with ECDSA P-256 / SHA-256, scheme
 * ecdsa_secp256r1_sha256 (0x0403). priv is the big-endian 32-byte private key;
 * transcript_hash is the 32-byte handshake transcript SHA-256 digest. Writes
 * header + scheme(2) + signature<2> DER into out (cap total) and sets
 * *out_len. Returns 1, or 0 if it does not fit or signing fails. */
int quic_cvecdsa_build(
    const u8 priv[32],
    const u8 transcript_hash[32],
    u8      *out,
    usz      cap,
    usz     *out_len);

#endif
