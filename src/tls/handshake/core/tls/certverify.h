#ifndef QUIC_TLS_CERTVERIFY_H
#define QUIC_TLS_CERTVERIFY_H

#include "common/platform/sys/syscall.h"

/* RFC 8446 4.4.3. SignatureScheme codepoints handled here. */
#define QUIC_TLS_SCHEME_RSA_PSS_SHA256 0x0804
#define QUIC_TLS_SCHEME_ECDSA_P256     0x0403
#define QUIC_TLS_SCHEME_ED25519        0x0807

/* RFC 8446 4.4.3. Verify a server CertificateVerify signature against the
 * end-entity certificate cert (DER, cert_len octets) and the handshake
 * transcript hash. The signed content is 64 octets of 0x20, the context
 * string "TLS 1.3, server CertificateVerify", a 0x00 separator, then the
 * transcript hash. scheme selects the algorithm and the certificate's
 * public key type. Returns 1 if the signature verifies, 0 otherwise. */
int quic_tls_verify_cert_signature(u16 scheme,
                                   const u8 *cert, usz cert_len,
                                   const u8 *sig, usz sig_len,
                                   const u8 transcript_hash[32]);

#endif
