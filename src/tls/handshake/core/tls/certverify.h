#ifndef QUIC_TLS_CERTVERIFY_H
#define QUIC_TLS_CERTVERIFY_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 8446 4.4.3. SignatureScheme codepoints handled here. */
#define QUIC_TLS_SCHEME_RSA_PSS_SHA256 0x0804
#define QUIC_TLS_SCHEME_ECDSA_P256 0x0403
#define QUIC_TLS_SCHEME_ED25519 0x0807

/* RFC 8446 4.4.3: a CertificateVerify to authenticate. cert is the
 * end-entity certificate (DER), sig its signature, transcript_hash the
 * handshake transcript hash the signature covers. */
typedef struct {
  u16       scheme;
  quic_span cert;
  quic_span sig;
  const u8 *transcript_hash; /* 32 bytes */
} quic_certverify_in;

/* RFC 8446 4.4.3. Verify a server CertificateVerify signature against the
 * end-entity certificate and the handshake transcript hash. The signed
 * content is 64 octets of 0x20, the context string "TLS 1.3, server
 * CertificateVerify", a 0x00 separator, then the transcript hash. in->scheme
 * selects the algorithm and the certificate's public key type. Returns 1 if
 * the signature verifies, 0 otherwise. */
int quic_tls_verify_cert_signature(const quic_certverify_in *in);

#endif
