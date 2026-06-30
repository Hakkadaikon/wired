#ifndef QUIC_TLS_CERT_H
#define QUIC_TLS_CERT_H

#include "common/platform/sys/syscall.h"

/* RFC 8446 4.4.2/4.4.3: the Certificate and CertificateVerify handshake
 * messages. Certificate carries a request context and a chain of entries,
 * each an opaque cert_data (X.509, not parsed here) plus extensions.
 * CertificateVerify carries a SignatureScheme and the signature over the
 * handshake transcript. */

/* A view of one CertificateEntry's cert_data within the message buffer. */
typedef struct {
    const u8 *cert_data;
    u32 cert_len;
} quic_tls_cert_entry;

/* Parse a Certificate message body (after the handshake header). Sets the
 * request context view and the first CertificateEntry's cert_data. Returns
 * 1 on success, 0 on truncation. Only the first entry (the end-entity
 * certificate) is exposed; the rest of the chain is skipped over. */
int quic_tls_cert_parse(const u8 *buf, usz n,
                        const u8 **context, u32 *context_len,
                        quic_tls_cert_entry *first);

/* Parse a CertificateVerify body: a 2-byte SignatureScheme then a
 * 2-byte-length-prefixed signature. Returns 1 on success, 0 on truncation. */
int quic_tls_certverify_parse(const u8 *buf, usz n, u16 *scheme,
                              const u8 **sig, u16 *sig_len);

#define QUIC_TLS_SCHEME_ED25519 0x0807

/* Verify a server's CertificateVerify Ed25519 signature (RFC 8446 4.4.3).
 * The signed content is 64 octets of 0x20, the context string "TLS 1.3,
 * server CertificateVerify", a 0x00 separator, then the transcript hash.
 * pubkey is the server's Ed25519 public key (from its certificate).
 * Returns 1 if the signature verifies. */
int quic_tls_certverify_ed25519(const u8 *sig, u16 sig_len,
                                const u8 transcript_hash[32],
                                const u8 pubkey[32]);

#endif
