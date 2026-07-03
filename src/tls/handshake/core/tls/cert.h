#ifndef QUIC_TLS_CERT_H
#define QUIC_TLS_CERT_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * RFC 8446 4.4.2/4.4.3: the Certificate and CertificateVerify handshake
 * messages. Certificate carries a request context and a chain of entries,
 * each an opaque cert_data (X.509, not parsed here) plus extensions.
 * CertificateVerify carries a SignatureScheme and the signature over the
 * handshake transcript. */

/** A view of one CertificateEntry's cert_data within the message buffer. */
typedef struct {
  const u8 *cert_data; /**< start of the entry's opaque cert_data (X.509) */
  u32       cert_len;  /**< length of cert_data in bytes */
} quic_tls_cert_entry;

/** Parse a Certificate message body (after the handshake header). Sets the
 * request context view and the first CertificateEntry's cert_data. Only the
 * first entry (the end-entity certificate) is exposed; the rest of the chain
 * is skipped over.
 * @param buf the Certificate message body
 * @param context receives the certificate_request_context view
 * @param first receives the first CertificateEntry's cert_data view
 * @return 1 on success, 0 on truncation. */
int quic_tls_cert_parse(
    quic_span buf, quic_span *context, quic_tls_cert_entry *first);

/** Longest certificate_list this SDK walks (leaf + up to 3 issuers — public
 * web chains are 2-3 entries). */
#define QUIC_TLS_CERT_CHAIN_MAX 4

/** Destination for quic_tls_cert_chain: entries[0..cap-1] and the count
 * actually written. */
typedef struct {
  quic_tls_cert_entry *entries; /**< receives the entry views, leaf first */
  usz                  cap;     /**< capacity of entries */
  usz                 *count;   /**< receives the number of entries written */
} quic_tls_cert_chain_out;

/** Parse a Certificate message body (after the handshake header) and view
 * EVERY CertificateEntry's cert_data into out->entries[0..out->cap-1], leaf
 * first. Sets *out->count.
 * @param buf the Certificate message body
 * @param context receives the certificate_request_context view
 * @param out destination entry views and count
 * @return 1 on success; 0 on truncation, trailing garbage, or more than cap
 * entries (fail closed). */
int quic_tls_cert_chain(
    quic_span buf, quic_span *context, const quic_tls_cert_chain_out *out);

/** Parse a CertificateVerify body: a 2-byte SignatureScheme then a
 * 2-byte-length-prefixed signature.
 * @param buf the CertificateVerify message body
 * @param scheme receives the SignatureScheme code point
 * @param sig receives the signature view
 * @return 1 on success, 0 on truncation. */
int quic_tls_certverify_parse(quic_span buf, u16 *scheme, quic_span *sig);

/** RFC 8446 4.2.3: the ed25519 SignatureScheme code point. */
#define QUIC_TLS_SCHEME_ED25519 0x0807

/** Verify a server's CertificateVerify Ed25519 signature (RFC 8446 4.4.3).
 * The signed content is 64 octets of 0x20, the context string "TLS 1.3,
 * server CertificateVerify", a 0x00 separator, then the transcript hash.
 * @param sig the signature from the CertificateVerify message
 * @param transcript_hash the handshake transcript hash
 * @param pubkey the server's Ed25519 public key (from its certificate)
 * @return 1 if the signature verifies. */
int quic_tls_certverify_ed25519(
    quic_span sig, const u8 transcript_hash[32], const u8 pubkey[32]);

#endif
