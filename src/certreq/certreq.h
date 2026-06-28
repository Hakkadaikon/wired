#ifndef QUIC_CERTREQ_H
#define QUIC_CERTREQ_H

#include "sys/syscall.h"

/* RFC 8446 4.3.2: CertificateRequest (handshake type 0x0d). Sent by a server
 * that wants client authentication (mTLS). The body is a
 * certificate_request_context (1-byte length + bytes, empty in the handshake)
 * followed by an extensions block; signature_algorithms (0x000d) is required.
 * Optional in QUIC, so this is the minimal empty-context encoder/decoder. */

/* Build a CertificateRequest with an empty context and a single
 * signature_algorithms extension whose scheme list is sig_algs (sa_len bytes,
 * a sequence of 2-byte SignatureSchemes). Writes into out (cap total) and sets
 * *out_len to the message length. Returns 1 on success, 0 if it does not fit. */
int quic_certreq_build(const u8 *sig_algs, usz sa_len, u8 *out, usz cap,
                       usz *out_len);

/* Parse a CertificateRequest message msg (len bytes, including the handshake
 * header). On success sets ctx/ctx_len to the certificate_request_context and
 * sa/sa_len to the signature_algorithms scheme list, returning 1. Returns 0
 * if truncated, not a CertificateRequest, or signature_algorithms is absent. */
int quic_certreq_parse(const u8 *msg, usz len, const u8 **ctx, u8 *ctx_len,
                       const u8 **sa, usz *sa_len);

#endif
