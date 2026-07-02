#ifndef QUIC_CERTREQ_H
#define QUIC_CERTREQ_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 8446 4.3.2: CertificateRequest (handshake type 0x0d). Sent by a server
 * that wants client authentication (mTLS). The body is a
 * certificate_request_context (1-byte length + bytes, empty in the handshake)
 * followed by an extensions block; signature_algorithms (0x000d) is required.
 * Optional in QUIC, so this is the minimal empty-context encoder/decoder. */

/* Parsed CertificateRequest: views into the message buffer. */
typedef struct {
  quic_span ctx;      /* certificate_request_context */
  quic_span sig_algs; /* signature_algorithms scheme list */
} quic_certreq;

/* Build a CertificateRequest with an empty context and a single
 * signature_algorithms extension whose scheme list is sig_algs (a sequence of
 * 2-byte SignatureSchemes). Writes into out and sets out->len to the message
 * length. Returns 1 on success, 0 if it does not fit. */
int quic_certreq_build(quic_span sig_algs, quic_obuf *out);

/* Parse a CertificateRequest message msg (including the handshake header).
 * On success fills *out and returns 1. Returns 0 if truncated, not a
 * CertificateRequest, or signature_algorithms is absent. */
int quic_certreq_parse(quic_span msg, quic_certreq *out);

#endif
