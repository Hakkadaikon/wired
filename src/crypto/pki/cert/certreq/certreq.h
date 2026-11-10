#ifndef CERTREQ_H
#define CERTREQ_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 8446 4.3.2: CertificateRequest (handshake type 0x0d). Sent by a server
 * that wants client authentication (mTLS). The body is a
 * certificate_request_context (1-byte length + bytes, empty in the handshake)
 * followed by an extensions block; signature_algorithms (0x000d) is required.
 * Optional in QUIC, so this is the minimal empty-context encoder. */

/* Build a CertificateRequest with an empty context and a single
 * signature_algorithms extension whose scheme list is sig_algs (a sequence of
 * 2-byte SignatureSchemes). Writes into out and sets out->len to the message
 * length. Returns 1 on success, 0 if it does not fit. */
int certreq_build(wired_span sig_algs, wired_obuf* out);

#endif
