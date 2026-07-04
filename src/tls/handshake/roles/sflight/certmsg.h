#ifndef QUIC_SFLIGHT_CERTMSG_H
#define QUIC_SFLIGHT_CERTMSG_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "tls/handshake/core/tls/cert.h"

/* RFC 8446 4.4.2: build the server Certificate message (type 0x0b) with an
 * empty certificate_request_context and a one-entry certificate_list holding
 * cert_der and empty extensions. Writes the full handshake message into out
 * and sets out->len. Returns 1, or 0 if it does not fit or cert_der exceeds
 * the 3-byte length field. */
int quic_sflight_certificate(quic_span cert_der, quic_obuf* out);

/* certs[0..count) are the chain DER views, leaf first (count in
 * 1..QUIC_TLS_CERT_CHAIN_MAX-worth of practical use; this SDK's server
 * flight path only ever passes 1 or 2). */
typedef struct {
  const quic_span* certs;
  usz              count;
} quic_sflight_certchain_in;

/* RFC 8446 4.4.2: build the server Certificate message with an empty
 * certificate_request_context and a certificate_list holding in->count
 * CertificateEntry values (leaf first), each with empty extensions. Writes
 * the full handshake message into out and sets out->len. Returns 1, or 0 if
 * count is out of range (0 or > QUIC_TLS_CERT_CHAIN_MAX) or the list does not
 * fit in out->cap. */
int quic_sflight_certificate_chain(
    const quic_sflight_certchain_in* in, quic_obuf* out);

#endif
