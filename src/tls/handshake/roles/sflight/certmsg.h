#ifndef QUIC_SFLIGHT_CERTMSG_H
#define QUIC_SFLIGHT_CERTMSG_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 8446 4.4.2: build the server Certificate message (type 0x0b) with an
 * empty certificate_request_context and a one-entry certificate_list holding
 * cert_der and empty extensions. Writes the full handshake message into out
 * and sets out->len. Returns 1, or 0 if it does not fit or cert_der exceeds
 * the 3-byte length field. */
int quic_sflight_certificate(quic_span cert_der, quic_obuf *out);

#endif
