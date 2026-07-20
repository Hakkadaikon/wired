#ifndef QUIC_EEBUILD_EEBUILD_H
#define QUIC_EEBUILD_EEBUILD_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "tls/ext/salpn/negotiate.h"

/* RFC 8446 4.3.1: build the server EncryptedExtensions message (type 0x08)
 * carrying the negotiated ALPN extension (RFC 7301 / RFC 9001 8.1 -- h3 or
 * hq-interop, whichever alpn names), the quic_transport_parameters extension
 * (0x39, RFC 9001 8.2) wrapping transport_params, and, when early_data is
 * nonzero, the empty early_data extension (0x002a) acknowledging 0-RTT
 * acceptance (RFC 8446 4.2.10). Writes the full handshake message (msg_type
 * + 24-bit length + extensions block) into out and sets out->len. Returns 1
 * on success, 0 if it does not fit or alpn is QUIC_SALPN_NONE (nothing
 * negotiated -- the caller must not have reached here with an unresolved
 * negotiation). */
int quic_eebuild_encrypted_extensions(
    quic_salpn_choice alpn,
    quic_span         transport_params,
    int               early_data,
    quic_obuf*        out);

#endif
