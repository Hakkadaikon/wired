#ifndef EEBUILD_EEBUILD_H
#define EEBUILD_EEBUILD_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "tls/ext/salpn/negotiate.h"

/* RFC 8446 4.3.1: build the server EncryptedExtensions message (type 0x08)
 * carrying the ALPN extension selecting alpn (RFC 7301 / RFC 9001 8.1 --
 * the negotiated protocol id: h3, hq-interop or a raw id such as moqt-19,
 * see salpn_choice_name), the quic_transport_parameters extension (0x39,
 * RFC 9001 8.2) wrapping transport_params, and, when early_data is nonzero,
 * the empty early_data extension (0x002a) acknowledging 0-RTT acceptance
 * (RFC 8446 4.2.10). Writes the full handshake message (msg_type + 24-bit
 * length + extensions block) into out and sets out->len. Returns 1 on
 * success, 0 if it does not fit or alpn is empty (nothing negotiated --
 * the caller must not have reached here with an unresolved negotiation). */
int eebuild_encrypted_extensions(
    wired_span  alpn,
    wired_span  transport_params,
    int         early_data,
    wired_obuf* out);

#endif
