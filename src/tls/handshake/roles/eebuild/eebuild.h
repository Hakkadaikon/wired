#ifndef EEBUILD_EEBUILD_H
#define EEBUILD_EEBUILD_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "tls/ext/salpn/negotiate.h"

/** eebuild_encrypted_extensions flag: the empty early_data extension
 * (0x002a) acknowledging 0-RTT acceptance (RFC 8446 4.2.10). */
#define EEBUILD_EARLY_DATA 1u
/** eebuild_encrypted_extensions flag: the empty server_name extension
 * (0x0000), sent when the ClientHello's server_name guided the certificate
 * and the handshake is not a resumption (RFC 6066 3). */
#define EEBUILD_SERVER_NAME 2u
/** eebuild_encrypted_extensions flag: supported_groups (0x000a) listing
 * x25519 then secp256r1, sent when the negotiated group is not the
 * server's first choice (RFC 8446 4.2.7). */
#define EEBUILD_GROUPS 4u

/* RFC 8446 4.3.1: build the server EncryptedExtensions message (type 0x08)
 * carrying the ALPN extension selecting alpn (RFC 7301 / RFC 9001 8.1 --
 * the negotiated protocol id: h3, hq-interop or a raw id such as moqt-19,
 * see salpn_choice_name), the quic_transport_parameters extension (0x39,
 * RFC 9001 8.2) wrapping transport_params, then each optional extension
 * flags names (EEBUILD_EARLY_DATA, EEBUILD_SERVER_NAME, EEBUILD_GROUPS),
 * in that order. Writes the full handshake message (msg_type + 24-bit
 * length + extensions block) into out and sets out->len. Returns 1 on
 * success, 0 if it does not fit or alpn is empty (nothing negotiated --
 * the caller must not have reached here with an unresolved negotiation). */
int eebuild_encrypted_extensions(
    wired_span  alpn,
    wired_span  transport_params,
    unsigned    flags,
    wired_obuf* out);

#endif
