#ifndef QUIC_ALPNVER_ALPNVER_H
#define QUIC_ALPNVER_ALPNVER_H

#include "common/platform/sys/syscall.h"

/* Interaction between the negotiated ALPN protocol and the QUIC version.
 * Builds on tls/alpn_match (protocol identity) and version/compat (version
 * compatibility). RFC 9001 8.1: a QUIC handshake MUST negotiate an
 * application protocol via ALPN; absent one the endpoint fails the handshake
 * with no_application_protocol. RFC 9368 / RFC 9000 7.4: a protocol selected
 * under one version stays valid across a compatible version change. */

/* Known application protocols carried over QUIC. */
typedef enum {
    QUIC_ALPNVER_PROTO_NONE = 0, /* unknown / not a QUIC application protocol */
    QUIC_ALPNVER_PROTO_H3   = 1  /* HTTP/3, ALPN "h3" (RFC 9114) */
} quic_alpnver_proto;

/* RFC 9001 8.1: returns 1 if an ALPN protocol was selected (non-empty),
 * 0 if none was (the handshake must then fail with no_application_protocol). */
int quic_alpnver_require(const u8 *selected_alpn, usz len);

/* Classify a selected ALPN name. Returns QUIC_ALPNVER_PROTO_NONE for an
 * unknown protocol (RFC 7301 3.2). */
quic_alpnver_proto quic_alpnver_protocol(const u8 *alpn, usz len);

/* RFC 9368 / RFC 9000 7.4: returns 1 if the given ALPN protocol is usable
 * with the given QUIC version. "h3" is valid on QUIC v1 and v2; an unknown
 * protocol or unknown version is not. */
int quic_alpnver_compatible(u32 version, const u8 *alpn, usz len);

#endif
