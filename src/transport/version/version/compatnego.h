#ifndef QUIC_VERSION_COMPATNEGO_H
#define QUIC_VERSION_COMPATNEGO_H

#include "transport/version/version/version.h"

/* RFC 9368 2.2: the Original version is what the client used in its first
 * Initial; the Negotiated version is what the connection ends up using. When
 * the two are compatible the server may switch without a new handshake;
 * otherwise a new handshake (CRYPTO retransmission) is required. */

int quic_version_compat_switch_ok(u32 original, u32 negotiated);
int quic_version_needs_retry(u32 original, u32 negotiated);

#endif
