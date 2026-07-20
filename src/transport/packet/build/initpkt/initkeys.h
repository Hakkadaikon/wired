#ifndef QUIC_INITPKT_INITKEYS_H
#define QUIC_INITPKT_INITKEYS_H

#include "common/bytes/span/span.h"
#include "tls/handshake/core/tls/initial.h"

/* RFC 9001 5.2: derive both the client and server Initial protection keys from
 * the Destination Connection ID of the client's first Initial packet, under
 * QUIC v1. Equivalent to quic_initpkt_derive_ver(dcid, QUIC_VERSION_1, ...). */
void quic_initpkt_derive(
    quic_span          dcid,
    quic_initial_keys* client_keys,
    quic_initial_keys* server_keys);

/* RFC 9001 5.2 / RFC 9369 3.3.1: same as quic_initpkt_derive, but under the
 * given version -- v1 and v2 differ only in the Initial salt (and HKDF-Expand-
 * Label prefix, tls/handshake/core/tls/initial.c). Unknown versions still
 * derive via the fallback quic_initial_derive applies. */
void quic_initpkt_derive_ver(
    quic_span          dcid,
    u32                version,
    quic_initial_keys* client_keys,
    quic_initial_keys* server_keys);

#endif
