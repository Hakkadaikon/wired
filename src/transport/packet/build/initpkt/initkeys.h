#ifndef QUIC_INITPKT_INITKEYS_H
#define QUIC_INITPKT_INITKEYS_H

#include "common/bytes/span/span.h"
#include "tls/handshake/core/tls/initial.h"

/* RFC 9001 5.2: derive both the client and server Initial protection keys from
 * the Destination Connection ID of the client's first Initial packet. */
void quic_initpkt_derive(
    quic_span          dcid,
    quic_initial_keys *client_keys,
    quic_initial_keys *server_keys);

#endif
