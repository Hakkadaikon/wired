#ifndef QUIC_INITPKT_INITKEYS_H
#define QUIC_INITPKT_INITKEYS_H

#include "tls/handshake/core/tls/initial.h"

/* RFC 9001 5.2: derive both the client and server Initial protection keys from
 * the Destination Connection ID of the client's first Initial packet. */
void quic_initpkt_derive(const u8 *dcid, u8 dcid_len,
                         quic_initial_keys *client_keys,
                         quic_initial_keys *server_keys);

#endif
