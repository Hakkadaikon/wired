#include "transport/packet/build/initpkt/initkeys.h"

/* RFC 9001 5.2 */
void quic_initpkt_derive(
    quic_span          dcid,
    quic_initial_keys *client_keys,
    quic_initial_keys *server_keys) {
  quic_initial_derive(dcid.p, (u8)dcid.n, 0, client_keys);
  quic_initial_derive(dcid.p, (u8)dcid.n, 1, server_keys);
}
