#include "transport/packet/build/initpkt/initkeys.h"

/* RFC 9001 5.2 / RFC 9369 3.3.1 */
void quic_initpkt_derive_ver(
    quic_span          dcid,
    u32                version,
    quic_initial_keys* client_keys,
    quic_initial_keys* server_keys) {
  quic_initial_derive(dcid, 0, version, client_keys);
  quic_initial_derive(dcid, 1, version, server_keys);
}

/* RFC 9001 5.2 */
void quic_initpkt_derive(
    quic_span          dcid,
    quic_initial_keys* client_keys,
    quic_initial_keys* server_keys) {
  quic_initpkt_derive_ver(dcid, QUIC_VERSION_1, client_keys, server_keys);
}
