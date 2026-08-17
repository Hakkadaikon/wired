#include "transport/packet/build/initpkt/initkeys.h"

/* RFC 9001 5.2 / RFC 9369 3.3.1 */
void initpkt_derive_ver(
    wired_span    dcid,
    u32           version,
    initial_keys* client_keys,
    initial_keys* server_keys) {
  initial_derive(dcid, 0, version, client_keys);
  initial_derive(dcid, 1, version, server_keys);
}

/* RFC 9001 5.2 */
void initpkt_derive(
    wired_span dcid, initial_keys* client_keys, initial_keys* server_keys) {
  initpkt_derive_ver(dcid, QUIC_VERSION_1, client_keys, server_keys);
}
