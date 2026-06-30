#include "transport/packet/build/initpkt/initkeys.h"

/* RFC 9001 5.2 */
void quic_initpkt_derive(const u8 *dcid, u8 dcid_len,
                         quic_initial_keys *client_keys,
                         quic_initial_keys *server_keys)
{
    quic_initial_derive(dcid, dcid_len, 0, client_keys);
    quic_initial_derive(dcid, dcid_len, 1, server_keys);
}
