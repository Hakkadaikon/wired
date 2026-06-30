#include "tls/handshake/core/tls/keydiscard.h"

/* RFC 9001 4.9.1 */
int quic_key_discard_initial(int handshake_keys_available)
{
    return handshake_keys_available ? 1 : 0;
}

/* RFC 9001 4.9.1 */
int quic_key_discard_handshake(int handshake_confirmed)
{
    return handshake_confirmed ? 1 : 0;
}
