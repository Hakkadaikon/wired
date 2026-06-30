#include "tls/handshake/core/tls/encext_check.h"

/* RFC 9001 8.2 */
int quic_encext_has_tp(int found_tp_ext)
{
    return found_tp_ext ? 1 : 0;
}

/* RFC 9001 8.2 */
int quic_encext_required_ok(int found_tp)
{
    return quic_encext_has_tp(found_tp);
}
