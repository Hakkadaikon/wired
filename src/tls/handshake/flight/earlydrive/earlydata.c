#include "tls/handshake/flight/earlydrive/earlydata.h"

/* RFC 9001 4.5 */
int quic_earlydata_can_send(int has_0rtt_keys, int resumption_offered)
{
    return has_0rtt_keys && resumption_offered;
}

/* RFC 9001 4.5 / RFC 8446 2.3 */
int quic_earlydata_must_resend(int server_accepted_0rtt)
{
    return !server_accepted_0rtt;
}

/* RFC 9000 9.1 */
int quic_earlydata_can_migrate(int new_path_validated, int handshake_confirmed)
{
    return new_path_validated && handshake_confirmed;
}
