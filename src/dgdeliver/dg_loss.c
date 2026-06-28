#include "dgdeliver/dg_loss.h"

int quic_dgdeliver_on_loss(int is_datagram_frame)
{
    return is_datagram_frame ? 1 : 0; /* RFC 9221 5.2: notify, never resend */
}

int quic_dgdeliver_retransmit_never(void)
{
    return 0; /* RFC 9221 5.2 */
}
