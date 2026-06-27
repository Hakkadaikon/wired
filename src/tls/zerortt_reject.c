#include "tls/zerortt_reject.h"

/* RFC 9001 4.6.1 */
void quic_zerortt_on_reject(int *retransmit_needed, int *discard_keys)
{
    *retransmit_needed = 1;
    *discard_keys = 1;
}

/* RFC 9001 4.6.1 */
int quic_zerortt_accepted(int server_accepted)
{
    return server_accepted ? 1 : 0;
}
