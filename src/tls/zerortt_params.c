#include "tls/zerortt_params.h"

/* RFC 9001 4.6.2 */
int quic_zerortt_param_ok(u64 remembered, u64 current)
{
    return current >= remembered;
}
